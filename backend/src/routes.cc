// ─── EndoriumFort — API routes implementation ──────────────────────────

#include "routes.h"
#include "app_context.h"
#include "auth_mfa.h"
#include "crypto.h"
#include "http_proxy.h"
#include "iam_common.h"
#include "route_common.h"
#include "scim_query.h"
#include "totp.h"
#include "utils.h"
#include "version.h"
#include "webauthn.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <sstream>

namespace {
// kApprovedAccessTtlSeconds moved to route_common.h (shared with pro/).
constexpr int64_t kEphemeralLeaseTtlSeconds = 120;

int base_risk_score_for_level(const std::string &risk_level) {
  if (risk_level == "critical") return 85;
  if (risk_level == "high") return 70;
  if (risk_level == "medium") return 40;
  return 15;
}

std::string risk_level_for_score(int score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  return "low";
}

bool is_off_hours_utc() {
  const std::time_t now = std::time(nullptr);
  std::tm utc_tm{};
#ifdef _WIN32
  gmtime_s(&utc_tm, &now);
#else
  gmtime_r(&now, &utc_tm);
#endif
  return utc_tm.tm_hour < 6 || utc_tm.tm_hour >= 20;
}

// env_flag_enabled / env_string_value / env_int_value moved to route_common.cc
// (shared with the pro/ route groups).

std::string auth_user_anomaly_key(const std::string &username) {
  return "anomaly:auth:user:" + to_lower(trim_copy(username));
}

std::string auth_ip_anomaly_key(const std::string &client_ip) {
  return "anomaly:auth:ip:" + trim_copy(client_ip);
}


void maybe_emit_auth_failure_burst_anomaly(AppContext &ctx,
                                           const std::string &username,
                                           const std::string &client_ip,
                                           const std::string &trigger_type) {
  const int window_seconds = env_int_value(
      "ENDORIUMFORT_ALERT_AUTH_WINDOW_SECONDS", 180, 30, 3600);
  const int user_threshold = env_int_value(
      "ENDORIUMFORT_ALERT_AUTH_FAILURE_THRESHOLD", 5, 2, 100);
  const int ip_threshold = env_int_value(
      "ENDORIUMFORT_ALERT_AUTH_IP_THRESHOLD", 8, 2, 200);
  const int cooldown_seconds = env_int_value(
      "ENDORIUMFORT_ALERT_AUTH_COOLDOWN_SECONDS", 90, 10, 3600);

  const std::string normalized_user = trim_copy(username);
  if (!normalized_user.empty()) {
    const std::string user_key = auth_user_anomaly_key(normalized_user);
    const int signal_count =
        ctx.record_anomaly_signal(user_key, std::chrono::seconds(window_seconds));
    if (signal_count >= user_threshold &&
        ctx.should_emit_anomaly_signal(user_key + ":emit",
                                       std::chrono::seconds(cooldown_seconds))) {
      append_behavior_anomaly_event(
          ctx, "behavior.anomaly.auth_failure_burst", normalized_user,
          "{\"scope\":\"username\",\"username\":\"" +
              json_escape(normalized_user) + "\",\"ip\":\"" +
              json_escape(client_ip) + "\",\"signalCount\":" +
              std::to_string(signal_count) + ",\"windowSeconds\":" +
              std::to_string(window_seconds) + ",\"trigger\":\"" +
              json_escape(trigger_type) + "\"}");
    }
  }

  const std::string normalized_ip = trim_copy(client_ip);
  if (!normalized_ip.empty()) {
    const std::string ip_key = auth_ip_anomaly_key(normalized_ip);
    const int signal_count =
        ctx.record_anomaly_signal(ip_key, std::chrono::seconds(window_seconds));
    if (signal_count >= ip_threshold &&
        ctx.should_emit_anomaly_signal(ip_key + ":emit",
                                       std::chrono::seconds(cooldown_seconds))) {
      append_behavior_anomaly_event(
          ctx, "behavior.anomaly.auth_failure_burst", normalized_user,
          "{\"scope\":\"ip\",\"username\":\"" +
              json_escape(normalized_user) + "\",\"ip\":\"" +
              json_escape(normalized_ip) + "\",\"signalCount\":" +
              std::to_string(signal_count) + ",\"windowSeconds\":" +
              std::to_string(window_seconds) + ",\"trigger\":\"" +
              json_escape(trigger_type) + "\"}");
    }
  }
}



// has_permission(ctx, auth, permission) is defined in route_common.cc so the
// pro/ route groups can share it (external linkage).


bool can_access_any_resource(AppContext &ctx, const AuthSession &auth) {
  if (has_permission(ctx, auth, "resources.manage")) return true;
  if (has_permission(ctx, auth, "resources.read")) return true;
  return false;
}

crow::json::wvalue build_webauthn_assertion_options(
    const WebAuthnChallenge &challenge,
    const std::vector<WebAuthnCredential> &credentials) {
  crow::json::wvalue payload;
  payload["requestId"] = challenge.requestId;
  payload["challenge"] = webauthn::base64url_encode(challenge.challenge);
  payload["rpId"] = challenge.rpId;
  payload["timeout"] = challenge.expiresAtEpoch > now_epoch_seconds()
                           ? static_cast<int>((challenge.expiresAtEpoch -
                                               now_epoch_seconds()) *
                                              1000)
                           : 0;
  payload["userVerification"] = "preferred";
  payload["allowCredentials"] = crow::json::wvalue::list();
  int index = 0;
  for (const auto &credential : credentials) {
    crow::json::wvalue item;
    item["type"] = "public-key";
    item["id"] = credential.credentialId;
    payload["allowCredentials"][index++] = std::move(item);
  }
  return payload;
}

std::string build_webauthn_audit_payload(const WebAuthnCredential &credential) {
  std::ostringstream oss;
  oss << "{\"userId\":" << credential.userId
      << ",\"credentialRecordId\":" << credential.id
      << ",\"label\":\"" << json_escape(credential.label) << "\"";
  if (!credential.transportsCsv.empty()) {
    oss << ",\"transports\":\"" << json_escape(credential.transportsCsv) << "\"";
  }
  oss << '}';
  return oss.str();
}





bool is_valid_credential_source(const std::string &value) {
  return is_allowed_role(
      to_lower(value), {"vaulted", "brokered", "ephemeral_account"});
}



std::optional<UserAccount> find_user_account_snapshot(AppContext &ctx, int user_id) {
  std::lock_guard<std::mutex> lock(ctx.user_mutex);
  auto it = ctx.users.find(user_id);
  if (it == ctx.users.end()) return std::nullopt;
  return it->second;
}

bool user_meets_mfa_requirement(const UserAccount &user,
                                const std::string &requirement) {
  const std::string normalized = to_lower(trim_copy(requirement));
  if (normalized.empty() || normalized == "any") return true;
  if (normalized == "required") {
    return user.totpEnabled || user.webauthnCredentialCount > 0;
  }
  if (normalized == "totp") return user.totpEnabled;
  if (normalized == "webauthn") return user.webauthnCredentialCount > 0;
  return true;
}







std::vector<AccessProfile> query_user_access_profiles(AppContext &ctx, int user_id) {
  std::vector<AccessProfile> items;
  if (!ctx.sqlite.db || user_id <= 0) return items;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "SELECT p.id, p.name, p.description, p.resource_tags_csv, "
      "p.resource_ids_csv, p.policy_id, p.created_at, p.updated_at "
      "FROM access_profiles p "
      "INNER JOIN user_access_profiles up ON up.profile_id = p.id "
      "WHERE up.user_id = ? ORDER BY p.id ASC";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return items;
  sqlite3_bind_int(stmt, 1, user_id);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    AccessProfile profile;
    profile.id = sqlite3_column_int(stmt, 0);
    if (auto value = sqlite3_column_text(stmt, 1))
      profile.name = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 2))
      profile.description = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 3))
      profile.resourceTagsCsv = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 4))
      profile.resourceIdsCsv = reinterpret_cast<const char *>(value);
    profile.policyId = sqlite3_column_int(stmt, 5);
    if (auto value = sqlite3_column_text(stmt, 6))
      profile.createdAt = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 7))
      profile.updatedAt = reinterpret_cast<const char *>(value);
    items.push_back(profile);
  }
  sqlite3_finalize(stmt);
  return items;
}

std::vector<int> query_user_access_profile_ids(AppContext &ctx, int user_id) {
  std::vector<int> ids;
  if (!ctx.sqlite.db || user_id <= 0) return ids;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "SELECT profile_id FROM user_access_profiles WHERE user_id=? ORDER BY profile_id ASC";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return ids;
  sqlite3_bind_int(stmt, 1, user_id);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    ids.push_back(sqlite3_column_int(stmt, 0));
  }
  sqlite3_finalize(stmt);
  return ids;
}




bool assign_access_profile_to_user(AppContext &ctx, int user_id, int profile_id) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "INSERT OR IGNORE INTO user_access_profiles (user_id, profile_id, created_at) "
      "VALUES (?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_int(stmt, 2, profile_id);
  const std::string created_at = now_utc();
  sqlite3_bind_text(stmt, 3, created_at.c_str(), -1, SQLITE_TRANSIENT);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool revoke_access_profile_from_user(AppContext &ctx, int user_id, int profile_id) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "DELETE FROM user_access_profiles WHERE user_id=? AND profile_id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_int(stmt, 2, profile_id);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}



bool insert_access_grant_db(AppContext &ctx, const AccessGrant &grant) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "INSERT INTO access_grants "
      "(id, policy_id, profile_id, resource_id, session_id, approval_ref, "
      "subject, resource_scope, granted_at, expires_at, used_at, mission_ref, "
      "elevation_scope, status, credential_source, routing_constraint, "
      "ticket_id, purpose, justification, mfa_requirement) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, grant.id);
  sqlite3_bind_int(stmt, 2, grant.policyId);
  sqlite3_bind_int(stmt, 3, grant.profileId);
  sqlite3_bind_int(stmt, 4, grant.resourceId);
  sqlite3_bind_int(stmt, 5, grant.sessionId);
  sqlite3_bind_int(stmt, 6, grant.approvalRef);
  sqlite3_bind_text(stmt, 7, grant.subject.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 8, grant.resourceScope.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, grant.grantedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 10, grant.expiresAt.c_str(), -1, SQLITE_TRANSIENT);
  grant.usedAt.empty()
      ? sqlite3_bind_null(stmt, 11)
      : sqlite3_bind_text(stmt, 11, grant.usedAt.c_str(), -1, SQLITE_TRANSIENT);
  grant.missionRef.empty()
      ? sqlite3_bind_null(stmt, 12)
      : sqlite3_bind_text(stmt, 12, grant.missionRef.c_str(), -1, SQLITE_TRANSIENT);
  grant.elevationScope.empty()
      ? sqlite3_bind_null(stmt, 13)
      : sqlite3_bind_text(stmt, 13, grant.elevationScope.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 14, grant.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 15, grant.credentialSource.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 16, grant.routingConstraint.c_str(), -1, SQLITE_TRANSIENT);
  grant.ticketId.empty()
      ? sqlite3_bind_null(stmt, 17)
      : sqlite3_bind_text(stmt, 17, grant.ticketId.c_str(), -1, SQLITE_TRANSIENT);
  grant.purpose.empty()
      ? sqlite3_bind_null(stmt, 18)
      : sqlite3_bind_text(stmt, 18, grant.purpose.c_str(), -1, SQLITE_TRANSIENT);
  grant.justification.empty()
      ? sqlite3_bind_null(stmt, 19)
      : sqlite3_bind_text(stmt, 19, grant.justification.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 20, grant.mfaRequirement.c_str(), -1, SQLITE_TRANSIENT);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool update_access_grant_session_binding(AppContext &ctx, int grant_id, int session_id) {
  if (!ctx.sqlite.db || grant_id <= 0) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql = "UPDATE access_grants SET session_id=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, session_id);
  sqlite3_bind_int(stmt, 2, grant_id);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}



bool profile_matches_resource(const AccessProfile &profile,
                              const Resource &resource) {
  if (csv_contains_token(profile.resourceIdsCsv, std::to_string(resource.id))) {
    return true;
  }
  if (!profile.resourceTagsCsv.empty() &&
      csv_intersects(profile.resourceTagsCsv, resource.tagsCsv)) {
    return true;
  }
  return profile.resourceIdsCsv.empty() && profile.resourceTagsCsv.empty();
}

bool policy_matches_subject_and_resource(const AccessPolicy &policy,
                                         const AuthSession &auth,
                                         const Resource &resource) {
  if (!policy.enabled) return false;
  const std::string identity_pattern = to_lower(trim_copy(policy.identityPattern));
  if (!identity_pattern.empty() && identity_pattern != "*" &&
      identity_pattern != to_lower(auth.user)) {
    return false;
  }
  const std::string role = to_lower(trim_copy(policy.role));
  if (!role.empty() && role != "any" && role != normalize_user_role(auth.role)) {
    return false;
  }
  const std::string group = to_lower(trim_copy(policy.groupName));
  if (!group.empty() && group != "*" && group != normalize_user_role(auth.role)) {
    return false;
  }
  const std::string risk = to_lower(trim_copy(policy.riskLevel));
  if (!risk.empty() && risk != "any" && risk != to_lower(resource.riskLevel)) {
    return false;
  }
  if (!policy.resourceTagsCsv.empty() &&
      !csv_intersects(policy.resourceTagsCsv, resource.tagsCsv)) {
    return false;
  }
  return true;
}

struct AccessDecision {
  bool requireJustification = false;
  bool ticketRequired = false;
  bool approvalRequired = false;
  bool purposeRequired = false;
  std::string mfaRequirement = "any";
  std::string routingConstraint = "any";
  int maxDurationSeconds = 3600;
  int selectedPolicyId = 0;
  int selectedProfileId = 0;
  std::vector<int> matchedPolicyIds;
  std::vector<std::string> matchedPolicyNames;
  std::vector<std::string> factors;
};

AccessDecision build_access_decision(
    AppContext &ctx, const AuthSession &auth, const UserAccount &account,
    const Resource &resource, const std::vector<AccessPolicy> &all_policies,
    const std::vector<AccessProfile> &user_profiles) {
  AccessDecision decision;
  decision.requireJustification = resource.requireAccessJustification;
  decision.approvalRequired = resource.requireDualApproval;
  decision.purposeRequired =
      to_lower(resource.riskLevel) == "high" ||
      to_lower(resource.riskLevel) == "critical";
  if (resource.adaptiveAccessPolicy && decision.purposeRequired) {
    decision.ticketRequired = true;
    decision.factors.push_back("resource.adaptive.ticket_required");
  }

  std::unordered_set<int> applied_policy_ids;
  std::unordered_map<int, int> policy_profile_map;
  for (const auto &profile : user_profiles) {
    if (!profile_matches_resource(profile, resource) || profile.policyId <= 0) continue;
    policy_profile_map[profile.policyId] = profile.id;
  }

  const std::time_t now = std::time(nullptr);
  std::tm utc_tm{};
#ifdef _WIN32
  gmtime_s(&utc_tm, &now);
#else
  gmtime_r(&now, &utc_tm);
#endif

  for (const auto &policy : all_policies) {
    const bool global_match =
        policy_matches_subject_and_resource(policy, auth, resource);
    const auto profile_it = policy_profile_map.find(policy.id);
    if (!global_match && profile_it == policy_profile_map.end()) continue;
    if (!applied_policy_ids.insert(policy.id).second) continue;
    if (!is_time_window_match_utc(policy.timeWindow, utc_tm.tm_hour,
                                  utc_tm.tm_min)) {
      decision.factors.push_back("policy.time_window.denied:" + policy.name);
      continue;
    }

    decision.matchedPolicyIds.push_back(policy.id);
    decision.matchedPolicyNames.push_back(policy.name);
    if (decision.selectedPolicyId == 0) decision.selectedPolicyId = policy.id;
    if (profile_it != policy_profile_map.end() && decision.selectedProfileId == 0) {
      decision.selectedProfileId = profile_it->second;
    }
    if (policy.requireJustification) decision.requireJustification = true;
    if (policy.ticketRequired) decision.ticketRequired = true;
    if (to_lower(policy.approvalMode) == "required") {
      decision.approvalRequired = true;
    }
    decision.mfaRequirement =
        stronger_mfa_requirement(decision.mfaRequirement, policy.mfaRequirement);
    if (policy.maxDurationSeconds > 0 &&
        (decision.maxDurationSeconds <= 0 ||
         policy.maxDurationSeconds < decision.maxDurationSeconds)) {
      decision.maxDurationSeconds = policy.maxDurationSeconds;
      decision.selectedPolicyId = policy.id;
      if (profile_it != policy_profile_map.end()) {
        decision.selectedProfileId = profile_it->second;
      }
    }
    const std::string routing = to_lower(policy.routingConstraint);
    if (!routing.empty() && routing != "any") {
      if (decision.routingConstraint == "any" ||
          decision.routingConstraint == routing) {
        decision.routingConstraint = routing;
      } else {
        decision.factors.push_back("policy.routing.conflict");
      }
    }
  }

  if (!user_meets_mfa_requirement(account, decision.mfaRequirement)) {
    decision.factors.push_back("policy.mfa.missing:" + decision.mfaRequirement);
  }

  if (decision.routingConstraint == "relay") {
    std::lock_guard<std::mutex> lock(ctx.relay_mutex);
    if (!ctx.resource_relay_bindings.count(resource.id) ||
        ctx.resource_relay_bindings[resource.id].empty()) {
      decision.factors.push_back("policy.routing.relay_required");
    }
  }

  return decision;
}

}

// ══════════════════════════════════════════════════════════════════════
//  Health
// ══════════════════════════════════════════════════════════════════════

void register_health_routes(CrowApp &app, AppContext &) {
  CROW_ROUTE(app, "/api/health")([] {
    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["message"] = "EndoriumFort API online";
    payload["version"] = APP_VERSION;
    return payload;
  });
}

// ══════════════════════════════════════════════════════════════════════
//  Auth (login / logout / change-password)
// ══════════════════════════════════════════════════════════════════════

void register_auth_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/auth/sso/oidc/start
  CROW_ROUTE(app, "/api/auth/login").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");
        std::string user = body["user"].s();
        std::string password = body["password"].s();
        if (user.empty() || password.empty())
          return crow::response(400, "Missing user or password");

        // Extract client IP for IP-based rate limiting
        std::string client_ip = get_client_ip(request);

        // Check username-based rate limiting
        if (!ctx.check_rate_limit("login:" + user)) {
          AuditEvent rl_evt;
          rl_evt.id = ctx.next_audit_id.fetch_add(1);
          rl_evt.type = "auth.login.rate_limited";
          rl_evt.actor = user;
          rl_evt.role = "";
          rl_evt.createdAt = now_utc();
          rl_evt.payloadJson = "{\"username\":\"" + json_escape(user) + "\",\"reason\":\"username_rate_limit\",\"ip\":\"" + json_escape(client_ip) + "\"}";
          rl_evt.payloadIsJson = true;
          ctx.append_audit(rl_evt);
          maybe_emit_auth_failure_burst_anomaly(ctx, user, client_ip,
                                                rl_evt.type);
          return crow::response(429, "Too many login attempts. Try again later.");
        }

        // Check IP-based rate limiting (brute-force protection across different usernames)
        if (!ctx.check_rate_limit("login_ip:" + client_ip)) {
          AuditEvent rl_evt;
          rl_evt.id = ctx.next_audit_id.fetch_add(1);
          rl_evt.type = "auth.login.rate_limited";
          rl_evt.actor = user;
          rl_evt.role = "";
          rl_evt.createdAt = now_utc();
          rl_evt.payloadJson = "{\"username\":\"" + json_escape(user) + "\",\"reason\":\"ip_rate_limit\",\"ip\":\"" + json_escape(client_ip) + "\"}";
          rl_evt.payloadIsJson = true;
          ctx.append_audit(rl_evt);
          maybe_emit_auth_failure_burst_anomaly(ctx, user, client_ip,
                                                rl_evt.type);
          return crow::response(429, "Too many login attempts from this IP. Try again later.");
        }

        // Optional MFA payloads for 2FA
        std::string totp_code;
        if (body.has("totpCode"))
          totp_code = body["totpCode"].s();
        std::string webauthn_request_id;
        std::string webauthn_credential_id;
        std::string webauthn_client_data;
        std::string webauthn_authenticator_data;
        std::string webauthn_signature;
        if (body.has("webauthnRequestId"))
          webauthn_request_id = body["webauthnRequestId"].s();
        if (body.has("webauthnCredentialId"))
          webauthn_credential_id = body["webauthnCredentialId"].s();
        if (body.has("webauthnClientDataJSON"))
          webauthn_client_data = body["webauthnClientDataJSON"].s();
        if (body.has("webauthnAuthenticatorData"))
          webauthn_authenticator_data = body["webauthnAuthenticatorData"].s();
        if (body.has("webauthnSignature"))
          webauthn_signature = body["webauthnSignature"].s();

        std::optional<UserAccount> matched;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          for (const auto &entry : ctx.users) {
            if (entry.second.username == user) {
              matched = entry.second;
              break;
            }
          }
        }

        const LdapRuntimeConfig ldap_cfg = load_ldap_runtime_config();
        bool ldap_authenticated = false;
        std::string ldap_directory_identity;
        LdapRoleResolution ldap_role_resolution;
        bool local_password_ok =
            matched && crypto::verify_password(password, matched->password);

        if (!local_password_ok) {
          const bool can_try_ldap =
              ldap_cfg.enabled &&
              (!matched || is_ldap_shadow_password(matched->password));
          if (can_try_ldap) {
            std::string ldap_error;
            if (ldap_authenticate_user(ldap_cfg, user, password,
                                       ldap_directory_identity, ldap_error)) {
              ldap_role_resolution =
                resolve_ldap_role(ldap_cfg, user, ldap_directory_identity);
              bool ldap_created = false;
              bool ldap_role_updated = false;
              std::string provision_error;
              auto ldap_user = provision_ldap_shadow_user(
                ctx, user, ldap_cfg, ldap_role_resolution.role, ldap_created,
                ldap_role_updated, provision_error);
              if (!ldap_user) {
                AuditEvent ldap_evt;
                ldap_evt.id = ctx.next_audit_id.fetch_add(1);
                ldap_evt.type = "auth.login.ldap.failure";
                ldap_evt.actor = user;
                ldap_evt.role = "";
                ldap_evt.createdAt = now_utc();
                ldap_evt.payloadJson =
                    "{\"reason\":\"provisioning_failed\",\"username\":\"" +
                    json_escape(user) + "\",\"ip\":\"" +
                    json_escape(client_ip) + "\",\"detail\":\"" +
                    json_escape(provision_error) + "\"}";
                ldap_evt.payloadIsJson = true;
                ctx.append_audit(ldap_evt);
                return crow::response(500, "Failed to provision LDAP user");
              }

              matched = *ldap_user;
              local_password_ok = true;
              ldap_authenticated = true;

              AuditEvent ldap_evt;
              ldap_evt.id = ctx.next_audit_id.fetch_add(1);
              ldap_evt.type = "auth.login.ldap.success";
              ldap_evt.actor = matched->username;
              ldap_evt.role = matched->role;
              ldap_evt.createdAt = now_utc();
              ldap_evt.payloadJson =
                  "{\"username\":\"" + json_escape(matched->username) +
                  "\",\"ip\":\"" + json_escape(client_ip) +
                  "\",\"directoryIdentity\":\"" +
                  json_escape(ldap_directory_identity) + "\",\"created\":" +
                  (ldap_created ? "true" : "false") +
                  ",\"roleUpdated\":" +
                  (ldap_role_updated ? "true" : "false") +
                  ",\"mappedRole\":\"" +
                  json_escape(ldap_role_resolution.role) +
                  "\",\"mappingStrategy\":\"" +
                  json_escape(ldap_role_resolution.strategy) +
                  "\",\"matchedRule\":\"" +
                  json_escape(ldap_role_resolution.matchedRule) + "\"}";
              ldap_evt.payloadIsJson = true;
              ctx.append_audit(ldap_evt);
            } else {
              AuditEvent ldap_evt;
              ldap_evt.id = ctx.next_audit_id.fetch_add(1);
              ldap_evt.type = "auth.login.ldap.failure";
              ldap_evt.actor = user;
              ldap_evt.role = "";
              ldap_evt.createdAt = now_utc();
              ldap_evt.payloadJson =
                  "{\"reason\":\"bind_failed\",\"username\":\"" +
                  json_escape(user) + "\",\"ip\":\"" +
                  json_escape(client_ip) + "\",\"detail\":\"" +
                  json_escape(ldap_error) + "\"}";
              ldap_evt.payloadIsJson = true;
              ctx.append_audit(ldap_evt);
            }
          }
        }

        // Verify password (supports hashed and legacy plaintext) with optional
        // LDAP fallback for directory-managed users.
        if (!local_password_ok) {
          // Record failed attempt for exponential backoff
          ctx.record_failed_login_attempt("login:" + user);
          ctx.record_failed_login_attempt("login_ip:" + client_ip);
          
          // Audit: login failure
          AuditEvent evt;
          evt.id = ctx.next_audit_id.fetch_add(1);
          evt.type = "auth.login.failure";
          evt.actor = user;
          evt.role = "";
          evt.createdAt = now_utc();
          evt.payloadJson = "{\"reason\":\"invalid_credentials\",\"username\":\"" +
                            json_escape(user) + "\",\"ip\":\"" + json_escape(client_ip) + "\"}";
          evt.payloadIsJson = true;
          ctx.append_audit(evt);
          maybe_emit_auth_failure_burst_anomaly(ctx, user, client_ip, evt.type);
          return crow::response(401, "Invalid credentials");
        }

        // Auto-migrate legacy password formats to the current scrypt scheme.
        if (!ldap_authenticated &&
            crypto::password_hash_needs_rehash(matched->password)) {
          std::string hashed = crypto::hash_password(password);
          ctx.update_user_password_hash(matched->id, hashed);
          matched->password = hashed;
        }

        const bool has_webauthn = user_has_webauthn_enabled(*matched);
        if (matched->totpEnabled || has_webauthn) {
          bool mfa_ok = false;

          if (matched->totpEnabled && !totp_code.empty() &&
              totp::verify_code(matched->totpSecret, totp_code)) {
            mfa_ok = true;
          }

          if (!mfa_ok && has_webauthn && !webauthn_request_id.empty() &&
              !webauthn_credential_id.empty() && !webauthn_client_data.empty() &&
              !webauthn_authenticator_data.empty() && !webauthn_signature.empty()) {
            const auto challenge = ctx.consume_webauthn_challenge(
                webauthn_request_id, matched->id, "login");
            const auto credential =
                ctx.find_webauthn_credential_by_external_id(webauthn_credential_id);
            const auto client_data =
                webauthn::parse_client_data(webauthn_client_data);
            const auto authenticator_data = challenge
                                                ? webauthn::parse_authenticator_data(
                                                      webauthn_authenticator_data,
                                                      challenge->rpId)
                                                : std::nullopt;

            if (challenge && credential && client_data && authenticator_data &&
                credential->userId == matched->id &&
                client_data->type == "webauthn.get" &&
                client_data->challenge ==
                    webauthn::base64url_encode(challenge->challenge) &&
                client_data->origin == challenge->origin &&
                (authenticator_data->flags & 0x01) != 0 &&
                webauthn::verify_assertion_signature(
                    credential->publicKeySpki, authenticator_data->raw,
                    client_data->rawJson, webauthn_signature)) {
              if (!(credential->signCount > 0 &&
                    authenticator_data->signCount <=
                        static_cast<uint32_t>(credential->signCount) &&
                    authenticator_data->signCount != 0)) {
                WebAuthnCredential updated = *credential;
                updated.signCount =
                    static_cast<int>(authenticator_data->signCount);
                updated.lastUsedAt = now_utc();
                ctx.update_webauthn_credential(updated);
                mfa_ok = true;
              }
            }
          }

          if (!mfa_ok) {
            if (matched->totpEnabled && !totp_code.empty() && !has_webauthn) {
              AuditEvent evt;
              evt.id = ctx.next_audit_id.fetch_add(1);
              evt.type = "auth.login.2fa_failure";
              evt.actor = user;
              evt.role = matched->role;
              evt.createdAt = now_utc();
              evt.payloadJson = "{\"userId\":" + std::to_string(matched->id) + "}";
              evt.payloadIsJson = true;
              ctx.append_audit(evt);
              return crow::response(401, "Invalid TOTP code");
            }

            crow::json::wvalue payload;
            payload["status"] = "mfa_required";
            payload["message"] =
                "A second factor is required to complete this login";
            payload["user"] = matched->username;
            apply_auth_mfa_payload(payload, *matched);
            payload["mfaMethods"] = crow::json::wvalue::list();
            int method_index = 0;
            const auto ordered_methods = ordered_mfa_methods_for_login(*matched);
            bool needs_webauthn_options = false;
            for (const auto &method : ordered_methods) {
              payload["mfaMethods"][method_index++] = method;
              if (method == "webauthn") needs_webauthn_options = true;
            }
            if (needs_webauthn_options) {
              const std::string rp_id = webauthn::expected_rp_id(
                  request, ctx.webauthn_rp_id_override);
              const std::string origin = webauthn::expected_origin(
                  request, ctx.webauthn_origin_override);
              if (!webauthn::is_valid_rp_id(rp_id) ||
                  !webauthn::is_valid_origin(origin)) {
                return crow::response(
                    400,
                    "WebAuthn requires a valid domain. Configure "
                    "ENDORIUMFORT_WEBAUTHN_RP_ID and ENDORIUMFORT_WEBAUTHN_ORIGIN "
                    "(example: app.example.com / https://app.example.com), or use localhost in dev.");
              }
              const auto challenge = ctx.create_webauthn_challenge(
                  matched->id, matched->username, "login", rp_id, origin);
              payload["webauthn"] = build_webauthn_assertion_options(
                  challenge, ctx.get_user_webauthn_credentials(matched->id));
            }
            return crow::response{payload};
          }
        }

        // Cleanup expired tokens periodically
        ctx.cleanup_expired_tokens();

        AuthSession auth;
        auth.userId = matched->id;
        auth.user = matched->username;
        auth.role = matched->role;
        auth.issuedAt = now_utc();
        auth.expiresAt = ctx.compute_expiry();
        auth.token = ctx.generate_token();

        {
          std::lock_guard<std::mutex> lock(ctx.auth_mutex);
          ctx.auth_sessions[auth.token] = auth;
        }

        // Clear rate limiting attempts on successful login
        ctx.clear_login_attempts("login:" + user);
        ctx.clear_login_attempts("login_ip:" + client_ip);
        ctx.clear_anomaly_signal(auth_user_anomaly_key(user));
        ctx.clear_anomaly_signal(auth_user_anomaly_key(user) + ":emit");
        ctx.clear_anomaly_signal(auth_ip_anomaly_key(client_ip));
        ctx.clear_anomaly_signal(auth_ip_anomaly_key(client_ip) + ":emit");

        // Audit: login success
        AuditEvent evt;
        evt.id = ctx.next_audit_id.fetch_add(1);
        evt.type = "auth.login.success";
        evt.actor = matched->username;
        evt.role = matched->role;
        evt.createdAt = now_utc();
        evt.payloadJson = "{\"userId\":" + std::to_string(matched->id) +
              ",\"username\":\"" +
              json_escape(matched->username) +
              "\",\"ip\":\"" + json_escape(client_ip) +
              "\",\"authSource\":\"" +
              std::string(ldap_authenticated ? "ldap" : "local") +
              "\",\"directoryRole\":\"" +
              json_escape(ldap_authenticated
                  ? ldap_role_resolution.role
                  : std::string("")) +
              "\",\"directoryRoleStrategy\":\"" +
              json_escape(ldap_authenticated
                  ? ldap_role_resolution.strategy
                  : std::string("")) + "\"}";
        evt.payloadIsJson = true;
        ctx.append_audit(evt);

        crow::json::wvalue payload;
        payload["token"] = auth.token;
        payload["user"] = auth.user;
        payload["role"] = auth.role;
        payload["permissions"] = crow::json::wvalue::list();
        int perm_index = 0;
        auto effective_permissions =
            ctx.get_effective_permissions(auth.userId, auth.role);
        for (const auto &permission : effective_permissions) {
          payload["permissions"][perm_index++] = permission;
        }
        payload["issuedAt"] = auth.issuedAt;
        payload["expiresAt"] = auth.expiresAt;
        payload["authSource"] = ldap_authenticated ? "ldap" : "local";
        if (ldap_authenticated) {
          payload["directoryRole"] = ldap_role_resolution.role;
          payload["directoryRoleStrategy"] = ldap_role_resolution.strategy;
          payload["directoryMatchedRule"] = ldap_role_resolution.matchedRule;
        }
        apply_auth_mfa_payload(payload, *matched);
        crow::response response{payload};
        response.add_header(
            "Set-Cookie",
            build_auth_cookie(auth.token, request_uses_https(request),
                              ctx.token_ttl_seconds));
        response.add_header("Cache-Control", "no-store");
        return response;
      });

  // POST /api/auth/logout
  CROW_ROUTE(app, "/api/auth/logout").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        // Audit: logout
        AuditEvent evt;
        evt.id = ctx.next_audit_id.fetch_add(1);
        evt.type = "auth.logout";
        evt.actor = auth->user;
        evt.role = auth->role;
        evt.createdAt = now_utc();
        evt.payloadJson = "{\"userId\":" + std::to_string(auth->userId) + "}";
        evt.payloadIsJson = true;
        ctx.append_audit(evt);

        ctx.invalidate_token(auth->token);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["message"] = "Logged out";
        crow::response response{payload};
        response.add_header("Set-Cookie",
                            build_cleared_auth_cookie(request_uses_https(request)));
        response.add_header("Cache-Control", "no-store");
        return response;
      });

  // POST /api/auth/change-password
  CROW_ROUTE(app, "/api/auth/change-password").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");
        std::string current_password = body["currentPassword"].s();
        std::string new_password = body["newPassword"].s();
        bool keep_current_session = body.has("keepCurrentSession") &&
                                    body["keepCurrentSession"].b();
        if (current_password.empty() || new_password.empty())
          return crow::response(400, "Missing currentPassword or newPassword");

        // Verify current password
        std::string stored;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it == ctx.users.end())
            return crow::response(404, "User not found");
          stored = it->second.password;
        }
        if (!crypto::verify_password(current_password, stored))
          return crow::response(401, "Current password is incorrect");

        // Validate new password
        auto policy = crypto::validate_password(new_password);
        if (!policy.valid)
          return crow::response(400, policy.message);

        // Hash and store
        std::string hashed = crypto::hash_password(new_password);
        if (!ctx.update_user_password_hash(auth->userId, hashed))
          return crow::response(500, "Failed to update password");
        bool mfa_required = false;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it == ctx.users.end())
            return crow::response(404, "User not found");
          mfa_required = it->second.bootstrapMfaRequired;
        }
        if (!ctx.update_user_bootstrap_flags(auth->userId, false, mfa_required))
          return crow::response(500, "Failed to update bootstrap security status");

        // Invalidate sessions, optionally preserving the current bootstrap flow.
        if (keep_current_session) {
          ctx.invalidate_user_tokens_except(auth->userId, auth->token);
        } else {
          ctx.invalidate_user_tokens(auth->userId);
        }

        // Audit
        AuditEvent evt;
        evt.id = ctx.next_audit_id.fetch_add(1);
        evt.type = "user.password.change";
        evt.actor = auth->user;
        evt.role = auth->role;
        evt.createdAt = now_utc();
        evt.payloadJson = "{\"userId\":" + std::to_string(auth->userId) + ",\"tokensInvalidated\":true}";
        evt.payloadIsJson = true;
        ctx.append_audit(evt);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it != ctx.users.end()) {
            apply_auth_mfa_payload(payload, it->second);
          }
        }
        payload["message"] = keep_current_session
                                 ? "Password changed successfully."
                                 : "Password changed. All sessions invalidated — please log in again.";
        crow::response response{payload};
        response.add_header(
            "Set-Cookie",
            keep_current_session
                ? build_auth_cookie(auth->token, request_uses_https(request),
                                    ctx.token_ttl_seconds)
                : build_cleared_auth_cookie(request_uses_https(request)));
        response.add_header("Cache-Control", "no-store");
        return response;
      });

  // GET /api/auth/bootstrap-status
  CROW_ROUTE(app, "/api/auth/bootstrap-status").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        std::lock_guard<std::mutex> lock(ctx.user_mutex);
        auto it = ctx.users.find(auth->userId);
        if (it == ctx.users.end())
          return crow::response(404, "User not found");

        crow::json::wvalue payload;
        payload["status"] = "ok";
        apply_auth_mfa_payload(payload, it->second);
        return scim_json_response(payload);
      });
}

// ══════════════════════════════════════════════════════════════════════
//  Users
// ══════════════════════════════════════════════════════════════════════

void register_user_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/users
  CROW_ROUTE(app, "/api/users").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.read"))
          return crow::response(403, "Forbidden");

        std::vector<UserAccount> snapshot;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          snapshot.reserve(ctx.users.size());
          for (const auto &entry : ctx.users)
            snapshot.push_back(entry.second);
        }
        std::sort(snapshot.begin(), snapshot.end(),
                  [](const UserAccount &a, const UserAccount &b) {
                    return a.id < b.id;
                  });
        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < snapshot.size(); ++i)
          payload["items"][static_cast<int>(i)] = user_to_json(snapshot[i]);
        return scim_json_response(payload);
      });

  // POST /api/users
  CROW_ROUTE(app, "/api/users").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.manage"))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        std::string username = body["username"].s();
        std::string password = body["password"].s();
        std::string role = body["role"].s();
        bool force_password_rotation =
            body.has("forcePasswordRotation")
                ? body["forcePasswordRotation"].b()
                : normalize_user_role(role) == "admin";
        if (username.empty() || password.empty() || role.empty())
          return crow::response(400, "Missing username, password, or role");
        if (!is_allowed_user_role(role, {"operator", "admin", "auditor"}))
          return crow::response(400, "Invalid role");

        // Validate password policy
        auto policy = crypto::validate_password(password);
        if (!policy.valid)
          return crow::response(400, policy.message);

        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          for (const auto &entry : ctx.users) {
            if (entry.second.username == username)
              return crow::response(409, "User already exists");
          }
        }

        UserAccount user;
        user.id = ctx.next_user_id.fetch_add(1);
        user.username = username;
        user.password = crypto::hash_password(password);
        user.role = normalize_user_role(role);
        user.createdAt = now_utc();
        user.updatedAt = user.createdAt;
        user.bootstrapPasswordChangeRequired = force_password_rotation;
        user.bootstrapMfaRequired = user.role == "admin";

        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          ctx.users[user.id] = user;
        }
        if (!ctx.insert_user(user))
          return crow::response(500, "Failed to persist user");

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "user.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_user_payload_json(user);
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload = user_to_json(user);
        return scim_json_response(payload);
      });

  // PUT /api/users/<int>
  CROW_ROUTE(app, "/api/users/<int>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, int user_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "users.manage"))
              return crow::response(403, "Forbidden");
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            std::string password = body["password"].s();
            std::string role = body["role"].s();
            std::string normalized_role = normalize_user_role(role);
            bool force_password_rotation =
                body.has("forcePasswordRotation")
                    ? body["forcePasswordRotation"].b()
                    : normalized_role == "admin";
            if (password.empty() || role.empty())
              return crow::response(400, "Missing password or role");
            if (!is_allowed_user_role(role, {"operator", "admin", "auditor"}))
              return crow::response(400, "Invalid role");

            // Validate password policy
            auto policy = crypto::validate_password(password);
            if (!policy.valid)
              return crow::response(400, policy.message);

            UserAccount user;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(user_id);
              if (it == ctx.users.end())
                return crow::response(404, "User not found");
              user = it->second;
              user.password = crypto::hash_password(password);
              user.role = normalized_role;
              user.updatedAt = now_utc();
              user.bootstrapPasswordChangeRequired = force_password_rotation;
              user.bootstrapMfaRequired =
                  user.role == "admin" && !user.totpEnabled &&
                  user.webauthnCredentialCount == 0;
              it->second = user;
            }
            if (!ctx.update_user_db(user))
              return crow::response(500, "Failed to persist user");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.update";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_user_payload_json(user);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload = user_to_json(user);
            return crow::response{payload};
          });

  // DELETE /api/users/<int>
  CROW_ROUTE(app, "/api/users/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int user_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "users.manage"))
              return crow::response(403, "Forbidden");

            UserAccount user;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(user_id);
              if (it == ctx.users.end())
                return crow::response(404, "User not found");
              user = it->second;
              ctx.users.erase(it);
            }
            if (!ctx.delete_user_db(user_id))
              return crow::response(500, "Failed to delete user");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.delete";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_user_payload_json(user);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "deleted";
            payload["id"] = user_id;
            return crow::response{payload};
          });

  // GET /api/users/<int>/resources
  CROW_ROUTE(app, "/api/users/<int>/resources")
      .methods(crow::HTTPMethod::Get)(
          [&ctx](const crow::request &request, int user_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.assign"))
              return crow::response(403, "Forbidden");

            auto allowed_ids = ctx.get_resource_permissions(user_id);
            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["userId"] = user_id;
            payload["resourceIds"] = crow::json::wvalue::list();
            for (size_t i = 0; i < allowed_ids.size(); ++i)
              payload["resourceIds"][static_cast<int>(i)] = allowed_ids[i];
            return crow::response{payload};
          });

  // POST /api/users/<int>/resources/<int>
  CROW_ROUTE(app, "/api/users/<int>/resources/<int>")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int user_id, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.assign"))
              return crow::response(403, "Forbidden");
            if (!ctx.grant_resource_permission(user_id, resource_id))
              return crow::response(500, "Failed to grant permission");

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "Permission granted";
            payload["userId"] = user_id;
            payload["resourceId"] = resource_id;
            return crow::response{payload};
          });

  // DELETE /api/users/<int>/resources/<int>
  CROW_ROUTE(app, "/api/users/<int>/resources/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int user_id, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.assign"))
              return crow::response(403, "Forbidden");
            if (!ctx.revoke_resource_permission(user_id, resource_id))
              return crow::response(500, "Failed to revoke permission");

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "Permission revoked";
            payload["userId"] = user_id;
            payload["resourceId"] = resource_id;
            return crow::response{payload};
          });

  // GET /api/users/<int>/access-profiles
  CROW_ROUTE(app, "/api/users/<int>/access-profiles")
      .methods(crow::HTTPMethod::Get)(
          [&ctx](const crow::request &request, int user_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.assign"))
              return crow::response(403, "Forbidden");

            const auto profile_ids = query_user_access_profile_ids(ctx, user_id);
            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["userId"] = user_id;
            payload["profileIds"] = crow::json::wvalue::list();
            for (size_t i = 0; i < profile_ids.size(); ++i) {
              payload["profileIds"][static_cast<int>(i)] = profile_ids[i];
            }
            return crow::response{payload};
          });

  // POST /api/users/<int>/access-profiles/<int>
  CROW_ROUTE(app, "/api/users/<int>/access-profiles/<int>")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int user_id, int profile_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.assign"))
              return crow::response(403, "Forbidden");
            const auto profiles = query_access_profiles(ctx);
            if (std::none_of(profiles.begin(), profiles.end(),
                             [&](const AccessProfile &item) {
                               return item.id == profile_id;
                             })) {
              return crow::response(404, "Access profile not found");
            }
            if (!assign_access_profile_to_user(ctx, user_id, profile_id))
              return crow::response(500, "Failed to assign access profile");

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["userId"] = user_id;
            payload["profileId"] = profile_id;
            return crow::response{payload};
          });

  // DELETE /api/users/<int>/access-profiles/<int>
  CROW_ROUTE(app, "/api/users/<int>/access-profiles/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int user_id, int profile_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.assign"))
              return crow::response(403, "Forbidden");
            if (!revoke_access_profile_from_user(ctx, user_id, profile_id))
              return crow::response(500, "Failed to revoke access profile");

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["userId"] = user_id;
            payload["profileId"] = profile_id;
            return crow::response{payload};
          });
}

// ══════════════════════════════════════════════════════════════════════
//  Resources
// ══════════════════════════════════════════════════════════════════════

void register_resource_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/resources
  CROW_ROUTE(app, "/api/resources").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!can_access_any_resource(ctx, *auth))
          return crow::response(403, "Forbidden");

        std::vector<int> allowed_resource_ids;
        if (has_permission(ctx, *auth, "resources.manage")) {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          for (const auto &entry : ctx.resources)
            allowed_resource_ids.push_back(entry.first);
        } else {
          allowed_resource_ids = ctx.get_resource_permissions(auth->userId);
        }

        std::vector<Resource> snapshot;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          for (int rid : allowed_resource_ids) {
            auto it = ctx.resources.find(rid);
            if (it != ctx.resources.end()) snapshot.push_back(it->second);
          }
        }
        std::sort(snapshot.begin(), snapshot.end(),
                  [](const Resource &a, const Resource &b) {
                    return a.id < b.id;
                  });
        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < snapshot.size(); ++i)
          payload["items"][static_cast<int>(i)] = resource_to_json(snapshot[i]);
        return scim_json_response(payload);
      });

  // POST /api/resources
  CROW_ROUTE(app, "/api/resources").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage"))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        std::string name = body["name"].s();
        std::string target = body["target"].s();
        std::string protocol = body["protocol"].s();
        int port = 22;
        if (body.has("port")) port = body["port"].i();
        int tunnel_ticket_rate_limit_max_attempts = 0;
        if (body.has("tunnelTicketRateLimitMaxAttempts")) {
          tunnel_ticket_rate_limit_max_attempts =
              body["tunnelTicketRateLimitMaxAttempts"].i();
        }
        std::string description;
        if (body.has("description")) description = body["description"].s();
        std::string image_url;
        if (body.has("imageUrl")) image_url = body["imageUrl"].s();
        std::string image_data;
        if (body.has("imageData")) image_data = body["imageData"].s();
        std::string tags_csv;
        if (body.has("tagsCsv")) tags_csv = join_csv_compact(split_csv_compact(body["tagsCsv"].s()));
        std::string credential_source = "vaulted";
        if (body.has("credentialSource")) {
          credential_source = to_lower(body["credentialSource"].s());
        }
        std::string http_username;
        if (body.has("httpUsername")) http_username = body["httpUsername"].s();
        std::string http_password;
        if (body.has("httpPassword")) http_password = body["httpPassword"].s();
        std::string ssh_username;
        if (body.has("sshUsername")) ssh_username = body["sshUsername"].s();
        std::string ssh_password;
        if (body.has("sshPassword")) ssh_password = body["sshPassword"].s();
        bool require_access_justification = false;
        if (body.has("requireAccessJustification")) {
          require_access_justification = body["requireAccessJustification"].b();
        }
        bool require_dual_approval = false;
        if (body.has("requireDualApproval")) {
          require_dual_approval = body["requireDualApproval"].b();
        }
        bool enable_command_guard = false;
        if (body.has("enableCommandGuard")) {
          enable_command_guard = body["enableCommandGuard"].b();
        }
        bool adaptive_access_policy = false;
        if (body.has("adaptiveAccessPolicy")) {
          adaptive_access_policy = body["adaptiveAccessPolicy"].b();
        }
        std::string risk_level = "low";
        if (body.has("riskLevel")) risk_level = to_lower(body["riskLevel"].s());
        if (!is_allowed_role(risk_level, {"low", "medium", "high", "critical"})) {
          return crow::response(400, "Invalid riskLevel");
        }
        if (!is_valid_credential_source(credential_source)) {
          return crow::response(400, "Invalid credentialSource");
        }

        if (name.empty() || target.empty() || protocol.empty())
          return crow::response(400, "Missing name, target, or protocol");
        if (port <= 0 || port > 65535)
          return crow::response(400, "Invalid port");
        if (tunnel_ticket_rate_limit_max_attempts < 0)
          return crow::response(400, "Invalid tunnelTicketRateLimitMaxAttempts");

        // Validate protocol whitelist
        if (!is_allowed_role(protocol, {"ssh", "rdp", "vnc", "http", "https", "agent"}))
          return crow::response(400, "Invalid protocol. Allowed: ssh, rdp, vnc, http, https, agent");

        // Input length limits
        if (name.size() > 255 || target.size() > 255 || description.size() > 1024 ||
            tags_csv.size() > 512)
          return crow::response(400, "Field too long");

        // SSRF protection: allow loopback only for SSH resources.
        if (!ctx.is_safe_target(target, protocol == "ssh"))
          return crow::response(400, "Target address is not allowed for this protocol");

        // Validate imageUrl scheme if provided
        if (!image_url.empty() && image_url.rfind("http", 0) != 0 && image_url.rfind("/", 0) != 0)
          return crow::response(400, "Invalid imageUrl: must be HTTP(S) or relative path");

        Resource resource;
        resource.id = ctx.next_resource_id.fetch_add(1);
        resource.name = name;
        resource.target = target;
        resource.protocol = protocol;
        resource.port = port;
        resource.tunnelTicketRateLimitMaxAttempts =
            tunnel_ticket_rate_limit_max_attempts;
        resource.description = description;
        resource.imageUrl = image_url;
        resource.imageData = image_data;
        resource.tagsCsv = tags_csv;
        resource.credentialSource = credential_source;
        resource.httpUsername = http_username;
        resource.httpPassword = http_password;
        resource.sshUsername = ssh_username;
        resource.sshPassword = ssh_password;
        resource.requireAccessJustification = require_access_justification;
        resource.requireDualApproval = require_dual_approval;
        resource.enableCommandGuard = enable_command_guard;
        resource.adaptiveAccessPolicy = adaptive_access_policy;
        resource.riskLevel = risk_level;
        resource.createdAt = now_utc();
        resource.updatedAt = resource.createdAt;

        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          ctx.resources.emplace(resource.id, resource);
        }
        if (!ctx.insert_resource(resource))
          return crow::response(500, "Failed to persist resource");

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "resource.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_resource_payload_json(resource);
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload = resource_to_json(resource);
        return scim_json_response(payload);
      });

  // PUT /api/resources/<int>
  CROW_ROUTE(app, "/api/resources/<int>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.manage"))
              return crow::response(403, "Forbidden");
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            std::string name = body["name"].s();
            std::string target = body["target"].s();
            std::string protocol = body["protocol"].s();
            int port = 22;
            if (body.has("port")) port = body["port"].i();
            int tunnel_ticket_rate_limit_max_attempts = 0;
            if (body.has("tunnelTicketRateLimitMaxAttempts")) {
              tunnel_ticket_rate_limit_max_attempts =
                  body["tunnelTicketRateLimitMaxAttempts"].i();
            }
            std::string description;
            if (body.has("description")) description = body["description"].s();
            std::string image_url;
            if (body.has("imageUrl")) image_url = body["imageUrl"].s();
            std::string image_data;
            if (body.has("imageData")) image_data = body["imageData"].s();
            std::string tags_csv;
            if (body.has("tagsCsv")) {
              tags_csv = join_csv_compact(split_csv_compact(body["tagsCsv"].s()));
            }
            std::string credential_source = "vaulted";
            if (body.has("credentialSource")) {
              credential_source = to_lower(body["credentialSource"].s());
            }
            std::string http_username;
            if (body.has("httpUsername")) http_username = body["httpUsername"].s();
            std::string http_password;
            if (body.has("httpPassword")) http_password = body["httpPassword"].s();
            std::string ssh_username;
            if (body.has("sshUsername")) ssh_username = body["sshUsername"].s();
            std::string ssh_password;
            if (body.has("sshPassword")) ssh_password = body["sshPassword"].s();
            bool require_access_justification = false;
            if (body.has("requireAccessJustification")) {
              require_access_justification = body["requireAccessJustification"].b();
            }
            bool require_dual_approval = false;
            if (body.has("requireDualApproval")) {
              require_dual_approval = body["requireDualApproval"].b();
            }
            bool enable_command_guard = false;
            if (body.has("enableCommandGuard")) {
              enable_command_guard = body["enableCommandGuard"].b();
            }
            bool adaptive_access_policy = false;
            if (body.has("adaptiveAccessPolicy")) {
              adaptive_access_policy = body["adaptiveAccessPolicy"].b();
            }
            std::string risk_level = "low";
            if (body.has("riskLevel")) risk_level = to_lower(body["riskLevel"].s());
            if (!is_allowed_role(risk_level, {"low", "medium", "high", "critical"})) {
              return crow::response(400, "Invalid riskLevel");
            }
            if (!is_valid_credential_source(credential_source)) {
              return crow::response(400, "Invalid credentialSource");
            }

            if (name.empty() || target.empty() || protocol.empty())
              return crow::response(400, "Missing name, target, or protocol");
            if (port <= 0 || port > 65535)
              return crow::response(400, "Invalid port");
            if (tunnel_ticket_rate_limit_max_attempts < 0)
              return crow::response(400, "Invalid tunnelTicketRateLimitMaxAttempts");

            // Validate protocol whitelist
            if (!is_allowed_role(protocol, {"ssh", "rdp", "vnc", "http", "https", "agent"}))
              return crow::response(400, "Invalid protocol");

            // Input length limits
            if (name.size() > 255 || target.size() > 255 || description.size() > 1024 ||
                tags_csv.size() > 512)
              return crow::response(400, "Field too long");

            // SSRF protection: allow loopback only for SSH resources.
            if (!ctx.is_safe_target(target, protocol == "ssh"))
              return crow::response(400, "Target address is not allowed for this protocol");

            Resource resource;
            {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(resource_id);
              if (it == ctx.resources.end())
                return crow::response(404, "Resource not found");
              resource = it->second;
              resource.name = name;
              resource.target = target;
              resource.protocol = protocol;
              resource.port = port;
              resource.tunnelTicketRateLimitMaxAttempts =
                  tunnel_ticket_rate_limit_max_attempts;
              resource.description = description;
              resource.imageUrl = image_url;
              resource.imageData = image_data;
              resource.tagsCsv = tags_csv;
              resource.credentialSource = credential_source;
              resource.httpUsername = http_username;
              resource.httpPassword = http_password;
              resource.sshUsername = ssh_username;
              // Only update sshPassword if provided (non-empty)
              if (!ssh_password.empty()) resource.sshPassword = ssh_password;
              resource.requireAccessJustification = require_access_justification;
              resource.requireDualApproval = require_dual_approval;
              resource.enableCommandGuard = enable_command_guard;
              resource.adaptiveAccessPolicy = adaptive_access_policy;
              resource.riskLevel = risk_level;
              resource.updatedAt = now_utc();
              it->second = resource;
            }
            if (!ctx.update_resource_db(resource))
              return crow::response(500, "Failed to persist resource");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "resource.update";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_resource_payload_json(resource);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload = resource_to_json(resource);
            return crow::response{payload};
          });

  // DELETE /api/resources/<int>
  CROW_ROUTE(app, "/api/resources/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.manage"))
              return crow::response(403, "Forbidden");

            Resource resource;
            {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(resource_id);
              if (it == ctx.resources.end())
                return crow::response(404, "Resource not found");
              resource = it->second;
              ctx.resources.erase(it);
            }
            if (!ctx.delete_resource_db(resource_id))
              return crow::response(500, "Failed to delete resource");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "resource.delete";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_resource_payload_json(resource);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "deleted";
            payload["id"] = resource_id;
            return crow::response{payload};
          });

  // GET /api/access-policies
}

// ══════════════════════════════════════════════════════════════════════
//  Access Requests
// ══════════════════════════════════════════════════════════════════════

// register_access_request_routes moved to pro/access_governance.cc (premium / EE only).

// ══════════════════════════════════════════════════════════════════════
//  Sessions
// ══════════════════════════════════════════════════════════════════════

void register_session_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/sessions
  CROW_ROUTE(app, "/api/sessions")([&ctx](const crow::request &request) {
    auto auth = ctx.find_auth(request);
    if (!auth) return crow::response(401, "Unauthorized");
    if (!has_permission(ctx, *auth, "sessions.read"))
      return crow::response(403, "Forbidden");

    const char *status_param = request.url_params.get("status");
    const char *user_param = request.url_params.get("user");
    const char *target_param = request.url_params.get("target");
    const char *protocol_param = request.url_params.get("protocol");
    const char *sort_param = request.url_params.get("sort");
    auto limit = parse_int_param(request.url_params.get("limit"));
    auto offset = parse_int_param(request.url_params.get("offset"));

    std::string status_filter = status_param ? to_lower(status_param) : "";
    std::string user_filter = user_param ? to_lower(user_param) : "";
    std::string target_filter = target_param ? to_lower(target_param) : "";
    std::string protocol_filter = protocol_param ? to_lower(protocol_param) : "";
    std::string sort_order = sort_param ? to_lower(sort_param) : "desc";

    std::vector<Session> snapshot;
    {
      std::lock_guard<std::mutex> lock(ctx.session_mutex);
      snapshot.reserve(ctx.sessions.size());
      for (const auto &entry : ctx.sessions)
        snapshot.push_back(entry.second);
    }

    std::vector<Session> filtered;
    for (const auto &session : snapshot) {
      if (!status_filter.empty() && to_lower(session.status) != status_filter) continue;
      if (!user_filter.empty() && to_lower(session.user) != user_filter) continue;
      if (!target_filter.empty() && to_lower(session.target) != target_filter) continue;
      if (!protocol_filter.empty() && to_lower(session.protocol) != protocol_filter) continue;
      filtered.push_back(session);
    }

    std::sort(filtered.begin(), filtered.end(),
              [&](const Session &a, const Session &b) {
                if (sort_order == "asc") return a.id < b.id;
                return a.id > b.id;
              });

    int start_index = offset.value_or(0);
    if (start_index < 0) start_index = 0;
    int end_index = static_cast<int>(filtered.size());
    if (limit && *limit > 0) {
      // Compute the upper bound in a wider type: start_index and *limit are
      // both client-controlled and can each reach INT_MAX, so start_index +
      // *limit would overflow a signed int (undefined behaviour).
      long long bound = static_cast<long long>(start_index) + *limit;
      end_index = static_cast<int>(std::min<long long>(end_index, bound));
    }
    if (start_index > end_index) start_index = end_index;

    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["items"] = crow::json::wvalue::list();
    payload["total"] = static_cast<int>(snapshot.size());
    payload["count"] = end_index - start_index;
    int index = 0;
    for (int i = start_index; i < end_index; ++i)
      payload["items"][index++] = session_to_json(filtered[i]);
    return crow::response{payload};
  });

  // GET /api/access-grants
  CROW_ROUTE(app, "/api/sessions").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "sessions.create"))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        std::string target = body["target"].s();
        std::string user = body["user"].s();
        std::string protocol = body["protocol"].s();
        std::string justification = body.has("justification")
                                        ? std::string(body["justification"].s())
                                        : "";
        std::string ticket_id = body.has("ticketId")
                                    ? std::string(body["ticketId"].s())
                                    : "";
        std::string purpose = body.has("purpose")
                ? std::string(body["purpose"].s())
                : "";
        std::string purpose_evidence = body.has("purposeEvidence")
                   ? std::string(body["purposeEvidence"].s())
                   : "";
        std::string mission_ref = body.has("missionRef")
                                      ? std::string(body["missionRef"].s())
                                      : "";
        int resource_id = 0;
        if (body.has("resourceId")) resource_id = body["resourceId"].i();
        int access_request_id = 0;
        if (body.has("accessRequestId")) access_request_id = body["accessRequestId"].i();
        int port = 22;
        if (body.has("port")) port = body["port"].i();
        if (target.empty() || user.empty() || protocol.empty())
          return crow::response(400, "Missing target, user, or protocol");
        if (port <= 0 || port > 65535)
          return crow::response(400, "Invalid port");
        if (justification.size() > 280)
          return crow::response(400, "justification is too long (max 280 chars)");
        if (ticket_id.size() > 80)
          return crow::response(400, "ticketId is too long (max 80 chars)");
        if (purpose.size() > 120)
          return crow::response(400, "purpose is too long (max 120 chars)");
        if (purpose_evidence.size() > 280)
          return crow::response(400, "purposeEvidence is too long (max 280 chars)");

        Resource resource;
        bool has_resource = false;
        AccessDecision decision;
        UserAccount account;
        std::string risk_level = "low";
        if (resource_id > 0) {
          {
            std::lock_guard<std::mutex> lock(ctx.resource_mutex);
            auto it = ctx.resources.find(resource_id);
            if (it == ctx.resources.end()) {
              return crow::response(404, "Resource not found");
            }
            resource = it->second;
            has_resource = true;
          }

          // Non-admin users can only open sessions on assigned resources.
          if (!has_permission(ctx, *auth, "resources.manage")) {
            auto allowed = ctx.get_resource_permissions(auth->userId);
            if (std::find(allowed.begin(), allowed.end(), resource_id) ==
                allowed.end()) {
              return crow::response(403, "Forbidden");
            }
          }

          if (resource.target != target || resource.protocol != protocol ||
              resource.port != port) {
            return crow::response(
                400,
                "resourceId does not match target/protocol/port payload");
          }
          const auto maybe_account = find_user_account_snapshot(ctx, auth->userId);
          if (maybe_account) account = *maybe_account;
          decision = build_access_decision(
              ctx, *auth, account, resource, query_access_policies(ctx),
              query_user_access_profiles(ctx, auth->userId));
          risk_level = to_lower(resource.riskLevel);
        } else {
          account = find_user_account_snapshot(ctx, auth->userId).value_or(UserAccount{});
          decision.maxDurationSeconds = 3600;
          decision.mfaRequirement = "any";
        }
        if (mission_ref.empty() && !purpose.empty()) {
          mission_ref = purpose;
        }

        auto emit_policy_decision = [&](const std::string &type,
                                        const std::string &reason) {
          AuditEvent decision_event;
          decision_event.id = ctx.next_audit_id.fetch_add(1);
          decision_event.type = type;
          decision_event.actor = auth->user;
          decision_event.role = auth->role;
          decision_event.createdAt = now_utc();
          std::ostringstream oss;
          oss << "{\"resourceId\":" << resource_id
              << ",\"reason\":\"" << json_escape(reason) << "\"";
          if (!decision.matchedPolicyIds.empty()) {
            oss << ",\"policyIds\":[";
            for (size_t i = 0; i < decision.matchedPolicyIds.size(); ++i) {
              if (i) oss << ',';
              oss << decision.matchedPolicyIds[i];
            }
            oss << "]";
          }
          oss << '}';
          decision_event.payloadJson = oss.str();
          decision_event.payloadIsJson = true;
          ctx.append_audit(decision_event);
        };

        if (decision.requireJustification && justification.empty()) {
          emit_policy_decision("policy.decision.deny", "missing_justification");
          return crow::response(
              400,
              "This resource requires an access justification before connect");
        }

        if (decision.approvalRequired &&
            !has_permission(ctx, *auth, "access_requests.review")) {
          if (access_request_id <= 0) {
            emit_policy_decision("policy.decision.deny", "approval_required");
            return crow::response(
                400,
                "This resource requires dual approval: provide an approved accessRequestId");
          }
          AccessRequest req;
          {
            std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
            auto it = ctx.access_requests.find(access_request_id);
            if (it == ctx.access_requests.end()) {
              return crow::response(404, "Access request not found");
            }
            req = it->second;
          }

          if (req.status == "approved") {
            const int64_t now_epoch = now_epoch_seconds();
            const auto approved_at =
                parse_utc_epoch_seconds(req.reviewedAt);
            if (approved_at && (now_epoch - *approved_at) >
                                   kApprovedAccessTtlSeconds) {
              req.status = "expired";
              {
                std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
                auto it = ctx.access_requests.find(access_request_id);
                if (it != ctx.access_requests.end()) {
                  it->second = req;
                }
              }
              ctx.update_access_request(req);

              AuditEvent expire_event;
              expire_event.id = ctx.next_audit_id.fetch_add(1);
              expire_event.type = "access_request.expire";
              expire_event.actor = "system";
              expire_event.role = "system";
              expire_event.createdAt = now_utc();
              expire_event.payloadJson =
                  "{\"id\":" + std::to_string(req.id) +
                  ",\"resourceId\":" + std::to_string(req.resourceId) +
                  "}";
              expire_event.payloadIsJson = true;
              ctx.append_audit(expire_event);
            }
          }

          if (req.status != "approved") {
            emit_policy_decision("policy.decision.deny", "approval_not_approved");
            return crow::response(403, "Access request is not approved");
          }
          if (req.requester != auth->user || req.resourceId != resource_id) {
            emit_policy_decision("policy.decision.deny", "approval_scope_mismatch");
            return crow::response(403, "Access request does not match requester/resource");
          }
        }

        if (decision.ticketRequired && ticket_id.empty()) {
          emit_policy_decision("policy.decision.deny", "ticket_required");
          return crow::response(
              400,
              "This access path requires a ticketId under JIT policy");
        }
        if (decision.purposeRequired && purpose.empty()) {
          emit_policy_decision("policy.decision.deny", "purpose_required");
          return crow::response(
              400,
              "High-risk resources require a purpose (purpose-bound session)");
        }
        if (!user_meets_mfa_requirement(account, decision.mfaRequirement)) {
          emit_policy_decision("policy.decision.deny", "mfa_requirement_unmet");
          return crow::response(403, "Additional MFA posture is required for this access");
        }
        if (decision.routingConstraint == "relay") {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          if (!ctx.resource_relay_bindings.count(resource_id) ||
              ctx.resource_relay_bindings[resource_id].empty()) {
            emit_policy_decision("policy.decision.deny", "relay_required");
            return crow::response(403, "This access policy requires a relay route");
          }
        }

        bool containment_enabled = false;
        std::string containment_reason;
        {
          std::lock_guard<std::mutex> lock(ctx.containment_mutex);
          containment_enabled = ctx.containment_mode_enabled;
          containment_reason = ctx.containment_reason;
        }
        if (containment_enabled && justification.empty()) {
          AuditEvent blocked_event;
          blocked_event.id = ctx.next_audit_id.fetch_add(1);
          blocked_event.type = "session.create.blocked.containment";
          blocked_event.actor = auth->user;
          blocked_event.role = auth->role;
          blocked_event.createdAt = now_utc();
          blocked_event.payloadJson =
              "{\"resourceId\":" + std::to_string(resource_id) +
              ",\"target\":\"" + json_escape(target) + "\"" +
              ",\"reason\":\"missing_justification\"" +
              ",\"containmentReason\":\"" +
              json_escape(containment_reason) + "\"}";
          blocked_event.payloadIsJson = true;
          ctx.append_audit(blocked_event);
          emit_policy_decision("policy.decision.deny", "containment_justification_required");
          return crow::response(
              400,
              "Containment mode is enabled: provide a justification to open this session");
        }

        emit_policy_decision("policy.decision.allow", "granted");

        AccessGrant grant;
        if (has_resource) {
          grant.id = next_table_numeric_id(ctx, "access_grants");
          grant.policyId = decision.selectedPolicyId;
          grant.profileId = decision.selectedProfileId;
          grant.resourceId = resource.id;
          grant.approvalRef = access_request_id;
          grant.subject = auth->user;
          grant.resourceScope = resource.name.empty()
                                    ? std::to_string(resource.id)
                                    : resource.name;
          grant.grantedAt = now_utc();
          const auto grant_expires_at = checked_epoch_seconds_after(
              now_epoch_seconds(),
              std::max<int64_t>(300, decision.maxDurationSeconds));
          if (!grant_expires_at) {
            return crow::response(500, "Invalid access grant TTL");
          }
          grant.expiresAt = utc_from_epoch_seconds(*grant_expires_at);
          grant.missionRef = mission_ref;
          grant.status = "issued";
          grant.credentialSource = resource.credentialSource;
          grant.routingConstraint = decision.routingConstraint;
          grant.ticketId = ticket_id;
          grant.purpose = purpose;
          grant.justification = justification;
          grant.mfaRequirement = decision.mfaRequirement;
          if (!insert_access_grant_db(ctx, grant)) {
            return crow::response(500, "Failed to persist access grant");
          }

          AuditEvent grant_event;
          grant_event.id = ctx.next_audit_id.fetch_add(1);
          grant_event.type = "access.grant.issued";
          grant_event.actor = auth->user;
          grant_event.role = auth->role;
          grant_event.createdAt = now_utc();
          grant_event.payloadJson = access_grant_to_json(grant).dump();
          grant_event.payloadIsJson = true;
          ctx.append_audit(grant_event);
        }

        Session session;
        session.id = ctx.next_session_id.fetch_add(1);
        session.resourceId = resource_id;
        session.accessGrantId = grant.id;
        session.target = target;
        session.user = user;
        session.protocol = protocol;
        session.port = port;
        session.status = "active";
        session.missionRef = mission_ref;
        session.credentialSource =
            has_resource ? resource.credentialSource : std::string("vaulted");
        session.maxDurationSeconds = decision.maxDurationSeconds;
        session.createdAt = now_utc();

        {
          std::lock_guard<std::mutex> lock(ctx.session_mutex);
          ctx.sessions.emplace(session.id, session);
        }
        if (!ctx.insert_session(session))
          return crow::response(500, "Failed to persist session");
        if (grant.id > 0) {
          update_access_grant_session_binding(ctx, grant.id, session.id);
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "session.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_session_payload_json(session);
        if (!justification.empty() || !ticket_id.empty() || !purpose.empty() ||
            !purpose_evidence.empty()) {
          if (!event.payloadJson.empty() && event.payloadJson.back() == '}') {
            event.payloadJson.pop_back();
          }
          if (!justification.empty()) {
            event.payloadJson += ",\"justification\":\"" +
                                 json_escape(justification) + "\"";
          }
          if (!ticket_id.empty()) {
            event.payloadJson +=
                ",\"ticketId\":\"" + json_escape(ticket_id) + "\"";
          }
          if (!purpose.empty()) {
            event.payloadJson +=
                ",\"purpose\":\"" + json_escape(purpose) + "\"";
          }
          if (!purpose_evidence.empty()) {
            event.payloadJson += ",\"purposeEvidence\":\"" +
                                 json_escape(purpose_evidence) + "\"";
          }
          event.payloadJson += "}";
        }
        if (access_request_id > 0) {
          if (!event.payloadJson.empty() && event.payloadJson.back() == '}') {
            event.payloadJson.pop_back();
          }
          event.payloadJson += ",\"accessRequestId\":" +
                               std::to_string(access_request_id) + "}";
        }
        event.payloadIsJson = true;
        ctx.append_audit(event);
        ctx.append_session_dna_entry(session.id, event.id, event.type,
                                     event.payloadJson, event.createdAt);
        ctx.append_session_event("session.create", session);

        if (!purpose.empty()) {
          AuditEvent purpose_event;
          purpose_event.id = ctx.next_audit_id.fetch_add(1);
          purpose_event.type = "session.purpose.bound";
          purpose_event.actor = auth->user;
          purpose_event.role = auth->role;
          purpose_event.createdAt = now_utc();
          purpose_event.payloadJson =
              "{\"sessionId\":" + std::to_string(session.id) +
              ",\"purpose\":\"" + json_escape(purpose) + "\"}";
          purpose_event.payloadIsJson = true;
          ctx.append_audit(purpose_event);
          ctx.append_session_dna_entry(session.id, purpose_event.id,
                                       purpose_event.type,
                                       purpose_event.payloadJson,
                                       purpose_event.createdAt);
        }

        // Compliance signal: track sessions opened without explicit reason.
        if (justification.empty()) {
          AuditEvent reason_event;
          reason_event.id = ctx.next_audit_id.fetch_add(1);
          reason_event.type = "session.create.unjustified";
          reason_event.actor = auth->user;
          reason_event.role = auth->role;
          reason_event.createdAt = now_utc();
          reason_event.payloadJson = "{\"sessionId\":" +
                                     std::to_string(session.id) + "}";
          reason_event.payloadIsJson = true;
          ctx.append_audit(reason_event);
          ctx.append_session_dna_entry(session.id, reason_event.id,
                                       reason_event.type,
                                       reason_event.payloadJson,
                                       reason_event.createdAt);
        }

        crow::json::wvalue payload = session_to_json(session);
        return crow::response{payload};
      });

  // GET /api/sessions/<int>
  CROW_ROUTE(app, "/api/sessions/<int>")(
      [&ctx](const crow::request &request, int session_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "sessions.read"))
          return crow::response(403, "Forbidden");
        std::lock_guard<std::mutex> lock(ctx.session_mutex);
        auto it = ctx.sessions.find(session_id);
        if (it == ctx.sessions.end())
          return crow::response(404, "Session not found");
        crow::json::wvalue payload = session_to_json(it->second);
        return crow::response{payload};
      });

  // GET /api/sessions/<int>/dna
  CROW_ROUTE(app, "/api/sessions/<int>/terminate")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int session_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "sessions.terminate"))
              return crow::response(403, "Forbidden");
            {
              std::lock_guard<std::mutex> lock(ctx.session_mutex);
              if (ctx.sessions.find(session_id) == ctx.sessions.end())
                return crow::response(404, "Session not found");
            }

            ctx.terminate_session(session_id, auth->user, auth->role,
                                  "session.terminate");
            ctx.close_ssh_for_session(session_id);

            Session updated;
            {
              std::lock_guard<std::mutex> lock(ctx.session_mutex);
              updated = ctx.sessions.at(session_id);
            }
            crow::json::wvalue payload = session_to_json(updated);
            return crow::response{payload};
          });

  // POST /api/sessions/<int>/elevation/start
  CROW_ROUTE(app, "/api/sessions/stream")(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "sessions.read"))
          return crow::response(403, "Forbidden");
        const char *since_param = request.url_params.get("since");
        auto since = parse_int_param(since_param).value_or(0);
        auto header = request.get_header_value("Last-Event-ID");
        if (!header.empty()) {
          auto parsed = parse_int_param(header.c_str());
          if (parsed) since = std::max(since, *parsed);
        }

        std::vector<SessionEvent> snapshot;
        {
          std::lock_guard<std::mutex> lock(ctx.event_mutex);
          snapshot.reserve(ctx.session_events.size());
          for (const auto &event : ctx.session_events) {
            if (event.id > since) snapshot.push_back(event);
          }
        }

        std::ostringstream body;
        body << "retry: 5000\n";
        int sent = 0;
        for (const auto &event : snapshot) {
          body << "id: " << event.id << "\n";
          body << "event: " << event.type << "\n";
          body << "data: " << event.payloadJson << "\n\n";
          if (++sent >= 100) break;
        }

        crow::response response;
        response.code = 200;
        response.set_header("Content-Type", "text/event-stream");
        response.set_header("Cache-Control", "no-cache");
        response.set_header("Connection", "keep-alive");
        response.body = body.str();
        return response;
      });
  // risk-preview kept in core (advisory; uses core access-decision engine); gated per-route.
  CROW_ROUTE(app, "/api/sessions/risk-preview").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!ctx.license_allows_feature("jit.governance"))
          return license_denied_response(ctx, "jit.governance");
        if (!has_permission(ctx, *auth, "sessions.create"))
          return crow::response(403, "Forbidden");

        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        int resource_id = body.has("resourceId") ? body["resourceId"].i() : 0;
        if (resource_id <= 0) return crow::response(400, "Missing resourceId");
        Resource resource;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          auto it = ctx.resources.find(resource_id);
          if (it == ctx.resources.end())
            return crow::response(404, "Resource not found");
          resource = it->second;
        }
        std::string justification =
            body.has("justification") ? std::string(body["justification"].s()) : "";
        std::string ticket_id =
            body.has("ticketId") ? std::string(body["ticketId"].s()) : "";
        std::string purpose =
            body.has("purpose") ? std::string(body["purpose"].s()) : "";
        const auto account = find_user_account_snapshot(ctx, auth->userId)
                                 .value_or(UserAccount{});
        const auto decision = build_access_decision(
            ctx, *auth, account, resource, query_access_policies(ctx),
            query_user_access_profiles(ctx, auth->userId));
        const std::string risk_level = to_lower(resource.riskLevel);
        const bool purpose_required = decision.purposeRequired;
        int score = base_risk_score_for_level(risk_level);
        std::vector<std::string> factors;
        factors.push_back("base:" + risk_level);

        if (decision.requireJustification && justification.empty()) {
          score += 10;
          factors.push_back("missing_justification:+10");
        }
        if (decision.ticketRequired && ticket_id.empty()) {
          score += 10;
          factors.push_back("missing_ticket_required:+10");
        }
        if (purpose_required && purpose.empty()) {
          score += 15;
          factors.push_back("missing_purpose_bound:+15");
        }
        if (!user_meets_mfa_requirement(account, decision.mfaRequirement)) {
          score += 15;
          factors.push_back("mfa_requirement_unmet:+15");
        }
        if (decision.routingConstraint == "relay") {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          if (!ctx.resource_relay_bindings.count(resource.id) ||
              ctx.resource_relay_bindings[resource.id].empty()) {
            score += 12;
            factors.push_back("relay_required_unavailable:+12");
          }
        }
        if (is_off_hours_utc()) {
          score += 10;
          factors.push_back("off_hours_utc:+10");
        }
        for (const auto &factor : decision.factors) {
          factors.push_back(factor);
        }
        if (score < 0) score = 0;
        if (score > 100) score = 100;

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["score"] = score;
        payload["effectiveRiskLevel"] = risk_level_for_score(score);
        payload["resourceRiskLevel"] = risk_level;
        payload["adaptivePolicyEnabled"] = resource.adaptiveAccessPolicy;
        payload["purposeRequired"] = purpose_required;
        payload["ticketRequired"] = decision.ticketRequired;
        payload["justificationRequired"] = decision.requireJustification;
        payload["approvalRequired"] = decision.approvalRequired;
        payload["mfaRequirement"] = decision.mfaRequirement;
        payload["routingConstraint"] = decision.routingConstraint;
        payload["maxDurationSeconds"] = decision.maxDurationSeconds;
        payload["matchedPolicyIds"] = crow::json::wvalue::list();
        for (size_t i = 0; i < decision.matchedPolicyIds.size(); ++i) {
          payload["matchedPolicyIds"][static_cast<int>(i)] =
              decision.matchedPolicyIds[i];
        }
        payload["factors"] = crow::json::wvalue::list();
        for (size_t i = 0; i < factors.size(); ++i) {
          payload["factors"][static_cast<int>(i)] = factors[i];
        }
        return crow::response{payload};
      });

  // POST /api/sessions
}

// ══════════════════════════════════════════════════════════════════════
//  Enterprise Foundations (SSO / SCIM / Integrations)
// ══════════════════════════════════════════════════════════════════════


// ══════════════════════════════════════════════════════════════════════
//  Audit
// ══════════════════════════════════════════════════════════════════════

void register_audit_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/security/alerts
  CROW_ROUTE(app, "/api/audit").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "audit.read"))
          return crow::response(403, "Forbidden");

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "audit.custom";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        auto body = crow::json::load(request.body);
        if (body) {
          event.payloadJson = request.body;
          event.payloadIsJson = true;
        } else {
          event.payloadJson = request.body;
          event.payloadIsJson = false;
        }
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "accepted";
        payload["id"] = event.id;
        return crow::response{payload};
      });

  // GET /api/audit
  CROW_ROUTE(app, "/api/audit")([&ctx](const crow::request &request) {
    auto auth = ctx.find_auth(request);
    if (!auth) return crow::response(401, "Unauthorized");
    if (!has_permission(ctx, *auth, "audit.read"))
      return crow::response(403, "Forbidden");

    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["items"] = crow::json::wvalue::list();
    {
      std::lock_guard<std::mutex> lock(ctx.audit_mutex);
      int index = 0;
      for (auto it = ctx.audit_events.rbegin();
           it != ctx.audit_events.rend() && index < 50; ++it) {
        payload["items"][index]["id"] = it->id;
        payload["items"][index]["type"] = it->type;
        payload["items"][index]["actor"] = it->actor;
        payload["items"][index]["role"] = it->role;
        payload["items"][index]["createdAt"] = it->createdAt;
        payload["items"][index]["payloadRaw"] = it->payloadJson;
        payload["items"][index]["payloadIsJson"] = it->payloadIsJson;
        ++index;
      }
    }
    return crow::response{payload};
  });
}

// ══════════════════════════════════════════════════════════════════════
//  TOTP / 2FA
// ══════════════════════════════════════════════════════════════════════

void register_totp_routes(CrowApp &app, AppContext &ctx) {
  // POST /api/auth/setup-2fa — Generate a TOTP secret for the current user
  CROW_ROUTE(app, "/api/auth/setup-2fa")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            // Check if already enabled
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end() && it->second.totpEnabled)
                return crow::response(400, "2FA is already enabled");
            }

            // Generate a new TOTP secret
            std::string secret = totp::generate_secret();
            std::string uri = totp::build_otpauth_uri(
                "EndoriumFort", auth->user, secret);

            // Store secret but don't enable yet (user must verify first)
            ctx.update_user_totp(auth->userId, false, secret);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["secret"] = secret;
            payload["otpauthUri"] = uri;
            payload["webauthnCompatible"] = true;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              }
            }
            payload["message"] =
                "Import the secret or otpauth URI into your authenticator app, "
                "then call /api/auth/verify-2fa with a code to enable.";
            return crow::response{payload};
          });

  // POST /api/auth/verify-2fa — Verify a TOTP code and enable 2FA
  CROW_ROUTE(app, "/api/auth/verify-2fa")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");
            std::string code;
            if (body.has("code")) code = body["code"].s();
            if (code.empty())
              return crow::response(400, "Missing TOTP code");

            std::string secret;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it == ctx.users.end())
                return crow::response(404, "User not found");
              secret = it->second.totpSecret;
            }
            if (secret.empty())
              return crow::response(400, "Call /api/auth/setup-2fa first");

            if (!totp::verify_code(secret, code))
              return crow::response(401, "Invalid TOTP code");

            // Enable 2FA
            ctx.update_user_totp(auth->userId, true, secret);
            bool password_required = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                password_required = it->second.bootstrapPasswordChangeRequired;
              }
            }
            ctx.update_user_bootstrap_flags(auth->userId, password_required, false);

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.2fa.enable";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = "{\"userId\":" + std::to_string(auth->userId) + "}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "2FA has been enabled successfully";
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              }
            }
            return crow::response{payload};
          });

  // POST /api/auth/disable-2fa — Disable 2FA (requires current TOTP code)
  CROW_ROUTE(app, "/api/auth/disable-2fa")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");
            std::string code;
            if (body.has("code")) code = body["code"].s();
            if (code.empty())
              return crow::response(400, "Missing TOTP code");

            std::string secret;
            bool enabled = false;
            std::string role;
            bool has_webauthn = false;
            UserAccount current_user;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it == ctx.users.end())
                return crow::response(404, "User not found");
              current_user = it->second;
              secret = it->second.totpSecret;
              enabled = it->second.totpEnabled;
              role = it->second.role;
              has_webauthn = user_has_webauthn_enabled(it->second);
            }
            if (!enabled)
              return crow::response(400, "2FA is not enabled");
            if (normalize_user_role(role) == "admin" &&
                !admin_can_disable_totp(current_user))
              return crow::response(
                  403,
                  "Admin accounts need at least one MFA method before TOTP can be disabled");

            if (!totp::verify_code(secret, code))
              return crow::response(401, "Invalid TOTP code");

            ctx.update_user_totp(auth->userId, false, "");
            bool prefer_totp = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              prefer_totp = it != ctx.users.end() &&
                            it->second.preferredMfaMethod == "totp";
            }
            if (prefer_totp) {
              ctx.update_user_mfa_preference(auth->userId,
                                             has_webauthn ? "webauthn" : "any");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.2fa.disable";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = "{\"userId\":" + std::to_string(auth->userId) + "}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "2FA has been disabled";
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              }
            }
            return crow::response{payload};
          });

  // GET /api/auth/2fa-status — Check the current 2FA status
  CROW_ROUTE(app, "/api/auth/2fa-status")(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        bool enabled = false;
        bool webauthn_enabled = false;
        std::string preferred_mfa_method = "any";
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it != ctx.users.end()) {
            enabled = it->second.totpEnabled;
            webauthn_enabled = it->second.webauthnCredentialCount > 0;
            preferred_mfa_method = it->second.preferredMfaMethod;
          }
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it != ctx.users.end()) {
            apply_auth_mfa_payload(payload, it->second);
          } else {
            payload["totpEnabled"] = enabled;
            payload["webauthnEnabled"] = webauthn_enabled;
            payload["preferredMfaMethod"] = normalize_mfa_preference(preferred_mfa_method);
          }
        }
        payload["credentials"] = crow::json::wvalue::list();
        int idx = 0;
        for (const auto &credential : ctx.get_user_webauthn_credentials(auth->userId)) {
          payload["credentials"][idx++] = webauthn::credential_to_json(credential);
        }
        return crow::response{payload};
      });

  // POST /api/auth/mfa-preference
  CROW_ROUTE(app, "/api/auth/mfa-preference")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            const std::string method =
                body.has("method") ? std::string(body["method"].s()) : std::string();
            const std::string normalized_method = normalize_mfa_preference(method);
            if (normalized_method != method && method != "ANY" && method != "TOTP" &&
                method != "WEBAUTHN") {
              return crow::response(400, "Invalid MFA preference");
            }

            bool totp_enabled = false;
            bool webauthn_enabled = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it == ctx.users.end()) return crow::response(404, "User not found");
              totp_enabled = it->second.totpEnabled;
              webauthn_enabled = it->second.webauthnCredentialCount > 0;
            }
            if (normalized_method == "totp" && !totp_enabled) {
              return crow::response(400, "TOTP is not enabled for this account");
            }
            if (normalized_method == "webauthn" && !webauthn_enabled) {
              return crow::response(400, "No passkey is registered for this account");
            }
            if (!ctx.update_user_mfa_preference(auth->userId, normalized_method)) {
              return crow::response(500, "Failed to save MFA preference");
            }

            crow::json::wvalue payload;
            payload["status"] = "ok";
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              } else {
                payload["totpEnabled"] = totp_enabled;
                payload["webauthnEnabled"] = webauthn_enabled;
                payload["preferredMfaMethod"] = normalized_method;
              }
            }
            return crow::response{payload};
          });

  // POST /api/auth/webauthn/register/options
  CROW_ROUTE(app, "/api/auth/webauthn/register/options")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            std::string label =
                body && body.has("label") ? std::string(body["label"].s()) : std::string();

            const std::string rp_id = webauthn::expected_rp_id(
                request, ctx.webauthn_rp_id_override);
            const std::string origin = webauthn::expected_origin(
                request, ctx.webauthn_origin_override);
            if (!webauthn::is_valid_rp_id(rp_id) ||
                !webauthn::is_valid_origin(origin)) {
              return crow::response(
                  400,
                  "WebAuthn requires a valid domain. Configure "
                  "ENDORIUMFORT_WEBAUTHN_RP_ID and ENDORIUMFORT_WEBAUTHN_ORIGIN "
                  "(example: app.example.com / https://app.example.com), or use localhost in dev.");
            }

            auto challenge = ctx.create_webauthn_challenge(
                auth->userId, auth->user, "register", rp_id, origin);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["requestId"] = challenge.requestId;
            payload["publicKey"]["rp"]["name"] = "EndoriumFort";
            payload["publicKey"]["rp"]["id"] = challenge.rpId;
            payload["publicKey"]["user"]["id"] =
                webauthn::base64url_encode(std::to_string(auth->userId));
            payload["publicKey"]["user"]["name"] = auth->user;
            payload["publicKey"]["user"]["displayName"] = auth->user;
            payload["publicKey"]["challenge"] =
                webauthn::base64url_encode(challenge.challenge);
            payload["publicKey"]["timeout"] = ctx.webauthn_challenge_ttl_seconds * 1000;
            payload["publicKey"]["attestation"] = "none";
            payload["publicKey"]["userVerification"] = "preferred";
            payload["publicKey"]["authenticatorSelection"]["userVerification"] =
                "preferred";
            payload["publicKey"]["pubKeyCredParams"] = crow::json::wvalue::list();
            payload["publicKey"]["pubKeyCredParams"][0]["type"] = "public-key";
            payload["publicKey"]["pubKeyCredParams"][0]["alg"] = -7;
            payload["publicKey"]["pubKeyCredParams"][1]["type"] = "public-key";
            payload["publicKey"]["pubKeyCredParams"][1]["alg"] = -257;
            payload["publicKey"]["excludeCredentials"] = crow::json::wvalue::list();
            int index = 0;
            for (const auto &credential :
                 ctx.get_user_webauthn_credentials(auth->userId)) {
              payload["publicKey"]["excludeCredentials"][index]["type"] =
                  "public-key";
              payload["publicKey"]["excludeCredentials"][index]["id"] =
                  credential.credentialId;
              ++index;
            }
            payload["labelHint"] = label;
            return crow::response{payload};
          });

  // POST /api/auth/webauthn/register/verify
  CROW_ROUTE(app, "/api/auth/webauthn/register/verify")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            const std::string request_id = body.has("requestId")
                                               ? std::string(body["requestId"].s())
                                               : std::string();
            const std::string credential_id = body.has("credentialId")
                                                  ? std::string(body["credentialId"].s())
                                                  : std::string();
            const std::string public_key = body.has("publicKey")
                                               ? std::string(body["publicKey"].s())
                                               : std::string();
            const std::string client_data_json = body.has("clientDataJSON")
                                                     ? std::string(body["clientDataJSON"].s())
                                                     : std::string();
            const std::string authenticator_data =
                body.has("authenticatorData")
                    ? std::string(body["authenticatorData"].s())
                    : std::string();
            const std::string label =
                body.has("label") ? std::string(body["label"].s()) : std::string();
            const int algorithm = body.has("algorithm") ? body["algorithm"].i() : 0;
            if (request_id.empty() || credential_id.empty() || public_key.empty() ||
                client_data_json.empty() || authenticator_data.empty()) {
              return crow::response(400, "Missing WebAuthn registration payload");
            }
            if (algorithm != -7 && algorithm != -257)
              return crow::response(400, "Only ES256 and RS256 passkeys are supported currently");

            const auto challenge =
                ctx.consume_webauthn_challenge(request_id, auth->userId, "register");
            const auto client_data = webauthn::parse_client_data(client_data_json);
            const auto parsed_auth_data = challenge
                                              ? webauthn::parse_authenticator_data(
                                                    authenticator_data,
                                                    challenge->rpId)
                                              : std::nullopt;
            if (!challenge || !client_data || !parsed_auth_data ||
                client_data->type != "webauthn.create" ||
                client_data->challenge !=
                    webauthn::base64url_encode(challenge->challenge) ||
                client_data->origin != challenge->origin ||
                (parsed_auth_data->flags & 0x01) == 0) {
              // 400 (not 401): the session is valid — only the passkey attestation
              // failed. A 401 here would trip the frontend's global logout.
              return crow::response(400, "WebAuthn registration validation failed");
            }

            WebAuthnCredential credential;
            credential.id = ctx.next_webauthn_credential_id.fetch_add(1);
            credential.userId = auth->userId;
            credential.credentialId = credential_id;
            credential.publicKeySpki = public_key;
            credential.signCount = static_cast<int>(parsed_auth_data->signCount);
            credential.label = label.empty() ? "Security key" : label;
            credential.transportsCsv =
                body.has("transports")
                    ? webauthn::transports_to_csv(body["transports"])
                    : "";
            credential.createdAt = now_utc();

            if (!ctx.insert_webauthn_credential(credential))
              return crow::response(409, "This passkey is already registered");

            bool password_required = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                password_required = it->second.bootstrapPasswordChangeRequired;
              }
            }
            ctx.update_user_bootstrap_flags(auth->userId, password_required, false);

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.webauthn.register";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_webauthn_audit_payload(credential);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "Passkey registered successfully";
            payload["credential"] = webauthn::credential_to_json(credential);
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              }
            }
            return crow::response{payload};
          });

  // DELETE /api/auth/webauthn/credentials/<int>
  CROW_ROUTE(app, "/api/auth/webauthn/credentials/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int credential_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto credentials = ctx.get_user_webauthn_credentials(auth->userId);
            auto it = std::find_if(credentials.begin(), credentials.end(),
                                   [credential_id](const WebAuthnCredential &item) {
                                     return item.id == credential_id;
                                   });
            if (it == credentials.end())
              return crow::response(404, "Passkey not found");

            bool totp_enabled = false;
            std::string role;
            UserAccount current_user;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto user_it = ctx.users.find(auth->userId);
              if (user_it == ctx.users.end())
                return crow::response(404, "User not found");
              current_user = user_it->second;
              totp_enabled = user_it->second.totpEnabled;
              role = user_it->second.role;
            }
            if (normalize_user_role(role) == "admin" &&
                !admin_can_remove_webauthn_credential(
                    current_user, static_cast<int>(credentials.size()) - 1)) {
              return crow::response(
                  403,
                  "Admin accounts must keep at least one MFA method enabled");
            }
            if (!ctx.delete_webauthn_credential(credential_id))
              return crow::response(500, "Failed to remove passkey");

            const bool has_webauthn = ctx.user_has_webauthn(auth->userId);
            if (!totp_enabled) {
              ctx.update_user_bootstrap_flags(auth->userId, false, !has_webauthn);
            }
            bool prefer_webauthn = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto user_it = ctx.users.find(auth->userId);
              prefer_webauthn = user_it != ctx.users.end() &&
                                user_it->second.preferredMfaMethod == "webauthn" &&
                                !has_webauthn;
            }
            if (prefer_webauthn) {
              ctx.update_user_mfa_preference(auth->userId,
                                             totp_enabled ? "totp" : "any");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.webauthn.delete";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_webauthn_audit_payload(*it);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "Passkey removed";
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto user_it = ctx.users.find(auth->userId);
              if (user_it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, user_it->second);
              }
            }
            payload["credentials"] = crow::json::wvalue::list();
            int idx = 0;
            for (const auto &credential : ctx.get_user_webauthn_credentials(auth->userId)) {
              payload["credentials"][idx++] = webauthn::credential_to_json(credential);
            }
            return crow::response{payload};
          });
}

// ══════════════════════════════════════════════════════════════════════
//  Session Recordings
// ══════════════════════════════════════════════════════════════════════

// register_recording_routes moved to pro/recording.cc (premium / EE only).

// ══════════════════════════════════════════════════════════════════════
//  Stats / Dashboard
// ══════════════════════════════════════════════════════════════════════

void register_stats_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/stats — Dashboard statistics
  CROW_ROUTE(app, "/api/stats")(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "stats.read"))
          return crow::response(403, "Forbidden");

        int total_sessions = 0, active_sessions = 0, terminated_sessions = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.session_mutex);
          total_sessions = static_cast<int>(ctx.sessions.size());
          for (const auto &entry : ctx.sessions) {
            if (entry.second.status == "active") ++active_sessions;
            else ++terminated_sessions;
          }
        }

        int total_resources = 0, ssh_resources = 0, http_resources = 0,
            rdp_resources = 0, vnc_resources = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          total_resources = static_cast<int>(ctx.resources.size());
          for (const auto &entry : ctx.resources) {
            if (entry.second.protocol == "ssh") ++ssh_resources;
            else if (entry.second.protocol == "http" || entry.second.protocol == "https") ++http_resources;
            else if (entry.second.protocol == "rdp") ++rdp_resources;
            else if (entry.second.protocol == "vnc") ++vnc_resources;
          }
        }

        int total_users = 0, admin_users = 0, admins_without_mfa = 0,
            admins_pending_bootstrap = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          total_users = static_cast<int>(ctx.users.size());
          for (const auto &entry : ctx.users) {
            if (!is_user_role(entry.second.role, "admin")) continue;
            ++admin_users;
            if (!user_has_any_mfa_enabled(entry.second)) ++admins_without_mfa;
            if (entry.second.bootstrapPasswordChangeRequired ||
                entry.second.bootstrapMfaRequired) {
              ++admins_pending_bootstrap;
            }
          }
        }

        int total_recordings = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.recording_mutex);
          total_recordings = static_cast<int>(ctx.recordings.size());
        }

        int total_audit = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.audit_mutex);
          total_audit = static_cast<int>(ctx.audit_events.size());
        }

        int active_tokens = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.auth_mutex);
          active_tokens = static_cast<int>(ctx.auth_sessions.size());
        }

        const std::string effective_rp_id =
            webauthn::expected_rp_id(request, ctx.webauthn_rp_id_override);
        const std::string effective_origin =
            webauthn::expected_origin(request, ctx.webauthn_origin_override);
        const bool rp_id_valid = webauthn::is_valid_rp_id(effective_rp_id);
        const bool origin_valid = webauthn::is_valid_origin(effective_origin);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["sessions"]["total"] = total_sessions;
        payload["sessions"]["active"] = active_sessions;
        payload["sessions"]["terminated"] = terminated_sessions;
        payload["resources"]["total"] = total_resources;
        payload["resources"]["ssh"] = ssh_resources;
        payload["resources"]["http"] = http_resources;
        payload["resources"]["rdp"] = rdp_resources;
        payload["resources"]["vnc"] = vnc_resources;
        payload["users"]["total"] = total_users;
        payload["users"]["admins"] = admin_users;
        payload["users"]["adminsWithoutMfa"] = admins_without_mfa;
        payload["users"]["adminsPendingBootstrap"] = admins_pending_bootstrap;
        payload["recordings"]["total"] = total_recordings;
        payload["audit"]["total"] = total_audit;
        payload["auth"]["activeTokens"] = active_tokens;
        payload["auth"]["runtime"]["port"] = ctx.listen_port;
        payload["auth"]["runtime"]["tokenTtlSeconds"] = ctx.token_ttl_seconds;
        payload["auth"]["runtime"]["webauthnChallengeTtlSeconds"] =
            ctx.webauthn_challenge_ttl_seconds;
        payload["auth"]["runtime"]["webauthnRpIdOverrideConfigured"] =
            !ctx.webauthn_rp_id_override.empty();
        payload["auth"]["runtime"]["webauthnOriginOverrideConfigured"] =
            !ctx.webauthn_origin_override.empty();
        payload["auth"]["webauthn"]["rpId"] = effective_rp_id;
        payload["auth"]["webauthn"]["origin"] = effective_origin;
        payload["auth"]["webauthn"]["rpIdValid"] = rp_id_valid;
        payload["auth"]["webauthn"]["originValid"] = origin_valid;
        payload["auth"]["webauthn"]["configured"] = rp_id_valid && origin_valid;
        payload["relay"]["runtime"]["enrollmentEnabled"] =
            !ctx.relay_enroll_secret.empty();
        payload["relay"]["runtime"]["certificateRequired"] =
            ctx.relay_certificate_required;
        payload["relay"]["runtime"]["certificateTtlSeconds"] =
            ctx.relay_certificate_ttl_seconds;
        payload["relay"]["runtime"]["enrollmentTokenTtlSeconds"] =
            ctx.relay_enrollment_token_ttl_seconds;
        payload["relay"]["runtime"]["tokenTtlSeconds"] =
            ctx.relay_token_ttl_seconds;
        payload["relay"]["runtime"]["heartbeatStaleSeconds"] =
            ctx.relay_heartbeat_stale_seconds;
        return crow::response{payload};
      });

  // GET /api/resources/<int>/credentials — Fetch stored SSH creds for auto-inject
  CROW_ROUTE(app, "/api/resources/<int>/credentials")(
      [&ctx](const crow::request &request, int resource_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_any_permission(ctx, *auth, {"credentials.ephemeral.consume",
                                             "credentials.ephemeral.issue"}))
          return crow::response(403, "Forbidden");

        // Permission check
        std::vector<int> allowed_ids;
        if (has_permission(ctx, *auth, "resources.manage")) {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          for (const auto &r : ctx.resources) allowed_ids.push_back(r.first);
        } else {
          allowed_ids = ctx.get_resource_permissions(auth->userId);
        }
        bool has_perm = false;
        for (int id : allowed_ids)
          if (id == resource_id) { has_perm = true; break; }
        if (!has_perm) return crow::response(403, "No access to this resource");

        Resource target_resource;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          auto it = ctx.resources.find(resource_id);
          if (it == ctx.resources.end())
            return crow::response(404, "Resource not found");
          target_resource = it->second;
        }

        // Audit the credential access
        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "credential.access";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = "{\"resourceId\":" + std::to_string(resource_id) +
                            ",\"resourceName\":\"" + json_escape(target_resource.name) + "\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["resourceId"] = resource_id;
        payload["sshUsername"] = target_resource.sshUsername;
        payload["sshPassword"] = target_resource.sshPassword;
        payload["hasCredentials"] = !target_resource.sshPassword.empty();
        return crow::response{payload};
      });

  // POST /api/resources/<int>/ephemeral-credentials — issue one-time lease
  CROW_ROUTE(app, "/api/resources/<int>/ephemeral-credentials")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "credentials.ephemeral.issue")) {
              return crow::response(403, "Forbidden");
            }

            if (!has_permission(ctx, *auth, "resources.manage")) {
              auto allowed_ids = ctx.get_resource_permissions(auth->userId);
              if (std::find(allowed_ids.begin(), allowed_ids.end(),
                            resource_id) == allowed_ids.end()) {
                return crow::response(403, "No access to this resource");
              }
            }

            Resource target_resource;
            {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(resource_id);
              if (it == ctx.resources.end()) {
                return crow::response(404, "Resource not found");
              }
              target_resource = it->second;
            }

            if (to_lower(target_resource.protocol) != "ssh") {
              return crow::response(
                  400,
                  "Ephemeral credential lease is only available for SSH resources");
            }
            if (target_resource.sshUsername.empty() ||
                target_resource.sshPassword.empty()) {
              return crow::response(
                  400,
                  "Resource has no vaulted SSH credentials to lease");
            }

            const int64_t now_epoch = now_epoch_seconds();
            EphemeralCredentialLease lease;
            lease.id = ctx.next_ephemeral_credential_id.fetch_add(1);
            lease.resourceId = resource_id;
            lease.requester = auth->user;
            lease.username = target_resource.sshUsername;
            lease.status = "issued";
            lease.issuedAt = now_utc();
            const auto lease_expires_at =
                checked_epoch_seconds_after(now_epoch, kEphemeralLeaseTtlSeconds);
            if (!lease_expires_at) {
              return crow::response(500, "Invalid ephemeral lease TTL");
            }
            lease.expiresAt = utc_from_epoch_seconds(*lease_expires_at);

            {
              std::lock_guard<std::mutex> lock(ctx.ephemeral_credential_mutex);
              ctx.ephemeral_credentials[lease.id] = lease;
            }
            if (!ctx.insert_ephemeral_credential(lease)) {
              return crow::response(500, "Failed to persist lease");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "credential.ephemeral.issue";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson =
                "{\"leaseId\":" + std::to_string(lease.id) +
                ",\"resourceId\":" + std::to_string(resource_id) +
                ",\"expiresAt\":\"" + json_escape(lease.expiresAt) +
                "\"}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["leaseId"] = lease.id;
            payload["resourceId"] = resource_id;
            payload["username"] = lease.username;
            payload["expiresAt"] = lease.expiresAt;
            payload["ttlSeconds"] = static_cast<int>(kEphemeralLeaseTtlSeconds);
            return crow::response{payload};
          });

  // POST /api/ephemeral-credentials/<int>/consume — one-time secret reveal
  CROW_ROUTE(app, "/api/ephemeral-credentials/<int>/consume")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int lease_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "credentials.ephemeral.consume")) {
              return crow::response(403, "Forbidden");
            }

            EphemeralCredentialLease lease;
            {
              std::lock_guard<std::mutex> lock(ctx.ephemeral_credential_mutex);
              auto it = ctx.ephemeral_credentials.find(lease_id);
              if (it == ctx.ephemeral_credentials.end()) {
                return crow::response(404, "Lease not found");
              }
              lease = it->second;
            }

            if (!has_permission(ctx, *auth, "resources.manage") &&
                lease.requester != auth->user) {
              return crow::response(403, "Lease requester mismatch");
            }
            if (lease.status != "issued") {
              return crow::response(403, "Lease is not consumable");
            }

            const int64_t now_epoch = now_epoch_seconds();
            const auto expiry_epoch = parse_utc_epoch_seconds(lease.expiresAt);
            if (expiry_epoch && now_epoch > *expiry_epoch) {
              lease.status = "expired";
              {
                std::lock_guard<std::mutex> lock(ctx.ephemeral_credential_mutex);
                auto it = ctx.ephemeral_credentials.find(lease_id);
                if (it != ctx.ephemeral_credentials.end()) it->second = lease;
              }
              ctx.update_ephemeral_credential(lease);
              return crow::response(403, "Lease has expired");
            }

            Resource target_resource;
            {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(lease.resourceId);
              if (it == ctx.resources.end()) {
                return crow::response(404, "Resource not found");
              }
              target_resource = it->second;
            }

            if (target_resource.sshUsername.empty() ||
                target_resource.sshPassword.empty()) {
              return crow::response(
                  400,
                  "Resource has no vaulted SSH credentials to consume");
            }

            lease.status = "consumed";
            lease.usedAt = now_utc();
            {
              std::lock_guard<std::mutex> lock(ctx.ephemeral_credential_mutex);
              auto it = ctx.ephemeral_credentials.find(lease_id);
              if (it != ctx.ephemeral_credentials.end()) it->second = lease;
            }
            if (!ctx.update_ephemeral_credential(lease)) {
              return crow::response(500, "Failed to persist lease state");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "credential.ephemeral.consume";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson =
                "{\"leaseId\":" + std::to_string(lease.id) +
                ",\"resourceId\":" + std::to_string(lease.resourceId) +
                "}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["leaseId"] = lease.id;
            payload["resourceId"] = lease.resourceId;
            payload["sshUsername"] = target_resource.sshUsername;
            payload["sshPassword"] = target_resource.sshPassword;
            payload["expiresAt"] = lease.expiresAt;
            return crow::response{payload};
          });
}
