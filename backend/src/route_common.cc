// ─── EndoriumFort — shared route helpers (implementation) ────────────────────
#include "route_common.h"

#include "app_context.h"
#include "routes.h"  // g_license_ctx
#include "settings.h"

#include "utils.h"  // to_lower, trim_copy

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <string>

bool has_permission(AppContext &ctx, const AuthSession &auth,
                    const std::string &permission) {
  return ctx.has_permission(auth.userId, auth.role, permission);
}

// The three helpers below are the single seam through which every integration
// reads its configuration, so consulting the settings store here is what makes
// the admin console able to configure them. A stored value wins over the
// environment; clearing it falls back to the environment, then to the default.
bool env_flag_enabled(const char *name, bool fallback) {
  if (!name || !*name) return fallback;
  std::string stored_text;
  const char *raw = nullptr;
  if (const auto stored = settings::stored_value(name)) {
    stored_text = *stored;
    raw = stored_text.c_str();
  } else {
    raw = std::getenv(name);
  }
  if (!raw) return fallback;
  const std::string normalized = to_lower(trim_copy(raw));
  if (normalized == "1" || normalized == "true" || normalized == "yes" ||
      normalized == "on") {
    return true;
  }
  if (normalized == "0" || normalized == "false" || normalized == "no" ||
      normalized == "off") {
    return false;
  }
  return fallback;
}

std::string env_string_value(const char *name, const std::string &fallback) {
  if (!name || !*name) return fallback;
  if (const auto stored = settings::stored_value(name)) {
    const std::string value = trim_copy(*stored);
    if (!value.empty()) return value;
  }
  const char *raw = std::getenv(name);
  if (!raw) return fallback;
  const std::string value = trim_copy(raw);
  return value.empty() ? fallback : value;
}

int env_int_value(const char *name, int fallback, int min_value,
                  int max_value) {
  if (!name || !*name) return fallback;
  std::string text;
  if (const auto stored = settings::stored_value(name)) {
    text = trim_copy(*stored);
  } else {
    const char *raw = std::getenv(name);
    if (!raw) return fallback;
    text = trim_copy(raw);
  }
  if (text.empty()) return fallback;
  try {
    const int parsed = std::stoi(text);
    return std::clamp(parsed, min_value, max_value);
  } catch (...) {
    return fallback;
  }
}

void add_scim_security_headers(crow::response &response) {
  response.add_header("X-Content-Type-Options", "nosniff");
  response.add_header("X-Frame-Options", "SAMEORIGIN");
  response.add_header("X-XSS-Protection", "0");
  response.add_header("Referrer-Policy", "strict-origin-when-cross-origin");
  response.add_header("Cache-Control",
                      "no-store, no-cache, must-revalidate, private");
  response.add_header("Pragma", "no-cache");
  response.add_header("Cross-Origin-Opener-Policy", "same-origin");
  response.add_header("Cross-Origin-Resource-Policy", "same-origin");
  response.add_header("X-Permitted-Cross-Domain-Policies", "none");
  response.add_header("Content-Security-Policy",
                      "default-src 'self'; "
                      "base-uri 'self'; "
                      "object-src 'none'; "
                      "frame-ancestors 'self'; "
                      "script-src 'self' 'unsafe-inline'; "
                      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                      "font-src 'self' https://fonts.gstatic.com; "
                      "img-src 'self' data: https:; "
                      "connect-src 'self' ws: wss:; "
                      "frame-src 'self'; "
                      "form-action 'self'; "
                      "worker-src 'self' blob:");
  response.add_header(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
}

crow::response scim_json_response(crow::json::wvalue payload, int status_code) {
  crow::response response;
  response.code = status_code;
  response.body = payload.dump();
  response.add_header("Content-Type", "application/json");
  add_scim_security_headers(response);
  return response;
}

bool has_any_permission(AppContext &ctx, const AuthSession &auth,
                        const std::vector<std::string> &permissions) {
  for (const auto &permission : permissions) {
    if (has_permission(ctx, auth, permission)) return true;
  }
  return false;
}

void append_behavior_anomaly_event(AppContext &ctx, const std::string &event_type,
                                   const std::string &actor,
                                   const std::string &payload_json) {
  AuditEvent anomaly;
  anomaly.id = ctx.next_audit_id.fetch_add(1);
  anomaly.type = event_type;
  anomaly.actor = actor;
  anomaly.role = "";
  anomaly.createdAt = now_utc();
  anomaly.payloadJson = payload_json;
  anomaly.payloadIsJson = true;
  ctx.append_audit(anomaly);
}

// ── Access policy/profile read helpers (shared: core session + pro) ──
int next_table_numeric_id(AppContext &ctx, const char *table_name) {
  if (!ctx.sqlite.is_open() || !table_name || !*table_name) return 1;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  auto stmt = ctx.sqlite.prepare(
      std::string("SELECT COALESCE(MAX(id), 0) + 1 FROM ") + table_name);
  if (!stmt) return 1;
  if (!stmt.step()) return 1;
  return std::max(1, stmt.column_int(0));
}

std::vector<AccessPolicy> query_access_policies(AppContext &ctx) {
  std::vector<AccessPolicy> items;
  if (!ctx.sqlite.is_open()) return items;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  auto stmt = ctx.sqlite.prepare(
      "SELECT id, name, description, identity_pattern, group_name, role, "
      "resource_tags_csv, risk_level, ticket_required, "
      "require_justification, approval_mode, mfa_requirement, time_window, "
      "max_duration_seconds, routing_constraint, enabled, created_at, "
      "updated_at FROM access_policies ORDER BY id ASC");
  if (!stmt) return items;
  while (stmt.step()) {
    AccessPolicy policy;
    policy.id = stmt.column_int(0);
    stmt.column_text_into(1, policy.name);
    stmt.column_text_into(2, policy.description);
    stmt.column_text_into(3, policy.identityPattern);
    stmt.column_text_into(4, policy.groupName);
    stmt.column_text_into(5, policy.role);
    stmt.column_text_into(6, policy.resourceTagsCsv);
    stmt.column_text_into(7, policy.riskLevel);
    policy.ticketRequired = stmt.column_int(8) != 0;
    policy.requireJustification = stmt.column_int(9) != 0;
    stmt.column_text_into(10, policy.approvalMode);
    stmt.column_text_into(11, policy.mfaRequirement);
    stmt.column_text_into(12, policy.timeWindow);
    policy.maxDurationSeconds = stmt.column_int(13);
    stmt.column_text_into(14, policy.routingConstraint);
    policy.enabled = stmt.column_int(15) != 0;
    stmt.column_text_into(16, policy.createdAt);
    stmt.column_text_into(17, policy.updatedAt);
    items.push_back(policy);
  }
  return items;
}

std::optional<AccessPolicy> query_access_policy_by_id(AppContext &ctx, int policy_id) {
  if (policy_id <= 0) return std::nullopt;
  for (const auto &policy : query_access_policies(ctx)) {
    if (policy.id == policy_id) return policy;
  }
  return std::nullopt;
}

std::vector<AccessProfile> query_access_profiles(AppContext &ctx) {
  std::vector<AccessProfile> items;
  if (!ctx.sqlite.is_open()) return items;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  auto stmt = ctx.sqlite.prepare(
      "SELECT id, name, description, resource_tags_csv, resource_ids_csv, "
      "policy_id, created_at, updated_at FROM access_profiles ORDER BY id ASC");
  if (!stmt) return items;
  while (stmt.step()) {
    AccessProfile profile;
    profile.id = stmt.column_int(0);
    stmt.column_text_into(1, profile.name);
    stmt.column_text_into(2, profile.description);
    stmt.column_text_into(3, profile.resourceTagsCsv);
    stmt.column_text_into(4, profile.resourceIdsCsv);
    profile.policyId = stmt.column_int(5);
    stmt.column_text_into(6, profile.createdAt);
    stmt.column_text_into(7, profile.updatedAt);
    items.push_back(profile);
  }
  return items;
}

std::optional<ParsedEndpointUrl> parse_endpoint_url(const std::string &raw_url) {
  const std::string url = trim_copy(raw_url);
  if (url.empty()) return std::nullopt;

  const size_t scheme_sep = url.find("://");
  if (scheme_sep == std::string::npos) return std::nullopt;

  ParsedEndpointUrl parsed;
  parsed.scheme = to_lower(url.substr(0, scheme_sep));
  if (parsed.scheme != "http" && parsed.scheme != "https") {
    return std::nullopt;
  }

  std::string remainder = url.substr(scheme_sep + 3);
  if (remainder.empty()) return std::nullopt;

  const size_t path_pos = remainder.find('/');
  const size_t query_pos = remainder.find('?');
  size_t authority_end = std::string::npos;
  if (path_pos == std::string::npos && query_pos == std::string::npos) {
    authority_end = remainder.size();
  } else if (path_pos == std::string::npos) {
    authority_end = query_pos;
  } else if (query_pos == std::string::npos) {
    authority_end = path_pos;
  } else {
    authority_end = std::min(path_pos, query_pos);
  }

  const std::string authority = remainder.substr(0, authority_end);
  if (authority.empty()) return std::nullopt;

  parsed.target = authority_end < remainder.size() ? remainder.substr(authority_end)
                                                    : "/";
  if (parsed.target.empty()) parsed.target = "/";
  if (!parsed.target.empty() && parsed.target[0] != '/') {
    parsed.target = "/" + parsed.target;
  }

  parsed.port = parsed.scheme == "https" ? 443 : 80;
  if (authority.front() == '[') {
    const size_t close = authority.find(']');
    if (close == std::string::npos || close <= 1) return std::nullopt;
    parsed.host = authority.substr(1, close - 1);
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':') return std::nullopt;
      const std::string port_part = authority.substr(close + 2);
      if (port_part.empty() ||
          !std::all_of(port_part.begin(), port_part.end(),
                       [](unsigned char c) { return std::isdigit(c) != 0; })) {
        return std::nullopt;
      }
      try {
        parsed.port = std::stoi(port_part);
      } catch (...) {
        return std::nullopt;
      }
    }
  } else {
    parsed.host = authority;
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
      const std::string port_part = authority.substr(colon + 1);
      if (!port_part.empty() &&
          std::all_of(port_part.begin(), port_part.end(),
                      [](unsigned char c) { return std::isdigit(c) != 0; })) {
        try {
          parsed.port = std::stoi(port_part);
          parsed.host = authority.substr(0, colon);
        } catch (...) {
          return std::nullopt;
        }
      }
    }
  }

  if (parsed.host.empty()) return std::nullopt;
  return parsed;
}

// ─── First-login security gate (called from SecurityHeadersMiddleware) ──────
namespace security_setup {

bool gate_before(const crow::request &req, crow::response &res) {
  AppContext *ctx = g_license_ctx;
  if (!ctx) return false;

  const std::string &path = req.url;
  const auto starts_with = [&path](const char *prefix) {
    return path.rfind(prefix, 0) == 0;
  };
  if (!starts_with("/api/") && !starts_with("/ws/") && !starts_with("/proxy/"))
    return false;
  // What the first-login dialog itself needs: sign-in/out, password rotation,
  // MFA enrolment and the page chrome. Minting an agent token is not part of it.
  if ((starts_with("/api/auth/") && !starts_with("/api/auth/agent-token")) ||
      path == "/api/health" || starts_with("/api/branding") ||
      path == "/api/license/status")
    return false;

  // No (valid) token: let the route answer 401 itself.
  const auto token = extract_auth_token_from_request(req);
  if (!token) return false;
  const auto auth = ctx->find_auth_by_token(*token);
  if (!auth || !auth->securitySetupPending) return false;

  res.code = 403;
  res.body = "Security setup required";
  return true;
}

}  // namespace security_setup

// ─── Request-body errors -> 400 ──────────────────────────────────────────────
void handle_route_exception(crow::response &res) {
  try {
    throw;
  } catch (const std::runtime_error &e) {
    // The messages crow::json::rvalue throws on a bad access (json.h).
    static const char *const kJsonAccessErrors[] = {
        "cannot find key",        "value is not",
        "expected number, got",   "list out of bound",
        "invalid json object",    "json type container"};
    const std::string what = e.what();
    for (const char *prefix : kJsonAccessErrors) {
      if (what.rfind(prefix, 0) == 0) {
        res = crow::response(400, "Invalid JSON body");
        return;
      }
    }
    crow::Router::default_exception_handler(res);
  } catch (...) {
    crow::Router::default_exception_handler(res);
  }
}
