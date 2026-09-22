// ─── EndoriumFort — License runtime wiring & routes ──────────────────────────
// Loads the license (env/file), verifies the hybrid Ed25519+ML-DSA-65 signature
// once, caches the claims, persists a monotonic clock watermark (anti-rollback),
// loads the signed revocation list, exposes /api/license/status + /reload, and
// provides the global premium gate used by the security middleware.

#include "app_context.h"
#include "license.h"
#include "routes.h"
#include "utils.h"

#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_set>

// Set once in main.cc before the server starts; read by the middleware gate.
AppContext *g_license_ctx = nullptr;

namespace {

std::string read_file_trimmed(const std::string &path) {
  if (path.empty()) return {};
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::string s((std::istreambuf_iterator<char>(f)),
                std::istreambuf_iterator<char>());
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
    s.pop_back();
  size_t start = 0;
  while (start < s.size() && (s[start] == ' ' || s[start] == '\n' ||
                             s[start] == '\r' || s[start] == '\t'))
    ++start;
  return s.substr(start);
}

// Local env-flag reader (license.cc must not depend on routes.cc internals).
bool env_flag_local(const char *name, bool fallback) {
  if (!name || !*name) return fallback;
  const char *raw = std::getenv(name);
  if (!raw || !*raw) return fallback;
  std::string v(raw);
  std::transform(v.begin(), v.end(), v.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
  if (v == "0" || v == "false" || v == "no" || v == "off") return false;
  return fallback;
}

int64_t db_get_int(AppContext &ctx, const std::string &key, int64_t fallback) {
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  if (!ctx.sqlite.db) return fallback;
  sqlite3_stmt *stmt = nullptr;
  int64_t value = fallback;
  if (sqlite3_prepare_v2(ctx.sqlite.db, "SELECT v FROM license_state WHERE k=?1;",
                         -1, &stmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
      value = sqlite3_column_int64(stmt, 0);
    }
  }
  sqlite3_finalize(stmt);
  return value;
}

void db_set_int(AppContext &ctx, const std::string &key, int64_t value) {
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  if (!ctx.sqlite.db) return;
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(
          ctx.sqlite.db,
          "INSERT INTO license_state(k,v) VALUES(?1,?2) "
          "ON CONFLICT(k) DO UPDATE SET v=excluded.v;",
          -1, &stmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, value);
    sqlite3_step(stmt);
  }
  sqlite3_finalize(stmt);
}

// Load and verify the signed revocation list; augment `denylist` with revoked
// ids. Enforces a strictly increasing `seq` persisted in license_state.
void load_crl(AppContext &ctx, const std::string &path,
              std::unordered_set<std::string> &denylist) {
  const std::string compact = read_file_trimmed(path);
  if (compact.empty()) return;
  std::string payload_json;
  if (!license::verify_signed_payload(compact, license::issuer_keys(),
                                      license::kRevocationTyp, payload_json)) {
    std::cerr << "[license] revocation list signature invalid — ignored\n";
    return;
  }
  const auto payload = crow::json::load(payload_json);
  if (!payload) return;
  int64_t seq = 0;
  try {
    if (payload.has("seq")) seq = static_cast<int64_t>(payload["seq"].i());
  } catch (...) {
  }
  const int64_t stored_seq = db_get_int(ctx, "crl_seq", 0);
  if (seq < stored_seq) {
    std::cerr << "[license] revocation list seq " << seq << " < stored "
              << stored_seq << " — rejected (anti-rollback)\n";
    return;
  }
  if (payload.has("revoked") &&
      payload["revoked"].t() == crow::json::type::List) {
    for (const auto &item : payload["revoked"]) {
      if (item.t() == crow::json::type::String) {
        denylist.insert(static_cast<std::string>(item.s()));
      }
    }
  }
  db_set_int(ctx, "crl_seq", seq);
}

}  // namespace

// ─── AppContext license methods ──────────────────────────────────────────────

void AppContext::load_license_watermark() {
  const int64_t stored = db_get_int(*this, "clock_watermark", 0);
  std::lock_guard<std::mutex> lock(license_mutex);
  license_clock_watermark = std::max(license_clock_watermark, stored);
}

void AppContext::reload_license() {
  std::string token = license_inline;
  if (token.empty()) token = read_file_trimmed(license_file_path);

  const int64_t now = now_epoch_seconds();

  // Watermark: highest epoch ever observed; advance and persist.
  int64_t watermark = std::max(db_get_int(*this, "clock_watermark", 0), now);
  db_set_int(*this, "clock_watermark", watermark);

  // Revocation list (signed) -> denylist.
  std::unordered_set<std::string> denylist;
  if (!license_crl_path.empty()) load_crl(*this, license_crl_path, denylist);

  {
    std::lock_guard<std::mutex> lock(license_mutex);
    license_clock_watermark = watermark;
    license_watermark_last_persist = now;
    license_denylist = denylist;

    if (token.empty()) {
      license_signature_valid = false;
      license_claims = license::LicenseClaims{};
      license_invalid_reason = "no license configured";
    } else {
      const auto st = license::parse_and_verify(token, license::issuer_keys(),
                                                now, watermark, denylist);
      if (st.state == license::LicenseState::Invalid) {
        license_signature_valid = false;
        license_claims = license::LicenseClaims{};
        license_invalid_reason = st.reason;
      } else {
        // Signature verified; state may be Valid/Expired/NotYetValid/Revoked.
        license_signature_valid = true;
        license_claims = st.claims;
        license_invalid_reason.clear();
      }
    }
  }

  const auto st = current_license_status();
  AuditEvent event;
  event.id = next_audit_id.fetch_add(1);
  event.type = token.empty() ? "license.absent" : "license.reloaded";
  event.actor = "system";
  event.role = "system";
  event.createdAt = now_utc();
  event.payloadJson = std::string("{\"state\":\"") +
                      json_escape(license::to_string(st.state)) +
                      "\",\"tier\":\"" + json_escape(st.claims.tier) +
                      "\",\"kind\":\"" + json_escape(st.claims.kind) +
                      "\",\"daysRemaining\":" +
                      std::to_string(st.daysRemaining) + "}";
  event.payloadIsJson = true;
  append_audit(event);

  std::cerr << "[license] state=" << license::to_string(st.state)
            << " tier=" << (st.state == license::LicenseState::Valid
                                ? st.claims.tier
                                : std::string("free"))
            << " kind=" << st.claims.kind
            << " daysRemaining=" << st.daysRemaining << '\n';
}

license::LicenseStatus AppContext::current_license_status() {
  std::lock_guard<std::mutex> lock(license_mutex);
  if (!license_signature_valid) {
    license::LicenseStatus st;
    st.state = (license_invalid_reason == "no license configured")
                   ? license::LicenseState::None
                   : license::LicenseState::Invalid;
    st.reason = license_invalid_reason;
    return st;
  }

  const int64_t now = now_epoch_seconds();
  if (now > license_clock_watermark) {
    license_clock_watermark = now;
    if (now - license_watermark_last_persist >= 3600) {
      license_watermark_last_persist = now;
      db_set_int(*this, "clock_watermark", license_clock_watermark);
    }
  }
  return license::evaluate_claims(license_claims, now, license_clock_watermark,
                                  license_denylist);
}

std::string AppContext::effective_tier() {
  const auto st = current_license_status();
  return st.state == license::LicenseState::Valid ? st.claims.tier : "free";
}

bool AppContext::license_allows_feature(const std::string &feature) {
  return license::license_allows(current_license_status(), feature);
}

bool AppContext::feature_active(const std::string &feature) {
  const auto *entry = license::find_feature(feature);
  bool env_ok = true;
  if (entry && entry->envFlag) env_ok = env_flag_local(entry->envFlag, true);
  return license_allows_feature(feature) && env_ok;
}

// ─── Global premium gate (called from SecurityHeadersMiddleware::before_handle) ─
namespace license {

namespace {
bool path_has_prefix(const std::string &path, const char *prefix) {
  return path.rfind(prefix, 0) == 0;
}
}  // namespace

bool gate_before(const crow::request &req, crow::response &res) {
  AppContext *ctx = g_license_ctx;
  if (!ctx) return false;

  const std::string &path = req.url;
  const char *feature = nullptr;
  if (path_has_prefix(path, "/api/cluster")) {
    feature = "cluster";
  } else if (path_has_prefix(path, "/api/relays")) {
    feature = "relay";
  } else if (path_has_prefix(path, "/api/rdp") ||
             path_has_prefix(path, "/api/ws/rdp")) {
    feature = "rdp";
  } else if (path_has_prefix(path, "/api/vnc") ||
             path_has_prefix(path, "/api/ws/vnc")) {
    feature = "vnc";
  } else if (path_has_prefix(path, "/api/tunnel") ||
             path_has_prefix(path, "/ws/tunnel")) {
    feature = "tunnel";
  } else if (path_has_prefix(path, "/api/recordings")) {
    feature = "recording";
  } else if (path_has_prefix(path, "/api/scim")) {
    feature = "scim";
  } else if (path_has_prefix(path, "/api/integrations/siem")) {
    feature = "siem";
  } else if (path_has_prefix(path, "/api/integrations/itsm")) {
    feature = "itsm";
  } else if (path_has_prefix(path, "/api/auth/sso")) {
    feature = "sso.oidc";  // OIDC/SAML SSO login + diagnostics (enterprise)
  } else if (path_has_prefix(path, "/api/auth/directory")) {
    feature = "ldap";      // LDAP/AD directory + bind (enterprise)
  } else if (path_has_prefix(path, "/api/access-requests") ||
             path_has_prefix(path, "/api/access-policies") ||
             path_has_prefix(path, "/api/access-profiles") ||
             path_has_prefix(path, "/api/access-grants") ||
             path_has_prefix(path, "/api/ephemeral-credentials")) {
    feature = "jit.governance";  // JIT access governance (pro)
  } else if (path_has_prefix(path, "/api/evidence-packs")) {
    feature = "evidence.packs";  // signed forensic evidence (enterprise)
  } else if (path_has_prefix(path, "/api/security")) {
    feature = "security.center";  // incidents / containment / alerts (enterprise)
  }
  if (!feature) return false;  // not a globally-gated premium prefix

  if (ctx->license_allows_feature(feature)) return false;  // entitled -> allow

  const FeatureEntitlement *entry = find_feature(feature);
  const auto st = ctx->current_license_status();
  crow::json::wvalue body;
  body["error"] = "license_required";
  body["feature"] = feature;
  body["requiredTier"] = entry ? entry->minTier : "pro";
  body["state"] = to_string(st.state);
  // NOTE: HTTP 402 "Payment Required" is the semantically correct code but Crow
  // v1.2.0's status map lacks it (it would be downgraded to 500). We therefore
  // use 403 as the transport code; clients discriminate a license block from a
  // permission block via the body `error:"license_required"` and this header.
  res.code = 403;
  res.set_header("Content-Type", "application/json");
  res.set_header("X-EndoriumFort-License-Required", "1");
  res.body = body.dump();
  return true;  // blocked
}

}  // namespace license

// Per-route license denial (couche a): premium handlers that share a core URL
// prefix call this to return a machine-readable 403 when unlicensed.
crow::response license_denied_response(AppContext &ctx, const std::string &feature) {
  const license::FeatureEntitlement *entry = license::find_feature(feature);
  const auto st = ctx.current_license_status();
  crow::json::wvalue body;
  body["error"] = "license_required";
  body["feature"] = feature;
  body["requiredTier"] = entry ? entry->minTier : "pro";
  body["state"] = license::to_string(st.state);
  crow::response resp(403, body.dump());
  resp.set_header("Content-Type", "application/json");
  resp.set_header("X-EndoriumFort-License-Required", "1");
  return resp;
}

// ─── Routes ──────────────────────────────────────────────────────────────────
void register_license_routes(CrowApp &app, AppContext &ctx) {
  // Public-ish: any authenticated user sees tier/state; full detail for admins.
  CROW_ROUTE(app, "/api/license/status")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        const auto st = ctx.current_license_status();
        const bool is_valid = st.state == license::LicenseState::Valid;
        crow::json::wvalue payload;
#ifdef ENDORIUMFORT_PRO
        payload["edition"] = "enterprise";  // EE build: premium modules present
#else
        payload["edition"] = "community";   // CE build: premium modules absent
#endif
        payload["state"] = license::to_string(st.state);
        payload["tier"] = is_valid ? st.claims.tier : std::string("free");
        payload["kind"] = st.claims.kind;
        payload["daysRemaining"] = st.daysRemaining;
        if (is_valid && st.claims.notAfter > 0) {
          payload["expiresAt"] = utc_from_epoch_seconds(st.claims.notAfter);
        }
        crow::json::wvalue::list feats;
        for (const auto &f : st.claims.features) {
          feats.push_back(crow::json::wvalue(f));
        }
        payload["features"] = std::move(feats);

        if (ctx.has_permission(auth->userId, auth->role, "resources.manage")) {
          payload["customer"] = st.claims.customer;
          payload["licenseId"] = st.claims.licenseId;
          payload["maxNodes"] = st.claims.maxNodes;
          payload["maxSeats"] = st.claims.maxSeats;
          if (!st.reason.empty()) payload["reason"] = st.reason;
        }
        return crow::response{payload};
      });

  // Admin: hot-reload the license/CRL from env/file (air-gap friendly).
  CROW_ROUTE(app, "/api/license/reload")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!ctx.has_permission(auth->userId, auth->role, "resources.manage")) {
          return crow::response(403, "Forbidden");
        }
        ctx.reload_license();
        const auto st = ctx.current_license_status();
        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["state"] = license::to_string(st.state);
        payload["tier"] = st.state == license::LicenseState::Valid
                              ? st.claims.tier
                              : std::string("free");
        payload["daysRemaining"] = st.daysRemaining;
        return crow::response{payload};
      });
}
