// ─── EndoriumFort — shared route helpers (implementation) ────────────────────
#include "route_common.h"

#include "app_context.h"

#include <sqlite3.h>
#include "utils.h"  // to_lower, trim_copy

#include <algorithm>
#include <cstdlib>
#include <string>

bool has_permission(AppContext &ctx, const AuthSession &auth,
                    const std::string &permission) {
  return ctx.has_permission(auth.userId, auth.role, permission);
}

bool env_flag_enabled(const char *name, bool fallback) {
  if (!name || !*name) return fallback;
  const char *raw = std::getenv(name);
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
  const char *raw = std::getenv(name);
  if (!raw) return fallback;
  const std::string value = trim_copy(raw);
  return value.empty() ? fallback : value;
}

int env_int_value(const char *name, int fallback, int min_value,
                  int max_value) {
  if (!name || !*name) return fallback;
  const char *raw = std::getenv(name);
  if (!raw) return fallback;
  try {
    const int parsed = std::stoi(trim_copy(raw));
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
  if (!ctx.sqlite.db || !table_name || !*table_name) return 1;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const std::string sql =
      std::string("SELECT COALESCE(MAX(id), 0) + 1 FROM ") + table_name;
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql.c_str(), -1, &stmt, nullptr) !=
      SQLITE_OK) {
    return 1;
  }
  int next_id = 1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    next_id = std::max(1, sqlite3_column_int(stmt, 0));
  }
  sqlite3_finalize(stmt);
  return next_id;
}

std::vector<AccessPolicy> query_access_policies(AppContext &ctx) {
  std::vector<AccessPolicy> items;
  if (!ctx.sqlite.db) return items;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "SELECT id, name, description, identity_pattern, group_name, role, "
      "resource_tags_csv, risk_level, ticket_required, "
      "require_justification, approval_mode, mfa_requirement, time_window, "
      "max_duration_seconds, routing_constraint, enabled, created_at, "
      "updated_at FROM access_policies ORDER BY id ASC";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return items;
  }
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    AccessPolicy policy;
    policy.id = sqlite3_column_int(stmt, 0);
    if (auto value = sqlite3_column_text(stmt, 1))
      policy.name = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 2))
      policy.description = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 3))
      policy.identityPattern = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 4))
      policy.groupName = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 5))
      policy.role = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 6))
      policy.resourceTagsCsv = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 7))
      policy.riskLevel = reinterpret_cast<const char *>(value);
    policy.ticketRequired = sqlite3_column_int(stmt, 8) != 0;
    policy.requireJustification = sqlite3_column_int(stmt, 9) != 0;
    if (auto value = sqlite3_column_text(stmt, 10))
      policy.approvalMode = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 11))
      policy.mfaRequirement = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 12))
      policy.timeWindow = reinterpret_cast<const char *>(value);
    policy.maxDurationSeconds = sqlite3_column_int(stmt, 13);
    if (auto value = sqlite3_column_text(stmt, 14))
      policy.routingConstraint = reinterpret_cast<const char *>(value);
    policy.enabled = sqlite3_column_int(stmt, 15) != 0;
    if (auto value = sqlite3_column_text(stmt, 16))
      policy.createdAt = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 17))
      policy.updatedAt = reinterpret_cast<const char *>(value);
    items.push_back(policy);
  }
  sqlite3_finalize(stmt);
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
  if (!ctx.sqlite.db) return items;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "SELECT id, name, description, resource_tags_csv, resource_ids_csv, "
      "policy_id, created_at, updated_at FROM access_profiles ORDER BY id ASC";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return items;
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
