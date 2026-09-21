#pragma once
// ─── EndoriumFort — shared route helpers ─────────────────────────────────────

// Small helpers used by both the core route groups (routes.cc) and the premium
// route groups extracted into the pro/ overlay. Kept in a dedicated TU (external
// linkage) so pro/*.cc can link them — routes.cc's own helpers live in an
// anonymous namespace and are not visible across translation units.

#include "crow.h"

#include "models.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct AppContext;
struct AuthSession;

// Convenience wrapper around AppContext::has_permission using the
// (ctx, auth, permission) call style used throughout the handlers.
bool has_permission(AppContext &ctx, const AuthSession &auth,
                    const std::string &permission);
bool has_any_permission(AppContext &ctx, const AuthSession &auth,
                        const std::vector<std::string> &permissions);

// TTL after which an approved-but-unused access request is treated as expired.
inline constexpr int64_t kApprovedAccessTtlSeconds = 3600;

// Environment-driven feature/config helpers (shared by core routes and pro/).
bool env_flag_enabled(const char *name, bool fallback);
std::string env_string_value(const char *name, const std::string &fallback);
int env_int_value(const char *name, int fallback, int min_value, int max_value);

// Generic JSON response helpers (named scim_* for historical reasons but used by
// many route groups). Add hardened security headers + JSON content type.
void add_scim_security_headers(crow::response &response);
crow::response scim_json_response(crow::json::wvalue payload, int status_code = 200);

// Appends a behavior/anomaly audit event (shared by core + pro security center).
void append_behavior_anomaly_event(AppContext &ctx, const std::string &event_type,
                                   const std::string &actor,
                                   const std::string &payload_json);

// Access policy/profile read helpers (shared by core session resolution + pro).
int next_table_numeric_id(AppContext &ctx, const char *table_name);
std::vector<AccessPolicy> query_access_policies(AppContext &ctx);
std::optional<AccessPolicy> query_access_policy_by_id(AppContext &ctx, int policy_id);
std::vector<AccessProfile> query_access_profiles(AppContext &ctx);
