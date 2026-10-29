#pragma once
// ─── EndoriumFort — API route registration ──────────────────────────────
// Each function registers a group of CROW_ROUTE entries.

#include "security_middleware.h"

#include <string>

struct AppContext;

void register_health_routes(CrowApp &app, AppContext &ctx);
void register_auth_routes(CrowApp &app, AppContext &ctx);
void register_totp_routes(CrowApp &app, AppContext &ctx);
void register_device_routes(CrowApp &app, AppContext &ctx);
void register_user_routes(CrowApp &app, AppContext &ctx);
void register_resource_routes(CrowApp &app, AppContext &ctx);
void register_access_request_routes(CrowApp &app, AppContext &ctx);
void register_session_routes(CrowApp &app, AppContext &ctx);
void register_audit_routes(CrowApp &app, AppContext &ctx);
void register_recording_routes(CrowApp &app, AppContext &ctx);
void register_stats_routes(CrowApp &app, AppContext &ctx);
void register_relay_routes(CrowApp &app, AppContext &ctx);
void register_enterprise_routes(CrowApp &app, AppContext &ctx);
void register_license_routes(CrowApp &app, AppContext &ctx);
// Integration configuration from the admin console (settings.h). Core, so the
// Community build can configure LDAP and the RBI transfer policy too.
void register_settings_routes(CrowApp &app, AppContext &ctx);
void register_ssh_guard_routes(CrowApp &app, AppContext &ctx);
// Remote Browser Isolation (core / CE): server-side headless Chromium streamed
// to the operator over a WebSocket (CDP screencast). Not license-gated.
void register_rbi_routes(CrowApp &app, AppContext &ctx);
// File share resources (core / CE): signed tickets for the separate drive
// service (fileshare/) and the directory of people a drive can be shared with.
void register_fileshare_routes(CrowApp &app, AppContext &ctx);
// Asks the file share service to delete the space of a deleted fileshare
// resource (signed purge order, in the background; journaled either way).
void fileshare_purge_space(AppContext &ctx, int resource_id,
                           const std::string &actor, const std::string &role);

// Open-core extension hook. Registers all premium (Enterprise) route groups.
// The Enterprise build defines it in src/pro/pro_features.cc; the Community
// build links a no-op from src/pro_stub.cc (premium code physically absent).
void register_pro_features(CrowApp &app, AppContext &ctx);

// Global license context, set once in main.cc; read by the middleware gate.
extern AppContext *g_license_ctx;

// Per-route license denial helper (403 machine-readable) for premium handlers
// that share a core URL prefix and can't be gated by the global prefix gate.
crow::response license_denied_response(AppContext &ctx, const std::string &feature);
