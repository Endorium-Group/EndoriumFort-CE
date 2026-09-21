#pragma once
// ─── EndoriumFort — API route registration ──────────────────────────────
// Each function registers a group of CROW_ROUTE entries.

#include "security_middleware.h"

struct AppContext;

void register_health_routes(CrowApp &app, AppContext &ctx);
void register_auth_routes(CrowApp &app, AppContext &ctx);
void register_totp_routes(CrowApp &app, AppContext &ctx);
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

// Open-core extension hook. Registers all premium (Enterprise) route groups.
// The Enterprise build defines it in src/pro/pro_features.cc; the Community
// build links a no-op from src/pro_stub.cc (premium code physically absent).
void register_pro_features(CrowApp &app, AppContext &ctx);

// Global license context, set once in main.cc; read by the middleware gate.
extern AppContext *g_license_ctx;

// Per-route license denial helper (403 machine-readable) for premium handlers
// that share a core URL prefix and can't be gated by the global prefix gate.
crow::response license_denied_response(AppContext &ctx, const std::string &feature);
