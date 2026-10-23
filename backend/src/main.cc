// ─── EndoriumFort — main entry point ────────────────────────────────────
// Slim launcher: creates the Crow app, initialises AppContext, registers
// all route groups, and starts the server.

#include "app_context.h"
#include "crypto.h"
#include "http_proxy.h"
#include "runtime_config.h"
#include "settings.h"
#include "route_common.h"
#include "routes.h"
#include "ssh_guard.h"
#include "security_middleware.h"
#include "ssh.h"

#ifndef _WIN32
#include <csignal>
#endif

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
#include <libssh2.h>
#endif
#endif

int main() {
#ifndef _WIN32
  // Writing to a socket whose peer has gone raises SIGPIPE, whose default
  // action terminates the process. Every outbound TLS write does it: the HTTPS
  // proxy, the OIDC token exchange, the ITSM lookups and the SIEM channels all
  // write through OpenSSL, which (unlike the raw send() calls) cannot pass
  // MSG_NOSIGNAL. Ignoring it turns the condition back into an EPIPE return
  // value, which those call sites already treat as a transport error.
  std::signal(SIGPIPE, SIG_IGN);
#endif

  CrowApp app;
  AppContext ctx;
  const RuntimeConfig runtime_config = load_runtime_config(ctx);
  apply_runtime_config(ctx, runtime_config);

  // ── Initialise database and load data ──
  ctx.init_database();
  ctx.seed_default_admin();
  ctx.init_recordings_dir();
  // Integration configuration set from the admin console, loaded before any
  // route group reads its settings.
  settings::init(ctx);
  ssh_guard::init(ctx);
  log_runtime_config(runtime_config);
  if (!crypto::get_vault_encryption_key()) {
    std::cerr << "[vault] WARNING: ENDORIUMFORT_VAULT_KEY is not set (64 hex "
                 "chars): new passwords and secrets are refused\n";
  }

  // ── License (freemium open-core): load + verify offline, then expose to gate ──
  ctx.reload_license();
  g_license_ctx = &ctx;

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
  if (libssh2_init(0) != 0) {
    std::cerr << "libssh2 init failed" << '\n';
  }
#endif
#endif

  // Missing/mistyped JSON fields: 400, not 500 (see handle_route_exception).
  app.exception_handler(handle_route_exception);

  // ── Register all route groups ──
  register_health_routes(app, ctx);
  register_auth_routes(app, ctx);
  register_totp_routes(app, ctx);
  register_device_routes(app, ctx);
  register_user_routes(app, ctx);
  register_resource_routes(app, ctx);
  register_session_routes(app, ctx);
  register_audit_routes(app, ctx);
  register_stats_routes(app, ctx);
  register_license_routes(app, ctx);
  register_settings_routes(app, ctx);
  register_ssh_guard_routes(app, ctx);
  register_proxy_routes(app, ctx);
  register_web_resource_routes(app, ctx);
  register_ssh_routes(app, ctx);
  register_rbi_routes(app, ctx);

  // Premium (Enterprise) route groups — no-op in the Community edition.
  register_pro_features(app, ctx);

  // ── Start server ── (blocks until SIGINT/SIGTERM)
  app.port(runtime_config.port).multithreaded().run();

  // ── Graceful teardown: stop premium background workers (scheduler, …) ──
  ctx.run_shutdown_hooks();

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
  libssh2_exit();
#endif
#endif
  return 0;
}
