// ─── EndoriumFort — GET /api/metrics (Prometheus exposition) ────────────────
// Core. Serves the registry in metrics.h in the Prometheus text format. Needs
// the `metrics.read` permission: in practice an API token scoped to it, which
// Prometheus sends as `Authorization: Bearer efapi_…`. Under /api/ so the
// bundled nginx and any ingress already route it; scrape with
// `metrics_path: /api/metrics`.

#include "routes.h"
#include "app_context.h"
#include "metrics.h"
#include "route_common.h"
#include "utils.h"
#include "version.h"

#include <string>
#include <unordered_map>

namespace {

#ifdef ENDORIUMFORT_PRO
constexpr const char *kEdition = "ee";
#else
constexpr const char *kEdition = "ce";
#endif

// Gauges computed from live state at each scrape (core part).
void collect_core(AppContext &ctx) {
  auto &r = metrics::registry();

  std::unordered_map<std::string, int> active;
  for (const char *protocol : {"ssh", "rdp", "vnc", "http", "https", "k8s", "tunnel", "agent", "postgres"})
    active[protocol] = 0;  // report zeros so dashboards show a flat line, not a gap
  {
    std::lock_guard<std::mutex> lock(ctx.session_mutex);
    for (const auto &entry : ctx.sessions)
      if (entry.second.status == "active")
        ++active[metrics::protocol_label(entry.second.protocol)];
  }
  r.clear(metrics::kSessionsActive);
  for (const auto &[protocol, count] : active)
    r.set(metrics::kSessionsActive, {{"protocol", protocol}}, count);

  const auto license = ctx.current_license_status();
  const bool valid = license.state == license::LicenseState::Valid;
  r.set(metrics::kLicenseValid, {}, valid ? 1 : 0);
  r.clear(metrics::kLicenseExpiry);
  if (license.state != license::LicenseState::None && license.claims.notAfter > 0)
    r.set(metrics::kLicenseExpiry, {}, static_cast<double>(license.claims.notAfter));

  r.set(metrics::kBuildInfo, {{"version", APP_VERSION}, {"edition", kEdition}}, 1);

  // A counter, but only the registry knows the drops; mirror its tally.
  const auto dropped = r.dropped_series();
  const auto seen = r.value(metrics::kDroppedSeries).value_or(0);
  if (static_cast<double>(dropped) > seen)
    r.inc(metrics::kDroppedSeries, {}, static_cast<double>(dropped) - seen);
}

}  // namespace

void register_metrics_routes(CrowApp &app, AppContext &ctx) {
  metrics::describe_core();
  metrics::registry().set(metrics::kStartTime, {}, static_cast<double>(now_epoch_seconds()));
  // Unlabelled counters start at 0, so rate() and alerts see a series before the
  // first event instead of nothing.
  for (const char *name : {metrics::kSshGuardBlocked, metrics::kProxyUpstreamErrors,
                           metrics::kDroppedSeries})
    metrics::registry().inc(name, {}, 0);
  metrics::registry().add_collector([&ctx] { collect_core(ctx); });

  CROW_ROUTE(app, "/api/metrics")
  ([&ctx](const crow::request &request) {
    auto auth = ctx.find_auth(request);
    if (!auth) return crow::response(401, "Unauthorized");
    if (!has_permission(ctx, *auth, "metrics.read"))
      return crow::response(403, "Forbidden");

    auto &registry = metrics::registry();
    registry.collect();
    crow::response response(200, registry.render());
    response.set_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
    return response;
  });
}
