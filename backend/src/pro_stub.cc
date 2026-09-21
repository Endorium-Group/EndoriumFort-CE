// ─── EndoriumFort — Community Edition pro-features stub ───────────────────────
// Compiled in the Community build (when ENDORIUMFORT_PRO is OFF). Provides a
// no-op register_pro_features() so the core links and runs without any premium
// code. The real implementation lives in src/pro/pro_features.cc (EE only).

#include "app_context.h"
#include "routes.h"

void register_pro_features(CrowApp & /*app*/, AppContext & /*ctx*/) {
  // Community edition: no premium route groups.
}
