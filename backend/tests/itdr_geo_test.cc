// Unit tests for the ITDR geo helpers (pro/itdr.h): lookup, haversine distance
// and impossible-travel detection. Pure, dependency-free.

#include "pro/itdr.h"

#include <iostream>
#include <string>

namespace {
bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}
}  // namespace

int main() {
  bool ok = true;

  // Lookup: known prefixes resolve, unknown/loopback do not.
  ok &= expect(itdr::geo_lookup("8.8.8.8").found, "8.8.8.8 should resolve");
  ok &= expect(itdr::geo_lookup("195.154.10.1").found, "195.154.* should resolve");
  ok &= expect(!itdr::geo_lookup("127.0.0.1").found, "loopback should not resolve");
  ok &= expect(!itdr::geo_lookup("10.0.0.5").found, "private IP should not resolve");

  // Distance sanity: Paris ↔ Mountain View is ~8000-9500 km.
  const auto paris = itdr::geo_lookup("195.154.0.1");
  const auto mtview = itdr::geo_lookup("8.8.8.8");
  const double d = itdr::haversine_km(paris.lat, paris.lon, mtview.lat, mtview.lon);
  ok &= expect(d > 8000.0 && d < 9500.0, "Paris↔MtnView distance in range");

  // Impossible travel: Paris then Mountain View 10 minutes apart → impossible.
  ok &= expect(itdr::is_impossible_travel(paris, mtview, 600),
               "Paris→MtnView in 10min should be impossible");
  // Same login 20 hours apart → feasible (long-haul flight).
  ok &= expect(!itdr::is_impossible_travel(paris, mtview, 20 * 3600),
               "Paris→MtnView in 20h should be feasible");
  // Same metro → never impossible.
  const auto paris2 = itdr::geo_lookup("51.15.0.1");
  ok &= expect(!itdr::is_impossible_travel(paris, paris2, 60),
               "same metro should not be impossible");
  // Unresolved endpoint → no detection (avoid false positives on private IPs).
  ok &= expect(!itdr::is_impossible_travel(itdr::geo_lookup("10.0.0.1"), mtview, 1),
               "unresolved endpoint should not trigger");

  if (!ok) return 1;
  std::cout << "All ITDR geo tests passed." << std::endl;
  return 0;
}
