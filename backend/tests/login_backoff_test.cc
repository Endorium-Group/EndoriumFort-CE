// Failed sign-ins: a few typos never block (the key is per user and per IP,
// so a block would also stop everyone behind the same address); from 10
// consecutive failures the backoff applies; a successful sign-in clears it.

#include "app_context.h"

#include <chrono>
#include <iostream>
#include <mutex>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    ++failures;
  }
}

// What POST /api/auth/login does for a wrong password: check, then record.
bool attempt_and_fail(AppContext &ctx, const std::string &key) {
  const bool allowed = ctx.check_rate_limit(key);
  if (allowed) ctx.record_failed_login_attempt(key);
  return allowed;
}

}  // namespace

int main() {
  AppContext ctx;
  // Isolate the backoff from the per-window attempt cap.
  ctx.rate_limit_max_attempts = 1000;
  const std::string ip = "login_ip:203.0.113.7";

  expect(attempt_and_fail(ctx, ip), "first attempt refused");
  // The case that used to fail: right after one typo, the next sign-in from
  // the same address (another user, or the same one) must go through.
  expect(ctx.check_rate_limit(ip), "blocked after a single failure");

  for (int i = 2; i <= 9; ++i) attempt_and_fail(ctx, ip);
  expect(ctx.get_consecutive_failures(ip) == 9, "failure count");
  expect(ctx.check_rate_limit(ip), "blocked after 9 failures");

  ctx.record_failed_login_attempt(ip);  // 10th consecutive failure
  expect(!ctx.check_rate_limit(ip), "not blocked after 10 failures");

  ctx.clear_login_attempts(ip);  // successful sign-in
  expect(ctx.check_rate_limit(ip), "still blocked after a successful sign-in");
  expect(ctx.get_consecutive_failures(ip) == 0, "failures not reset");

  // The per-window cap still applies on its own (default 10 / 5 min).
  AppContext capped;
  const std::string user = "login:alice";
  int allowed = 0;
  for (int i = 0; i < 12; ++i) allowed += capped.check_rate_limit(user) ? 1 : 0;
  expect(allowed == capped.rate_limit_max_attempts, "attempt cap not enforced");

  // Lookups and a successful sign-in leave no entry behind, and a sweep drops
  // what has nothing left to enforce while keeping live blocks.
  AppContext swept;
  const auto entries = [&swept] { return swept.rate_limit_map.size(); };
  expect(!swept.is_login_blocked("login:nobody") &&
             swept.get_consecutive_failures("login:nobody") == 0 &&
             entries() == 0,
         "lookup created an entry");
  swept.check_rate_limit("login:bob");
  swept.clear_login_attempts("login:bob");
  expect(entries() == 0, "cleared entry kept");

  swept.check_rate_limit("login:stale");
  const std::string blocked = "login_ip:198.51.100.9";
  for (int i = 0; i < 10; ++i) swept.record_failed_login_attempt(blocked);
  const auto later = std::chrono::steady_clock::now() + std::chrono::seconds(400);
  {
    std::lock_guard<std::mutex> lock(swept.rate_limit_mutex);
    swept.sweep_rate_limits_locked(later);  // past the 5 min window
  }
  expect(swept.rate_limit_map.count("login:stale") == 0, "stale entry not swept");
  expect(swept.rate_limit_map.count(blocked) == 1,
         "recent failure history swept too early");
  {
    std::lock_guard<std::mutex> lock(swept.rate_limit_mutex);
    swept.sweep_rate_limits_locked(later + std::chrono::hours(2));
  }
  expect(entries() == 0, "idle failure history never forgotten");

  if (failures == 0) std::cout << "login backoff tests passed" << std::endl;
  return failures == 0 ? 0 : 1;
}
