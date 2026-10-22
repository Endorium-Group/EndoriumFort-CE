// Failed sign-ins: a few typos never block (the key is per user and per IP,
// so a block would also stop everyone behind the same address); from 10
// consecutive failures the backoff applies; a successful sign-in clears it.

#include "app_context.h"

#include <iostream>
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

  if (failures == 0) std::cout << "login backoff tests passed" << std::endl;
  return failures == 0 ? 0 : 1;
}
