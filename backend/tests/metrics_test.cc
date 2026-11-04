// Unit tests for the Prometheus registry (metrics.h): exposition format,
// histogram buckets, cardinality cap, and the bounded label vocabularies.
#include "api_tokens.h"
#include "metrics.h"

#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {
int failures = 0;
bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    ++failures;
  }
  return condition;
}
bool contains(const std::string &haystack, const std::string &needle) {
  return haystack.find(needle) != std::string::npos;
}

void test_exposition() {
  metrics::Registry r;
  r.describe("t_requests_total", metrics::Type::Counter, "Requests.\nSecond line");
  r.describe("t_active", metrics::Type::Gauge, "Active.");
  r.inc("t_requests_total", {{"status", "2xx"}, {"group", "users"}});
  r.inc("t_requests_total", {{"group", "users"}, {"status", "2xx"}}, 2);  // same series
  r.set("t_active", {}, 4);
  r.set("t_active", {}, 3);
  r.inc("t_requests_total", {{"group", "users"}, {"status", "2xx"}}, -5);  // ignored
  r.inc("t_unknown_total");                                                // ignored

  const std::string out = r.render();
  expect(contains(out, "# HELP t_requests_total Requests.\\nSecond line\n"), "help escaped");
  expect(contains(out, "# TYPE t_requests_total counter\n"), "counter type line");
  expect(contains(out, "t_requests_total{group=\"users\",status=\"2xx\"} 3\n"),
         "labels sorted, same set accumulates, negative ignored");
  expect(contains(out, "# TYPE t_active gauge\nt_active 3\n"), "gauge holds the last value");
  expect(!contains(out, "t_unknown_total"), "undeclared family not rendered");
  expect(out.find("t_active") < out.find("t_requests_total"), "families sorted by name");

  r.describe("t_esc", metrics::Type::Gauge, "Escaping.");
  r.set("t_esc", {{"v", "a\"b\\c\nd"}}, 1.5);
  expect(contains(r.render(), "t_esc{v=\"a\\\"b\\\\c\\nd\"} 1.5\n"), "label value escaped");

  r.set("t_active", {}, 3);
  r.clear("t_active");
  expect(!contains(r.render(), "t_active 3"), "clear drops the series");
  expect(contains(r.render(), "# TYPE t_active gauge"), "clear keeps the family");
}

void test_histogram() {
  metrics::Registry r;
  r.describe("t_seconds", metrics::Type::Histogram, "Duration.", {0.1, 1, 0.5});
  r.observe("t_seconds", {{"g", "a"}}, 0.05);
  r.observe("t_seconds", {{"g", "a"}}, 0.3);
  r.observe("t_seconds", {{"g", "a"}}, 2);
  const std::string out = r.render();
  expect(contains(out, "t_seconds_bucket{g=\"a\",le=\"0.1\"} 1\n"), "bucket 0.1");
  expect(contains(out, "t_seconds_bucket{g=\"a\",le=\"0.5\"} 2\n"), "buckets sorted, cumulative");
  expect(contains(out, "t_seconds_bucket{g=\"a\",le=\"1\"} 2\n"), "bucket 1");
  expect(contains(out, "t_seconds_bucket{g=\"a\",le=\"+Inf\"} 3\n"), "+Inf = count");
  expect(contains(out, "t_seconds_sum{g=\"a\"} 2.35\n"), "sum");
  expect(contains(out, "t_seconds_count{g=\"a\"} 3\n"), "count");
  r.inc("t_seconds");
  expect(contains(r.render(), "t_seconds_count{g=\"a\"} 3\n"), "inc on a histogram ignored");
}

void test_cardinality_cap() {
  metrics::Registry r;
  r.describe("t_capped", metrics::Type::Gauge, "Capped.");
  for (size_t i = 0; i < metrics::kMaxSeriesPerFamily + 10; ++i)
    r.set("t_capped", {{"i", std::to_string(i)}}, 1);
  expect(r.dropped_series() == 10, "series beyond the cap are dropped and counted");
  r.set("t_capped", {{"i", "0"}}, 7);
  expect(r.value("t_capped", {{"i", "0"}}).value_or(0) == 7, "existing series still updates");
}

void test_concurrency() {
  metrics::Registry r;
  r.describe("t_c_total", metrics::Type::Counter, "Concurrent.");
  std::vector<std::thread> threads;
  for (int t = 0; t < 8; ++t)
    threads.emplace_back([&r] {
      for (int i = 0; i < 1000; ++i) r.inc("t_c_total");
    });
  for (auto &thread : threads) thread.join();
  expect(r.value("t_c_total").value_or(0) == 8000, "no lost increments");
}

void test_collectors() {
  metrics::Registry r;
  r.describe("t_live", metrics::Type::Gauge, "Live.");
  int calls = 0;
  r.add_collector([&] { r.set("t_live", {}, ++calls); });
  r.collect();
  r.collect();
  expect(r.value("t_live").value_or(0) == 2, "collectors run at each collect");
}

void test_vocabularies() {
  using namespace metrics;
  expect(route_group("/api/users/12") == "users", "group from first segment");
  expect(route_group("/api/sessions?limit=5") == "sessions", "query ignored");
  expect(route_group("/api/ssh-guard/rules/x") == "ssh-guard", "dashed group");
  expect(route_group("/api/zzz-made-up") == "other", "unknown group folded");
  expect(route_group("/api/users-export") == "other", "prefix is not a group");
  expect(route_group("/proxy/7/") == "proxy", "web proxy");
  expect(route_group("/index.html") == "static", "spa");

  expect(status_class(204) == "2xx", "2xx");
  expect(status_class(503) == "5xx", "5xx");
  expect(status_class(42) == "other", "bogus code");

  expect(protocol_label("SSH") == "ssh", "protocol lower-cased");
  expect(protocol_label("gopher") == "other", "unknown protocol folded");

  auto ok = login_outcome("auth.login.success", "{\"authSource\":\"local\"}");
  expect(ok && ok->first == "password" && ok->second == "success", "local login");
  auto ldap = login_outcome("auth.login.success", "{\"authSource\":\"ldap\"}");
  expect(ldap && ldap->first == "ldap", "ldap login counted on the final event");
  expect(!login_outcome("auth.login.ldap.success", "{}"), "ldap first factor not counted");
  auto mfa = login_outcome("auth.login.2fa_failure", "");
  expect(mfa && mfa->first == "mfa" && mfa->second == "failure", "mfa failure");
  auto rl = login_outcome("auth.login.rate_limited", "");
  expect(rl && rl->second == "rate_limited", "rate limited");
  expect(!login_outcome("auth.logout", ""), "logout is not a login");

  expect(format_value(3) == "3", "integral value");
  expect(format_value(0.25) == "0.25", "fractional value");
}

void test_core_families_and_token_access() {
  metrics::Registry r;
  metrics::describe_core(r);
  const std::string out = r.render();
  expect(contains(out, "# TYPE endoriumfort_http_request_duration_seconds histogram"),
         "core histogram declared");
  expect(contains(out, "# TYPE endoriumfort_logins_total counter"), "logins declared");

  expect(api_tokens::is_grantable_scope("metrics.read"), "metrics.read grantable");
  expect(api_tokens::path_allowed("GET", "/api/metrics"), "token may scrape");
  expect(!api_tokens::path_allowed("POST", "/api/metrics"), "only GET");
}
}  // namespace

int main() {
  test_exposition();
  test_histogram();
  test_cardinality_cap();
  test_concurrency();
  test_collectors();
  test_vocabularies();
  test_core_families_and_token_access();
  if (failures) {
    std::cerr << failures << " metrics test(s) failed" << std::endl;
    return 1;
  }
  std::cout << "metrics tests passed" << std::endl;
  return 0;
}
