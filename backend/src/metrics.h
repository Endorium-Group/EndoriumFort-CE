#pragma once
// ─── EndoriumFort — Prometheus metrics registry ─────────────────────────────
// A small, dependency-free, thread-safe registry of counters, gauges and
// histograms, rendered in the Prometheus text exposition format (0.0.4) by
// GET /api/metrics (metrics_routes.cc). Core, so the Community edition exposes
// its own metrics; the Enterprise modules add theirs through collectors, which
// therefore only appear when the module is compiled in.
//
// Labels never carry user names, targets or other free text from requests:
// every label value comes from a short, bounded vocabulary chosen at the call
// site, and each family is capped at kMaxSeriesPerFamily series as a last line
// of defence against a cardinality explosion.

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace metrics {

using Labels = std::vector<std::pair<std::string, std::string>>;
using Collector = std::function<void()>;

inline constexpr size_t kMaxSeriesPerFamily = 256;

enum class Type { Counter, Gauge, Histogram };

inline const char *type_name(Type type) {
  switch (type) {
    case Type::Counter: return "counter";
    case Type::Gauge: return "gauge";
    case Type::Histogram: return "histogram";
  }
  return "untyped";
}

// Seconds; covers a cached JSON answer up to a slow report or proxied page.
inline const std::vector<double> &default_duration_buckets() {
  static const std::vector<double> buckets = {0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
                                              0.5,   1,    2.5,   5,    10,  30};
  return buckets;
}

// ── Exposition-format helpers ───────────────────────────────────────────────

inline std::string escape_label_value(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  for (char c : value) {
    if (c == '\\') out += "\\\\";
    else if (c == '"') out += "\\\"";
    else if (c == '\n') out += "\\n";
    else out += c;
  }
  return out;
}

inline std::string escape_help(const std::string &value) {
  std::string out;
  for (char c : value) {
    if (c == '\\') out += "\\\\";
    else if (c == '\n') out += "\\n";
    else out += c;
  }
  return out;
}

inline std::string format_value(double value) {
  if (std::isnan(value)) return "NaN";
  if (std::isinf(value)) return value > 0 ? "+Inf" : "-Inf";
  if (value == std::floor(value) && std::fabs(value) < 1e15) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(value));
    return buf;
  }
  char buf[40];
  std::snprintf(buf, sizeof(buf), "%.10g", value);
  return buf;
}

// Labels sorted by name, so the same set always names the same series.
inline Labels normalize(Labels labels) {
  std::sort(labels.begin(), labels.end());
  return labels;
}

inline std::string render_labels(const Labels &labels,
                                 const std::pair<std::string, std::string> *extra = nullptr) {
  if (labels.empty() && !extra) return "";
  std::string out = "{";
  bool first = true;
  for (const auto &[name, value] : labels) {
    if (!first) out += ',';
    out += name + "=\"" + escape_label_value(value) + "\"";
    first = false;
  }
  if (extra) {
    if (!first) out += ',';
    out += extra->first + "=\"" + escape_label_value(extra->second) + "\"";
  }
  return out + "}";
}

// ── Registry ────────────────────────────────────────────────────────────────

class Registry {
 public:
  // Declare a family. Re-declaring is harmless; the first declaration wins.
  void describe(const std::string &name, Type type, const std::string &help,
                std::vector<double> buckets = {}) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (families_.count(name)) return;
    Family family;
    family.type = type;
    family.help = help;
    if (type == Type::Histogram) {
      family.buckets = buckets.empty() ? default_duration_buckets() : std::move(buckets);
      std::sort(family.buckets.begin(), family.buckets.end());
    }
    families_.emplace(name, std::move(family));
  }

  void inc(const std::string &name, const Labels &labels = {}, double by = 1) {
    if (by < 0) return;  // counters only go up
    std::lock_guard<std::mutex> lock(mutex_);
    if (auto *series = find_series(name, labels, Type::Counter)) series->value += by;
  }

  void set(const std::string &name, const Labels &labels, double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (auto *series = find_series(name, labels, Type::Gauge)) series->value = value;
  }

  void observe(const std::string &name, const Labels &labels, double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto fit = families_.find(name);
    if (fit == families_.end() || fit->second.type != Type::Histogram) return;
    auto *series = find_series(name, labels, Type::Histogram);
    if (!series) return;
    const auto &buckets = fit->second.buckets;
    if (series->bucket_counts.size() != buckets.size())
      series->bucket_counts.assign(buckets.size(), 0);
    for (size_t i = 0; i < buckets.size(); ++i)
      if (value <= buckets[i]) ++series->bucket_counts[i];
    series->count += 1;
    series->value += value;  // the _sum
  }

  // Drop every series of a gauge family, for collectors that rebuild a gauge
  // from current state (a relay that disappeared must stop being reported).
  void clear(const std::string &name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = families_.find(name);
    if (it != families_.end()) it->second.series.clear();
  }

  std::optional<double> value(const std::string &name, const Labels &labels = {}) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto fit = families_.find(name);
    if (fit == families_.end()) return std::nullopt;
    auto sit = fit->second.series.find(normalize(labels));
    if (sit == fit->second.series.end()) return std::nullopt;
    return sit->second.value;
  }

  // Run at each scrape, before rendering, to refresh gauges from live state.
  void add_collector(Collector collector) {
    std::lock_guard<std::mutex> lock(mutex_);
    collectors_.push_back(std::move(collector));
  }

  void collect() {
    std::vector<Collector> collectors;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      collectors = collectors_;
    }
    for (const auto &collector : collectors) collector();  // they take the lock
  }

  std::string render() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string out;
    for (const auto &[name, family] : families_) {
      out += "# HELP " + name + " " + escape_help(family.help) + "\n";
      out += "# TYPE " + name + " " + type_name(family.type) + "\n";
      for (const auto &[labels, series] : family.series) {
        if (family.type != Type::Histogram) {
          out += name + render_labels(labels) + " " + format_value(series.value) + "\n";
          continue;
        }
        uint64_t cumulative = 0;
        for (size_t i = 0; i < family.buckets.size(); ++i) {
          cumulative = i < series.bucket_counts.size() ? series.bucket_counts[i] : 0;
          const std::pair<std::string, std::string> le{"le", format_value(family.buckets[i])};
          out += name + "_bucket" + render_labels(labels, &le) + " " +
                 std::to_string(cumulative) + "\n";
        }
        const std::pair<std::string, std::string> inf{"le", "+Inf"};
        out += name + "_bucket" + render_labels(labels, &inf) + " " +
               std::to_string(series.count) + "\n";
        out += name + "_sum" + render_labels(labels) + " " + format_value(series.value) + "\n";
        out += name + "_count" + render_labels(labels) + " " +
               std::to_string(series.count) + "\n";
      }
    }
    return out;
  }

  uint64_t dropped_series() {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
  }

 private:
  struct Series {
    double value = 0;  // counter/gauge value, or histogram sum
    uint64_t count = 0;
    std::vector<uint64_t> bucket_counts;  // per bucket, already cumulative
  };
  struct Family {
    Type type = Type::Counter;
    std::string help;
    std::vector<double> buckets;
    std::map<Labels, Series> series;
  };

  // Caller holds mutex_. Null when the family is unknown, of another type, or
  // full — a full family drops new series rather than growing without bound.
  Series *find_series(const std::string &name, const Labels &labels, Type type) {
    auto fit = families_.find(name);
    if (fit == families_.end() || fit->second.type != type) return nullptr;
    auto &series = fit->second.series;
    Labels key = normalize(labels);
    auto sit = series.find(key);
    if (sit != series.end()) return &sit->second;
    if (series.size() >= kMaxSeriesPerFamily) {
      ++dropped_;
      return nullptr;
    }
    return &series.emplace(std::move(key), Series{}).first->second;
  }

  std::mutex mutex_;
  std::map<std::string, Family> families_;  // sorted: stable output
  std::vector<Collector> collectors_;
  uint64_t dropped_ = 0;
};

// The process-wide registry behind /api/metrics.
inline Registry &registry() {
  static Registry instance;
  return instance;
}

// ── Bounded label vocabularies ──────────────────────────────────────────────

// Session protocol, folded onto a fixed set.
inline std::string protocol_label(const std::string &protocol) {
  static const char *const kKnown[] = {"ssh", "rdp", "vnc", "http", "https",
                                       "k8s", "tunnel", "agent", "telnet",
                                       "postgres"};
  std::string lower;
  for (char c : protocol) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  for (const char *known : kKnown)
    if (lower == known) return lower;
  return "other";
}

// First path segment after /api/, from a fixed list; anything else is
// "other". Keeps request IDs and typos out of the series names.
inline std::string route_group(const std::string &raw_path) {
  const std::string path = raw_path.substr(0, raw_path.find('?'));
  if (path.rfind("/proxy/", 0) == 0) return "proxy";
  if (path.rfind("/ws/", 0) == 0) return "ws";
  if (path.rfind("/api/", 0) != 0) return "static";
  const size_t start = 5;
  const size_t end = path.find('/', start);
  const std::string segment = path.substr(start, end == std::string::npos ? std::string::npos : end - start);
  static const char *const kGroups[] = {
      "access-grants", "access-policies", "access-profiles", "access-requests",
      "agents",        "audit",           "auth",            "automation",
      "branding",      "cluster",         "devices",         "evidence-packs",
      "health",        "integrations",    "itdr",            "k8s",
      "license",       "metrics",         "rbi",             "recordings",
      "relay",         "relays",          "reports",         "resources",
      "scim",          "security",        "sessions",        "settings",
      "ssh-guard",     "stats",           "tokens",          "totp",
      "tunnel",        "users",           "vault",           "webauthn",
      "ws"};
  for (const char *group : kGroups)
    if (segment == group) return segment;
  return "other";
}

inline std::string status_class(int code) {
  if (code < 100 || code > 599) return "other";
  return std::to_string(code / 100) + "xx";
}

// Login outcome of an audit event, as {method, result}, or nothing when the
// event is not a final login outcome. auth.login.ldap.success is only the
// first factor: the login ends with auth.login.success (authSource "ldap").
inline std::optional<std::pair<std::string, std::string>> login_outcome(
    const std::string &type, const std::string &payload) {
  if (type == "auth.login.success") {
    const bool ldap = payload.find("\"authSource\":\"ldap\"") != std::string::npos;
    return std::make_pair(std::string(ldap ? "ldap" : "password"), std::string("success"));
  }
  if (type == "auth.login.failure") return std::make_pair(std::string("password"), std::string("failure"));
  if (type == "auth.login.2fa_failure") return std::make_pair(std::string("mfa"), std::string("failure"));
  if (type == "auth.login.rate_limited") return std::make_pair(std::string("password"), std::string("rate_limited"));
  if (type == "auth.login.ldap.failure") return std::make_pair(std::string("ldap"), std::string("failure"));
  if (type == "auth.login.sso.success") return std::make_pair(std::string("sso"), std::string("success"));
  if (type == "auth.login.sso.failure") return std::make_pair(std::string("sso"), std::string("failure"));
  return std::nullopt;
}

// ── Family names ────────────────────────────────────────────────────────────

inline constexpr const char *kSessionsActive = "endoriumfort_sessions_active";
inline constexpr const char *kSessionsTotal = "endoriumfort_sessions_total";
inline constexpr const char *kLoginsTotal = "endoriumfort_logins_total";
inline constexpr const char *kSshGuardBlocked = "endoriumfort_ssh_guard_blocked_total";
inline constexpr const char *kHttpRequests = "endoriumfort_http_requests_total";
inline constexpr const char *kHttpDuration = "endoriumfort_http_request_duration_seconds";
inline constexpr const char *kProxyUpstreamErrors = "endoriumfort_proxy_upstream_errors_total";
inline constexpr const char *kAccessRequestsPending = "endoriumfort_access_requests_pending";
inline constexpr const char *kRelayUp = "endoriumfort_relay_up";
inline constexpr const char *kClusterPeers = "endoriumfort_cluster_peers";
inline constexpr const char *kSchedulerLastSuccess =
    "endoriumfort_scheduler_job_last_success_timestamp_seconds";
inline constexpr const char *kLicenseExpiry = "endoriumfort_license_expiry_timestamp_seconds";
inline constexpr const char *kLicenseValid = "endoriumfort_license_valid";
inline constexpr const char *kBuildInfo = "endoriumfort_build_info";
inline constexpr const char *kStartTime = "endoriumfort_process_start_time_seconds";
inline constexpr const char *kDroppedSeries = "endoriumfort_metrics_dropped_series_total";

// Declares the core families. Idempotent; called once at start-up.
inline void describe_core(Registry &r = registry()) {
  r.describe(kSessionsActive, Type::Gauge, "Sessions currently active, by protocol.");
  r.describe(kSessionsTotal, Type::Counter,
             "Session openings and endings, by protocol and outcome (started, denied, failed, ended).");
  r.describe(kLoginsTotal, Type::Counter, "Login attempts, by method and result.");
  r.describe(kSshGuardBlocked, Type::Counter, "SSH commands blocked by the command guard.");
  r.describe(kHttpRequests, Type::Counter, "HTTP requests, by route group and status class.");
  r.describe(kHttpDuration, Type::Histogram, "HTTP request duration in seconds, by route group.");
  r.describe(kProxyUpstreamErrors, Type::Counter, "Web proxy requests that failed to reach the upstream.");
  r.describe(kLicenseExpiry, Type::Gauge, "License expiry (notAfter) as a Unix timestamp; absent without a license.");
  r.describe(kLicenseValid, Type::Gauge, "1 when a license is installed and valid, else 0.");
  r.describe(kBuildInfo, Type::Gauge, "Build information; the value is always 1.");
  r.describe(kStartTime, Type::Gauge, "Process start time as a Unix timestamp.");
  r.describe(kDroppedSeries, Type::Counter,
             "Series refused because a family reached its cardinality cap.");
}

}  // namespace metrics
