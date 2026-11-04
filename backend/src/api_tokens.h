#pragma once
// ─── EndoriumFort — API token policy ────────────────────────────────────────
// Pure rules behind personal API tokens: which permissions a token may carry,
// which endpoints it may reach, and source-address restrictions. Header-only
// and free of AppContext so the boundary can be unit-tested on its own; the
// storage lives in AppContext and the endpoints in api_token_routes.cc.
//
// A token acts for its owner, never beyond: a request authenticated by one is
// allowed only when the owner's role grants the permission AND the token's
// scope lists it. Interactive access (opening sessions, connecting, approving
// requests, MFA and password changes) is never reachable with a token.

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace api_tokens {

// Distinct from the "eft_" session tokens so the two can never be confused.
inline constexpr const char *kPrefix = "efapi_";
// Characters of the token kept in clear for display ("efapi_" + 8 hex).
inline constexpr size_t kDisplayPrefixLength = 14;
inline constexpr size_t kMaxNameLength = 64;
inline constexpr int kMaxTokensPerUser = 25;
inline constexpr int kDefaultMaxLifetimeDays = 365;
inline constexpr size_t kMaxAllowedCidrs = 16;

inline bool looks_like_api_token(const std::string &token) {
  return token.rfind(kPrefix, 0) == 0;
}

// Permissions a token may be scoped to. Everything that opens or drives an
// interactive session, or reviews four-eyes requests, is deliberately absent.
inline const std::vector<std::string> &grantable_scopes() {
  static const std::vector<std::string> scopes = {
      "users.read",        "users.manage",    "resources.read",
      "resources.manage",  "resources.assign", "sessions.read",
      "sessions.terminate", "audit.read",     "recordings.read",
      "stats.read",        "access_requests.read", "cluster.read",
      "cluster.manage",    "settings.manage", "metrics.read"};
  return scopes;
}

inline bool is_grantable_scope(const std::string &scope) {
  for (const auto &item : grantable_scopes())
    if (item == scope) return true;
  return false;
}

inline bool scope_allows(const std::vector<std::string> &scopes,
                         const std::string &permission) {
  for (const auto &item : scopes)
    if (item == permission) return true;
  return false;
}

inline std::string join_csv(const std::vector<std::string> &items) {
  std::string out;
  for (const auto &item : items) {
    if (!out.empty()) out += ',';
    out += item;
  }
  return out;
}

inline std::vector<std::string> split_csv(const std::string &csv) {
  std::vector<std::string> out;
  std::stringstream stream(csv);
  std::string item;
  while (std::getline(stream, item, ','))
    if (!item.empty()) out.push_back(item);
  return out;
}

// ── Endpoint boundary ───────────────────────────────────────────────────────

namespace detail {

// True when `path` is `prefix` itself or continues with a '/' after it, so
// "/api/users" does not also cover "/api/users-export".
inline bool under(const std::string &path, const std::string &prefix) {
  if (path.rfind(prefix, 0) != 0) return false;
  return path.size() == prefix.size() || path[prefix.size()] == '/';
}

inline std::vector<std::string> segments(const std::string &path) {
  std::vector<std::string> out;
  std::stringstream stream(path);
  std::string item;
  while (std::getline(stream, item, '/'))
    if (!item.empty()) out.push_back(item);
  return out;
}

inline bool is_number(const std::string &value) {
  if (value.empty()) return false;
  for (char c : value)
    if (c < '0' || c > '9') return false;
  return true;
}

}  // namespace detail

// Whether a token-authenticated request may reach this endpoint at all. The
// permission check inside the handler still applies on top. An allowlist, so
// an endpoint added later stays out of reach until someone decides otherwise.
inline bool path_allowed(const std::string &method, const std::string &raw_path) {
  std::string path = raw_path.substr(0, raw_path.find('?'));
  while (path.size() > 1 && path.back() == '/') path.pop_back();
  using detail::under;

  if (path == "/api/health" || path == "/api/license/status") return true;
  // Prometheus scrape; the handler still requires metrics.read.
  if (path == "/api/metrics") return method == "GET";

  // Sessions: read and terminate only — never open, stream, or move files.
  if (under(path, "/api/sessions")) {
    const auto parts = detail::segments(path);  // api, sessions, <id>, <verb>
    if (parts.size() == 2) return method == "GET";
    if (parts.size() == 3 && detail::is_number(parts[2])) return method == "GET";
    if (parts.size() == 4 && detail::is_number(parts[2])) {
      if (parts[3] == "terminate") return method == "POST";
      if (parts[3] == "dna") return method == "GET";
    }
    return false;
  }

  // Resources, except what hands out live access (one-time credentials, the
  // file-share directory of people allowed on a drive).
  if (under(path, "/api/resources")) {
    const auto parts = detail::segments(path);
    if (parts.size() >= 4 &&
        (parts[3] == "ephemeral-credentials" || parts[3] == "fileshare"))
      return false;
    return true;
  }

  // Access requests may be listed, never approved or denied: four-eyes review
  // stays a human decision.
  if (under(path, "/api/access-requests")) return method == "GET";

  static const char *const kAllowed[] = {
      "/api/users",           "/api/access-policies", "/api/access-profiles",
      "/api/access-grants",   "/api/audit",           "/api/reports",
      "/api/stats",           "/api/recordings",      "/api/ssh-guard",
      "/api/vault",           "/api/automation",      "/api/itdr",
      "/api/db-guard",
      "/api/security",        "/api/k8s/resources",   "/api/integrations/siem",
      "/api/evidence-packs",  "/api/cluster/status"};
  for (const char *prefix : kAllowed)
    if (under(path, prefix)) return true;
  return false;
}

// ── Source-address restriction ──────────────────────────────────────────────

inline std::optional<uint32_t> parse_ipv4(const std::string &text) {
  uint32_t value = 0;
  int octets = 0;
  size_t i = 0;
  while (i <= text.size()) {
    size_t end = text.find('.', i);
    if (end == std::string::npos) end = text.size();
    const std::string part = text.substr(i, end - i);
    if (part.empty() || part.size() > 3 || !detail::is_number(part)) return std::nullopt;
    const int octet = std::stoi(part);
    if (octet > 255) return std::nullopt;
    value = (value << 8) | static_cast<uint32_t>(octet);
    ++octets;
    i = end + 1;
    if (end == text.size()) break;
  }
  if (octets != 4) return std::nullopt;
  return value;
}

// Accepts "a.b.c.d" or "a.b.c.d/n" (IPv4), or a literal IPv6 address matched
// exactly. Returns false for anything else so bad input is refused, not ignored.
inline bool is_valid_cidr(const std::string &cidr) {
  const size_t slash = cidr.find('/');
  if (slash == std::string::npos) {
    if (parse_ipv4(cidr)) return true;
    return cidr.find(':') != std::string::npos && cidr.size() <= 45 &&
           cidr.find_first_not_of("0123456789abcdefABCDEF:.") == std::string::npos;
  }
  if (!parse_ipv4(cidr.substr(0, slash))) return false;
  const std::string bits = cidr.substr(slash + 1);
  return detail::is_number(bits) && bits.size() <= 2 && std::stoi(bits) <= 32;
}

inline bool ip_matches(const std::string &raw_ip, const std::string &cidr) {
  std::string ip = raw_ip;
  if (ip.rfind("::ffff:", 0) == 0 && ip.find('.') != std::string::npos)
    ip = ip.substr(7);  // IPv4-mapped IPv6, as Asio reports dual-stack peers
  const size_t slash = cidr.find('/');
  if (slash == std::string::npos) return ip == cidr;
  const auto net = parse_ipv4(cidr.substr(0, slash));
  const auto addr = parse_ipv4(ip);
  if (!net || !addr) return false;
  const int bits = std::stoi(cidr.substr(slash + 1));
  const uint32_t mask = bits == 0 ? 0 : (~uint32_t{0} << (32 - bits));
  return (*net & mask) == (*addr & mask);
}

// An empty list means "from anywhere".
inline bool ip_allowed(const std::string &ip,
                       const std::vector<std::string> &cidrs) {
  if (cidrs.empty()) return true;
  for (const auto &cidr : cidrs)
    if (ip_matches(ip, cidr)) return true;
  return false;
}

}  // namespace api_tokens
