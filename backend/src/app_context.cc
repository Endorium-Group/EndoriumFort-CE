// ─── EndoriumFort — AppContext implementation ───────────────────────────

#include "app_context.h"
#include "crypto.h"
#include "utils.h"

#include <openssl/rand.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace {
std::string build_token_from_bytes(const unsigned char *bytes, size_t len) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string token;
  token.reserve(4 + len * 2);
  token = "eft_";
  for (size_t i = 0; i < len; ++i) {
    const unsigned char b = bytes[i];
    token.push_back(kHex[(b >> 4) & 0x0F]);
    token.push_back(kHex[b & 0x0F]);
  }
  return token;
}
}  // namespace

// ── Secure token generation (using /dev/urandom on Linux/macOS) ─────────

std::string AppContext::generate_token() {
#ifndef _WIN32
  unsigned char bytes[32];
  std::ifstream urandom("/dev/urandom", std::ios::binary);
  if (urandom.good()) {
    urandom.read(reinterpret_cast<char *>(bytes), sizeof(bytes));
    if (urandom.gcount() == sizeof(bytes)) {
      return build_token_from_bytes(bytes, sizeof(bytes));
    }
  }
#endif
  // Fallback (Windows or /dev/urandom failure)
  std::random_device rd;
  unsigned char fbytes[32];
  for (size_t i = 0; i < sizeof(fbytes); i += 4) {
    uint32_t val = rd();
    memcpy(fbytes + i, &val, std::min(sizeof(val), sizeof(fbytes) - i));
  }
  return build_token_from_bytes(fbytes, sizeof(fbytes));
}

// ── Rate limiting ───────────────────────────────────────────────────────

bool AppContext::check_rate_limit(const std::string &key) {
  std::lock_guard<std::mutex> lock(rate_limit_mutex);
  auto now = std::chrono::steady_clock::now();

  auto &entry = rate_limit_map[key];
  
  // Check if currently blocked due to exponential backoff
  if (entry.block_until > now) {
    return false;  // Still blocked
  }
  
  // Cleanup old entries (older than window)
  while (!entry.attempts.empty() &&
         (now - entry.attempts.front()) > rate_limit_window) {
    entry.attempts.pop();
  }

  if (static_cast<int>(entry.attempts.size()) >= rate_limit_max_attempts) {
    return false;  // Rate limited
  }

  entry.attempts.push(now);
  return true;
}

bool AppContext::is_login_blocked(const std::string &key) {
  std::lock_guard<std::mutex> lock(rate_limit_mutex);
  auto now = std::chrono::steady_clock::now();
  auto &entry = rate_limit_map[key];
  return entry.block_until > now;
}

void AppContext::record_failed_login_attempt(const std::string &key) {
  std::lock_guard<std::mutex> lock(rate_limit_mutex);
  auto now = std::chrono::steady_clock::now();
  
  auto &entry = rate_limit_map[key];
  entry.consecutive_failures++;
  entry.last_failure_time = now;
  
  // Exponential backoff once failures pile up. Below 10 there is no block: a
  // single typo must not lock out the user, nor everyone behind the same IP
  // (keys are per user and per IP). check_rate_limit still caps attempts.
  // 10-19 failures: 30 seconds
  // 20-29 failures: 5 minutes
  // 30+ failures: 30 minutes
  int backoff_seconds = 0;
  if (entry.consecutive_failures >= 30) {
    backoff_seconds = 1800;  // 30 minutes
  } else if (entry.consecutive_failures >= 20) {
    backoff_seconds = 300;   // 5 minutes
  } else if (entry.consecutive_failures >= 10) {
    backoff_seconds = 30;    // 30 seconds
  }

  if (backoff_seconds > 0) {
    entry.block_until = now + std::chrono::seconds(backoff_seconds);
  }
}

void AppContext::clear_login_attempts(const std::string &key) {
  std::lock_guard<std::mutex> lock(rate_limit_mutex);
  
  auto &entry = rate_limit_map[key];
  // Clear the attempt queue
  while (!entry.attempts.empty()) {
    entry.attempts.pop();
  }
  // Reset failure counter and blocks
  entry.consecutive_failures = 0;
  entry.block_until = std::chrono::steady_clock::now();  // Clear any block
}

int AppContext::get_consecutive_failures(const std::string &key) {
  std::lock_guard<std::mutex> lock(rate_limit_mutex);
  auto &entry = rate_limit_map[key];
  return entry.consecutive_failures;
}

int AppContext::record_anomaly_signal(const std::string &key,
                                      std::chrono::seconds window) {
  std::lock_guard<std::mutex> lock(anomaly_mutex);
  auto now = std::chrono::steady_clock::now();
  auto &signals = anomaly_signal_windows[key];
  while (!signals.empty() && (now - signals.front()) > window) {
    signals.pop();
  }
  signals.push(now);
  return static_cast<int>(signals.size());
}

bool AppContext::should_emit_anomaly_signal(const std::string &key,
                                            std::chrono::seconds cooldown) {
  std::lock_guard<std::mutex> lock(anomaly_mutex);
  auto now = std::chrono::steady_clock::now();
  auto it = anomaly_signal_cooldowns.find(key);
  if (it != anomaly_signal_cooldowns.end() && it->second > now) {
    return false;
  }
  anomaly_signal_cooldowns[key] = now + cooldown;
  return true;
}

void AppContext::clear_anomaly_signal(const std::string &key) {
  std::lock_guard<std::mutex> lock(anomaly_mutex);
  anomaly_signal_windows.erase(key);
  anomaly_signal_cooldowns.erase(key);
}


// ── SSRF protection ─────────────────────────────────────────────────────

bool is_blocked_ipv4_target(uint32_t ip, bool allow_loopback) {
  if ((ip >> 24) == 0) return true;                       // 0.0.0.0/8
  if ((ip >> 16) == 0xA9FE) return true;                  // 169.254.0.0/16
  if (!allow_loopback && (ip >> 24) == 127) return true;  // 127.0.0.0/8
  return false;
}

bool AppContext::is_safe_target(const std::string &raw_host, bool allow_loopback) {
  // Resolvers are case-insensitive, accept a trailing dot and bracketed IPv6,
  // so normalise before comparing or "LOCALHOST" / "localhost." slip through.
  std::string host = to_lower(trim_copy(raw_host));
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
    host = host.substr(1, host.size() - 2);
  while (!host.empty() && host.back() == '.') host.pop_back();
  if (host.empty()) return false;

  const auto ends_with = [&host](const std::string &suffix) {
    return host.size() >= suffix.size() &&
           host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0;
  };
  if (!allow_loopback && (host == "localhost" || ends_with(".localhost")))
    return false;

  // Block metadata endpoints (cloud providers)
  if (host == "metadata.google.internal" || host == "metadata.internal") {
    return false;
  }

#ifndef _WIN32
  // inet_aton (unlike inet_pton) takes every IPv4 spelling the resolver takes:
  // "127.1", "0x7f000001", "2130706433", "0177.0.0.1".
  struct in_addr addr;
  if (inet_aton(host.c_str(), &addr) == 1) {
    return !is_blocked_ipv4_target(ntohl(addr.s_addr), allow_loopback);
  }
  struct in6_addr addr6;
  if (inet_pton(AF_INET6, host.c_str(), &addr6) == 1) {
    const unsigned char *b = addr6.s6_addr;
    if (IN6_IS_ADDR_UNSPECIFIED(&addr6)) return false;
    if (IN6_IS_ADDR_LINKLOCAL(&addr6)) return false;
    if (IN6_IS_ADDR_LOOPBACK(&addr6)) return allow_loopback;
    // IPv4-mapped (::ffff:a.b.c.d) reaches the embedded IPv4 address.
    if (IN6_IS_ADDR_V4MAPPED(&addr6)) {
      const uint32_t ip = (uint32_t(b[12]) << 24) | (uint32_t(b[13]) << 16) |
                          (uint32_t(b[14]) << 8) | uint32_t(b[15]);
      return !is_blocked_ipv4_target(ip, allow_loopback);
    }
  }
#else
  if (host == "0.0.0.0" || host == "169.254.169.254" ||
      (!allow_loopback && (host == "127.0.0.1" || host == "::1")))
    return false;
#endif

  return true;
}

// ── Auth helpers ────────────────────────────────────────────────────────

std::optional<AuthSession> AppContext::find_auth(const crow::request &request) {
  auto token = extract_auth_token_from_request(request);

  if (!token) return std::nullopt;
  return find_auth_by_token(*token);
}

std::optional<AuthSession> AppContext::find_auth_by_token(
    const std::string &token) {
  if (token.empty()) return std::nullopt;
  AuthSession session;
  {
    std::lock_guard<std::mutex> lock(auth_mutex);
    auto it = auth_sessions.find(token);
    if (it == auth_sessions.end()) return std::nullopt;

    // Check expiration
    if (!it->second.expiresAt.empty() && it->second.expiresAt < now_utc()) {
      auth_sessions.erase(it);
      return std::nullopt;
    }
    session = it->second;
  }

  // The token only snapshots the identity at login: re-read the account so a
  // deleted user loses access and a role change (demotion) applies at once.
  // Checked after releasing auth_mutex so the two locks are never nested.
  std::optional<std::string> current_role;
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    auto user_it = users.find(session.userId);
    if (user_it != users.end() && user_it->second.username == session.user) {
      current_role = user_it->second.role;
      session.securitySetupPending =
          user_it->second.bootstrapPasswordChangeRequired ||
          user_it->second.bootstrapMfaRequired;
    }
  }
  if (!current_role) {
    invalidate_token(token);
    return std::nullopt;
  }
  if (*current_role != session.role) {
    session.role = *current_role;
    std::lock_guard<std::mutex> lock(auth_mutex);
    auto it = auth_sessions.find(token);
    if (it != auth_sessions.end()) it->second.role = session.role;
  }
  return session;
}

// ── Token management ────────────────────────────────────────────────────

bool AppContext::invalidate_token(const std::string &token) {
  std::lock_guard<std::mutex> lock(auth_mutex);
  return auth_sessions.erase(token) > 0;
}

void AppContext::invalidate_user_tokens(int user_id) {
  {
    std::lock_guard<std::mutex> lock(auth_mutex);
    for (auto it = auth_sessions.begin(); it != auth_sessions.end();) {
      if (it->second.userId == user_id)
        it = auth_sessions.erase(it);
      else
        ++it;
    }
  }
  // Account disable / containment / password change must also kill the agent's
  // tunnel credentials, otherwise a live tunnel would outlive the revocation.
  // Done after releasing auth_mutex so the two locks are never nested.
  invalidate_user_tunnel_credentials(user_id);
}

void AppContext::invalidate_user_tunnel_credentials(int user_id) {
  std::lock_guard<std::mutex> lock(tunnel_credential_mutex);
  for (auto it = tunnel_credentials.begin(); it != tunnel_credentials.end();) {
    if (it->second.userId == user_id)
      it = tunnel_credentials.erase(it);
    else
      ++it;
  }
}

void AppContext::invalidate_user_tokens_except(int user_id,
                                               const std::string &token) {
  std::lock_guard<std::mutex> lock(auth_mutex);
  for (auto it = auth_sessions.begin(); it != auth_sessions.end();) {
    if (it->second.userId == user_id && it->first != token)
      it = auth_sessions.erase(it);
    else
      ++it;
  }
}

void AppContext::cleanup_expired_tokens() {
  std::string current = now_utc();
  std::lock_guard<std::mutex> lock(auth_mutex);
  for (auto it = auth_sessions.begin(); it != auth_sessions.end();) {
    if (!it->second.expiresAt.empty() && it->second.expiresAt < current)
      it = auth_sessions.erase(it);
    else
      ++it;
  }
}

std::string AppContext::compute_expiry() {
  auto now = std::chrono::system_clock::now();
  auto expiry = now + std::chrono::seconds(token_ttl_seconds);
  std::time_t exp_time = std::chrono::system_clock::to_time_t(expiry);
  std::tm utc_tm{};
#ifdef _WIN32
  gmtime_s(&utc_tm, &exp_time);
#else
  gmtime_r(&exp_time, &utc_tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

// ── Graceful shutdown hooks ───────────────────────────────────────────────

void AppContext::register_shutdown_hook(std::function<void()> fn) {
  if (!fn) return;
  std::lock_guard<std::mutex> lock(shutdown_hooks_mutex);
  shutdown_hooks.push_back(std::move(fn));
}

void AppContext::run_shutdown_hooks() {
  std::vector<std::function<void()>> hooks;
  {
    std::lock_guard<std::mutex> lock(shutdown_hooks_mutex);
    hooks.swap(shutdown_hooks);
  }
  // Run in reverse registration order (teardown mirrors setup).
  for (auto it = hooks.rbegin(); it != hooks.rend(); ++it) {
    try {
      (*it)();
    } catch (...) {
      // Never let a teardown failure crash the shutdown path.
    }
  }
}

// ── Audit ───────────────────────────────────────────────────────────────

namespace {
// Keyed when an HMAC key is configured (forgery-resistant), otherwise a plain
// SHA-256 chain (detects edits/truncation by anyone without the prior state).
std::string audit_mac(const std::string &key, const std::string &input) {
  return key.empty() ? crypto::sha256_hex(input)
                     : crypto::hmac_sha256_hex(key, input);
}
constexpr char kAuditPrevMarker[] = ",\"prevHash\":\"";
constexpr char kAuditHashMarker[] = "\"hash\":\"";
}  // namespace

void AppContext::append_audit(const AuditEvent &event) {
  {
    std::lock_guard<std::mutex> lock(audit_mutex);
    audit_events.push_back(event);
    if (audit_events.size() > 200) {
      audit_events.erase(audit_events.begin(), audit_events.begin() + 50);
    }

    // Canonical entry object: the exact bytes re-hashed on verification.
    std::ostringstream body;
    body << '{'
         << "\"id\":" << event.id << ','
         << "\"type\":\"" << json_escape(event.type) << "\","
         << "\"actor\":\"" << json_escape(event.actor) << "\","
         << "\"role\":\"" << json_escape(event.role) << "\","
         << "\"createdAt\":\"" << json_escape(event.createdAt) << "\","
         << "\"payload\":"
         << (event.payloadIsJson ? event.payloadJson
                                 : "\"" + json_escape(event.payloadJson) + "\"")
         << '}';
    const std::string canonical = body.str();
    const std::string prev = audit_chain_hash;
    const std::string hash = audit_mac(audit_hmac_key, prev + "|" + canonical);

    {
      std::ofstream out(audit_path, std::ios::app);
      if (out) {
        // Reopen the canonical object (drop its closing brace) and append the
        // chain fields last, so a verifier recovers `canonical` as a literal
        // substring.
        out << canonical.substr(0, canonical.size() - 1) << kAuditPrevMarker
            << prev << "\"," << kAuditHashMarker << hash << "\"}\n";
      }
    }
    audit_chain_hash = hash;
    maybe_rotate_audit_locked();  // seal + purge per retention policy
  }
  // Outside the lock: the SIEM forwarder (premium) only queues the event.
  if (siem_forward) siem_forward(event);
}

void AppContext::maybe_rotate_audit_locked() {
  if (audit_max_file_bytes <= 0) return;
  struct stat st {};
  if (stat(audit_path.c_str(), &st) != 0) return;
  if (st.st_size < static_cast<off_t>(audit_max_file_bytes)) return;

  // Seal the current log as a timestamped archive. The in-memory chain head
  // (audit_chain_hash) is unchanged, so the next entry written to the fresh log
  // links back to this archive's last hash — cross-file tamper-evidence.
  const std::string archive =
      audit_path + "." + std::to_string(now_epoch_seconds());
  std::rename(audit_path.c_str(), archive.c_str());

  if (audit_retention_days <= 0) return;  // keep archives forever
  namespace fs = std::filesystem;
  const fs::path logp(audit_path);
  const fs::path dir = logp.has_parent_path() ? logp.parent_path() : fs::path(".");
  const std::string prefix = logp.filename().string() + ".";
  const int64_t cutoff =
      now_epoch_seconds() - static_cast<int64_t>(audit_retention_days) * 86400;
  std::error_code ec;
  for (fs::directory_iterator it(dir, ec), end; it != end && !ec;
       it.increment(ec)) {
    const std::string name = it->path().filename().string();
    if (name.rfind(prefix, 0) != 0) continue;
    int64_t sealed = 0;
    try {
      sealed = std::stoll(name.substr(prefix.size()));
    } catch (...) {
      continue;  // not one of our epoch-suffixed archives
    }
    if (sealed < cutoff) {
      std::error_code rm_ec;
      fs::remove(it->path(), rm_ec);
    }
  }
}

void AppContext::init_audit_chain() {
  const char *k = std::getenv("ENDORIUMFORT_AUDIT_HMAC_KEY");
  if (k && *k) {
    std::string raw;
    // Accept either a hex-encoded key or a raw passphrase.
    if (crypto::hex_decode(k, raw) && !raw.empty()) {
      audit_hmac_key = raw;
    } else {
      audit_hmac_key.assign(k);
    }
  }

  std::lock_guard<std::mutex> lock(audit_mutex);
  audit_chain_hash = "GENESIS";
  std::ifstream in(audit_path, std::ios::binary);
  if (!in) return;
  std::string line, last_hash;
  const std::string marker = kAuditHashMarker;
  while (std::getline(in, line)) {
    const size_t p = line.rfind(marker);
    if (p == std::string::npos) continue;
    const size_t s = p + marker.size();
    const size_t e = line.find('"', s);
    if (e != std::string::npos) last_hash = line.substr(s, e - s);
  }
  if (!last_hash.empty()) audit_chain_hash = last_hash;
}

std::vector<std::string> AppContext::collect_audit_lines_for_actor(
    const std::string &actor, size_t max_lines) {
  std::vector<std::string> out;
  if (actor.empty()) return out;
  const std::string needle = "\"actor\":\"" + json_escape(actor) + "\"";
  std::lock_guard<std::mutex> lock(audit_mutex);
  std::ifstream in(audit_path, std::ios::binary);
  if (!in) return out;
  std::string line;
  while (std::getline(in, line)) {
    if (line.find(needle) != std::string::npos) out.push_back(line);
  }
  // Most recent first, capped.
  std::reverse(out.begin(), out.end());
  if (out.size() > max_lines) out.resize(max_lines);
  return out;
}

int AppContext::register_user_device(const UserDevice &device) {
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  if (!sqlite.is_open()) return -1;
  const std::string now = now_utc();

  // Upsert on (user_id, push_token): re-registering the same device refreshes it
  // rather than creating duplicates.
  auto stmt = sqlite.prepare(
      "INSERT INTO user_devices "
      "(user_id, platform, label, push_provider, push_token, public_key, "
      " created_at, last_seen_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?7) "
      "ON CONFLICT(user_id, push_token) DO UPDATE SET "
      "platform=excluded.platform, label=excluded.label, "
      "push_provider=excluded.push_provider, public_key=excluded.public_key, "
      "last_seen_at=excluded.last_seen_at;");
  if (!stmt) return -1;
  stmt.bind_int(1, device.userId);
  stmt.bind_text(2, device.platform);
  stmt.bind_text(3, device.label);
  stmt.bind_text(4, device.pushProvider);
  stmt.bind_text(5, device.pushToken);
  stmt.bind_text(6, device.publicKey);
  stmt.bind_text(7, now);
  if (!stmt.execute()) return -1;

  // Resolve the row id (works for both insert and upsert paths).
  auto idq = sqlite.prepare(
      "SELECT id FROM user_devices WHERE user_id=?1 AND push_token=?2;");
  if (!idq) return -1;
  idq.bind_int(1, device.userId);
  idq.bind_text(2, device.pushToken);
  if (!idq.step()) return -1;
  return idq.column_int(0);
}

std::vector<UserDevice> AppContext::list_user_devices(int user_id) {
  std::vector<UserDevice> out;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  if (!sqlite.is_open()) return out;
  auto stmt = sqlite.prepare(
      "SELECT id, user_id, platform, label, push_provider, push_token, "
      "public_key, created_at, last_seen_at FROM user_devices "
      "WHERE user_id=?1 ORDER BY id;");
  if (!stmt) return out;
  stmt.bind_int(1, user_id);
  while (stmt.step()) {
    UserDevice d;
    d.id = stmt.column_int(0);
    d.userId = stmt.column_int(1);
    d.platform = stmt.column_text(2);
    d.label = stmt.column_text(3);
    d.pushProvider = stmt.column_text(4);
    d.pushToken = stmt.column_text(5);
    d.publicKey = stmt.column_text(6);
    d.createdAt = stmt.column_text(7);
    d.lastSeenAt = stmt.column_text(8);
    out.push_back(std::move(d));
  }
  return out;
}

namespace {
// base64url (and base64) decode → raw bytes; empty on invalid input.
std::string b64url_decode(const std::string &in) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
  };
  std::string out;
  int buf = 0, bits = 0;
  for (char c : in) {
    if (c == '=' || c == '\n' || c == '\r') continue;
    const int v = val(c);
    if (v < 0) return {};
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buf >> bits) & 0xFF));
    }
  }
  return out;
}
}  // namespace

bool AppContext::verify_device_signature(int user_id, int device_id,
                                         const std::string &message,
                                         const std::string &signature_b64url) {
  if (message.empty() || signature_b64url.empty()) return false;

  std::string pubkey_b64;
  {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    if (!sqlite.is_open()) return false;
    auto stmt = sqlite.prepare(
        "SELECT public_key FROM user_devices WHERE id=?1 AND user_id=?2;");
    if (stmt) {
      stmt.bind_int(1, device_id);
      stmt.bind_int(2, user_id);
      if (stmt.step()) pubkey_b64 = stmt.column_text(0);
    }
  }
  if (pubkey_b64.empty()) return false;

  const std::string spki = b64url_decode(pubkey_b64);
  const std::string sig = b64url_decode(signature_b64url);
  if (spki.empty() || sig.empty()) return false;

  const unsigned char *p = reinterpret_cast<const unsigned char *>(spki.data());
  EVP_PKEY *pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size()));
  if (!pkey) return false;

  bool ok = false;
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx) {
    // Ed25519 verifies with a null digest; EC (ES256) / RSA use SHA-256.
    const EVP_MD *md =
        (EVP_PKEY_id(pkey) == EVP_PKEY_ED25519) ? nullptr : EVP_sha256();
    if (EVP_DigestVerifyInit(mdctx, nullptr, md, nullptr, pkey) == 1) {
      ok = EVP_DigestVerify(
               mdctx, reinterpret_cast<const unsigned char *>(sig.data()),
               sig.size(),
               reinterpret_cast<const unsigned char *>(message.data()),
               message.size()) == 1;
    }
    EVP_MD_CTX_free(mdctx);
  }
  EVP_PKEY_free(pkey);
  return ok;
}

bool AppContext::delete_user_device(int user_id, int device_id) {
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  if (!sqlite.is_open()) return false;
  // Scoped to the owner so one user cannot delete another's device.
  auto stmt =
      sqlite.prepare("DELETE FROM user_devices WHERE id=?1 AND user_id=?2;");
  if (!stmt) return false;
  stmt.bind_int(1, device_id);
  stmt.bind_int(2, user_id);
  const bool ok = stmt.execute();
  return ok && sqlite.changes() > 0;
}

AppContext::AuditChainCheck AppContext::verify_audit_chain() {
  AuditChainCheck res;
  std::lock_guard<std::mutex> lock(audit_mutex);
  std::ifstream in(audit_path, std::ios::binary);
  if (!in) return res;  // no log yet → trivially intact

  std::string prev;
  bool first = true;
  std::string line;
  int64_t n = 0;
  const std::string pmark = kAuditPrevMarker;
  const std::string hmark = kAuditHashMarker;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    ++n;
    const size_t pp = line.rfind(pmark);
    const size_t hp = line.rfind(hmark);
    if (pp == std::string::npos || hp == std::string::npos || hp < pp) {
      // Before the first chained line: legacy log from an older version.
      // After it: a line slipped into the chain, which is tampering.
      if (first) {
        ++res.legacyLines;
      } else if (res.ok) {
        res.ok = false;
        res.firstBrokenLine = n;
      }
      continue;
    }
    const std::string canonical = line.substr(0, pp) + "}";
    const size_t pvs = pp + pmark.size();
    const size_t pve = line.find('"', pvs);
    const size_t hvs = hp + hmark.size();
    const size_t hve = line.find('"', hvs);
    if (pve == std::string::npos || hve == std::string::npos) {
      if (res.ok) { res.ok = false; res.firstBrokenLine = n; }
      continue;
    }
    const std::string line_prev = line.substr(pvs, pve - pvs);
    const std::string line_hash = line.substr(hvs, hve - hvs);
    // The first line's prevHash is the baseline (it links to the previous
    // archive after a rotation, or is GENESIS on a fresh log); we don't compare
    // it, only enforce linkage between consecutive lines in this file.
    if (first) {
      prev = line_prev;
      first = false;
    }
    const std::string expect =
        audit_mac(audit_hmac_key, line_prev + "|" + canonical);
    if (line_prev != prev || line_hash != expect) {
      if (res.ok) { res.ok = false; res.firstBrokenLine = n; }
    }
    prev = line_hash;
  }
  res.lines = n;
  return res;
}

void AppContext::append_session_event(const std::string &type,
                                     const Session &session) {
  SessionEvent event;
  event.id = next_event_id.fetch_add(1);
  event.type = type;
  event.createdAt = now_utc();
  event.payloadJson = build_session_payload_json(session);
  std::lock_guard<std::mutex> lock(event_mutex);
  session_events.push_back(event);
  if (session_events.size() > 200) {
    session_events.erase(session_events.begin(), session_events.begin() + 50);
  }
}

// ── Database initialization ─────────────────────────────────────────────

void AppContext::init_database(const std::string &path) {
  std::string err;
  // ENDORIUMFORT_DB_DSN selects the store: a "postgresql://" URI uses the
  // PostgreSQL backend (production, lets several nodes share one database),
  // anything else is a SQLite file path. Defaults to `path` (the embedded file)
  // so an existing single-node install keeps working untouched.
  const char *dsn_env = std::getenv("ENDORIUMFORT_DB_DSN");
  const std::string dsn = (dsn_env && *dsn_env) ? std::string(dsn_env) : path;
  if (!sqlite.open(dsn, err)) {
    // Fail closed. A bastion with no database has no users, no resource
    // permissions and no audit trail; carrying on would be far worse than not
    // starting. Container restart policies retry this, which is also how a
    // PostgreSQL server that is not up yet resolves itself.
    std::cerr << "FATAL: database open failed: " << err << '\n';
    std::exit(1);
  }
  std::cerr << "[config] database backend="
            << (sqlite.backend() == db::Backend::Postgres ? "postgresql" : "sqlite")
            << '\n';

  // License runtime state: clock watermark (anti-rollback) + CRL sequence.
  const std::string license_state_schema =
      "CREATE TABLE IF NOT EXISTS license_state ("
      "k TEXT PRIMARY KEY,"
      "v INTEGER NOT NULL"
      ");";
  if (!sqlite.exec(license_state_schema, err))
    std::cerr << "SQLite license_state schema failed: " << err << '\n';

  // Automation scheduler (premium): recurring/one-shot background jobs.
  // The table lives in the core schema so the DB is edition-agnostic, but the
  // engine that runs the jobs is compiled only in the Enterprise build (pro/).
  const std::string scheduled_jobs_schema =
      "CREATE TABLE IF NOT EXISTS scheduled_jobs ("
      "id " + sqlite.autoinc_pk() + ","
      "name TEXT NOT NULL UNIQUE,"
      "kind TEXT NOT NULL,"
      "feature TEXT NOT NULL DEFAULT 'automation.scheduler',"
      "interval_seconds INTEGER NOT NULL DEFAULT 0,"
      "enabled INTEGER NOT NULL DEFAULT 1,"
      "next_run_epoch INTEGER NOT NULL DEFAULT 0,"
      "last_run_epoch INTEGER NOT NULL DEFAULT 0,"
      "last_status TEXT NOT NULL DEFAULT '',"
      "last_detail TEXT NOT NULL DEFAULT '',"
      "run_count INTEGER NOT NULL DEFAULT 0,"
      "fail_count INTEGER NOT NULL DEFAULT 0,"
      "payload_json TEXT NOT NULL DEFAULT '',"
      "created_at TEXT NOT NULL DEFAULT ''"
      ");";
  if (!sqlite.exec(scheduled_jobs_schema, err))
    std::cerr << "SQLite scheduled_jobs schema failed: " << err << '\n';

  const std::string session_schema =
      "CREATE TABLE IF NOT EXISTS sessions ("
      "id " + sqlite.autoinc_pk() + ","
      "resource_id INTEGER DEFAULT 0,"
      "access_grant_id INTEGER DEFAULT 0,"
      "target TEXT NOT NULL,"
      "\"user\" TEXT NOT NULL,"  // quoted: reserved word in PostgreSQL
      "protocol TEXT NOT NULL,"
      "port INTEGER NOT NULL DEFAULT 22,"
      "status TEXT NOT NULL,"
      "mission_ref TEXT,"
      "credential_source TEXT DEFAULT 'vaulted',"
      "max_duration_seconds INTEGER DEFAULT 0,"
      "created_at TEXT NOT NULL,"
      "terminated_at TEXT"
      ");";
  if (!sqlite.exec(session_schema, err))
    std::cerr << "SQLite schema failed: " << err << '\n';
  sqlite.exec("ALTER TABLE sessions ADD COLUMN port INTEGER DEFAULT 22;", err);
  sqlite.exec("ALTER TABLE sessions ADD COLUMN resource_id INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE sessions ADD COLUMN access_grant_id INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE sessions ADD COLUMN mission_ref TEXT;", err);
  sqlite.exec("ALTER TABLE sessions ADD COLUMN credential_source TEXT DEFAULT 'vaulted';", err);
  sqlite.exec("ALTER TABLE sessions ADD COLUMN max_duration_seconds INTEGER DEFAULT 0;", err);

  const std::string resource_schema =
      "CREATE TABLE IF NOT EXISTS resources ("
      "id " + sqlite.autoinc_pk() + ","
      "name TEXT NOT NULL,"
      "target TEXT NOT NULL,"
      "protocol TEXT NOT NULL,"
      "port INTEGER NOT NULL DEFAULT 22,"
      "description TEXT,"
      "image_url TEXT,"
      "image_data TEXT,"
      "created_at TEXT NOT NULL,"
      "updated_at TEXT NOT NULL"
      ");";
  if (!sqlite.exec(resource_schema, err))
    std::cerr << "SQLite resource schema failed: " << err << '\n';
  sqlite.exec("ALTER TABLE resources ADD COLUMN image_url TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN image_data TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN http_username TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN http_password TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN ssh_username TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN ssh_password TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN agent_protocol TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN require_access_justification INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN require_dual_approval INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN enable_command_guard INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN adaptive_access_policy INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN risk_level TEXT DEFAULT 'low';", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN tunnel_ticket_rate_limit_max_attempts INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN tags_csv TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN credential_source TEXT DEFAULT 'vaulted';", err);

  const std::string user_schema =
      "CREATE TABLE IF NOT EXISTS users ("
      "id " + sqlite.autoinc_pk() + ","
      "username TEXT NOT NULL UNIQUE,"
      "password TEXT NOT NULL,"
      "role TEXT NOT NULL,"
      "created_at TEXT NOT NULL,"
      "updated_at TEXT NOT NULL"
      ");";
  if (!sqlite.exec(user_schema, err))
    std::cerr << "SQLite user schema failed: " << err << '\n';

  const std::string perm_schema =
      "CREATE TABLE IF NOT EXISTS user_resource_permissions ("
      "id " + sqlite.autoinc_pk() + ","
      "user_id INTEGER NOT NULL,"
      "resource_id INTEGER NOT NULL,"
      "created_at TEXT NOT NULL,"
      "FOREIGN KEY (user_id) REFERENCES users(id),"
      "FOREIGN KEY (resource_id) REFERENCES resources(id),"
      "UNIQUE(user_id, resource_id)"
      ");";
  if (!sqlite.exec(perm_schema, err))
    std::cerr << "SQLite user_resource_permissions schema failed: " << err << '\n';
  sqlite.exec("DROP TABLE IF EXISTS user_permission_overrides;", err);

  // Session recordings table
  const std::string rec_schema =
      "CREATE TABLE IF NOT EXISTS session_recordings ("
      "id " + sqlite.autoinc_pk() + ","
      "session_id INTEGER NOT NULL,"
      "file_path TEXT NOT NULL,"
      "created_at TEXT NOT NULL,"
      "closed_at TEXT,"
      "duration_ms INTEGER DEFAULT 0,"
      "file_size INTEGER DEFAULT 0,"
      "FOREIGN KEY (session_id) REFERENCES sessions(id)"
      ");";
  if (!sqlite.exec(rec_schema, err))
    std::cerr << "SQLite session_recordings schema failed: " << err << '\n';

  const std::string session_dna_schema =
      "CREATE TABLE IF NOT EXISTS session_dna_chain ("
      "id " + sqlite.autoinc_pk() + ","
      "session_id INTEGER NOT NULL,"
      "audit_event_id INTEGER NOT NULL,"
      "event_type TEXT NOT NULL,"
      "created_at TEXT NOT NULL,"
      "prev_hash TEXT NOT NULL,"
      "payload_hash TEXT NOT NULL,"
      "chain_hash TEXT NOT NULL,"
      "FOREIGN KEY (session_id) REFERENCES sessions(id)"
      ");";
  if (!sqlite.exec(session_dna_schema, err))
    std::cerr << "SQLite session_dna_chain schema failed: " << err << '\n';

  const std::string access_req_schema =
      "CREATE TABLE IF NOT EXISTS access_requests ("
      "id " + sqlite.autoinc_pk() + ","
      "resource_id INTEGER NOT NULL,"
      "resource_name TEXT,"
      "requester TEXT NOT NULL,"
      "requester_role TEXT NOT NULL,"
      "status TEXT NOT NULL,"
      "justification TEXT,"
      "ticket_id TEXT,"
      "created_at TEXT NOT NULL,"
      "reviewed_at TEXT,"
      "reviewed_by TEXT"
      ");";
  if (!sqlite.exec(access_req_schema, err))
    std::cerr << "SQLite access_requests schema failed: " << err << '\n';

  const std::string behavior_schema =
      "CREATE TABLE IF NOT EXISTS user_behavior_stats ("
      "username TEXT PRIMARY KEY,"
      "total_sessions INTEGER NOT NULL DEFAULT 0,"
      "total_duration_ms INTEGER NOT NULL DEFAULT 0,"
      "total_input_events INTEGER NOT NULL DEFAULT 0,"
      "updated_at TEXT NOT NULL"
      ");";
  if (!sqlite.exec(behavior_schema, err))
    std::cerr << "SQLite user_behavior_stats schema failed: " << err << '\n';

  const std::string ephemeral_schema =
      "CREATE TABLE IF NOT EXISTS ephemeral_credentials ("
      "id " + sqlite.autoinc_pk() + ","
      "resource_id INTEGER NOT NULL,"
      "requester TEXT NOT NULL,"
      "username TEXT NOT NULL,"
      "status TEXT NOT NULL,"
      "issued_at TEXT NOT NULL,"
      "expires_at TEXT NOT NULL,"
      "used_at TEXT"
      ");";
  if (!sqlite.exec(ephemeral_schema, err))
    std::cerr << "SQLite ephemeral_credentials schema failed: " << err << '\n';

  const std::string access_policy_schema =
      "CREATE TABLE IF NOT EXISTS access_policies ("
      "id " + sqlite.autoinc_pk() + ","
      "name TEXT NOT NULL,"
      "description TEXT,"
      "identity_pattern TEXT,"
      "group_name TEXT,"
      "role TEXT,"
      "resource_tags_csv TEXT,"
      "risk_level TEXT DEFAULT 'any',"
      "ticket_required INTEGER DEFAULT 0,"
      "require_justification INTEGER DEFAULT 0,"
      "approval_mode TEXT DEFAULT 'inherit',"
      "mfa_requirement TEXT DEFAULT 'any',"
      "time_window TEXT DEFAULT 'any',"
      "max_duration_seconds INTEGER DEFAULT 3600,"
      "routing_constraint TEXT DEFAULT 'any',"
      "enabled INTEGER DEFAULT 1,"
      "created_at TEXT NOT NULL,"
      "updated_at TEXT NOT NULL"
      ");";
  if (!sqlite.exec(access_policy_schema, err))
    std::cerr << "SQLite access_policies schema failed: " << err << '\n';

  const std::string access_profile_schema =
      "CREATE TABLE IF NOT EXISTS access_profiles ("
      "id " + sqlite.autoinc_pk() + ","
      "name TEXT NOT NULL,"
      "description TEXT,"
      "resource_tags_csv TEXT,"
      "resource_ids_csv TEXT,"
      "policy_id INTEGER DEFAULT 0,"
      "created_at TEXT NOT NULL,"
      "updated_at TEXT NOT NULL"
      ");";
  if (!sqlite.exec(access_profile_schema, err))
    std::cerr << "SQLite access_profiles schema failed: " << err << '\n';

  const std::string user_access_profile_schema =
      "CREATE TABLE IF NOT EXISTS user_access_profiles ("
      "id " + sqlite.autoinc_pk() + ","
      "user_id INTEGER NOT NULL,"
      "profile_id INTEGER NOT NULL,"
      "created_at TEXT NOT NULL,"
      "UNIQUE(user_id, profile_id)"
      ");";
  if (!sqlite.exec(user_access_profile_schema, err))
    std::cerr << "SQLite user_access_profiles schema failed: " << err << '\n';

  const std::string access_grant_schema =
      "CREATE TABLE IF NOT EXISTS access_grants ("
      "id " + sqlite.autoinc_pk() + ","
      "policy_id INTEGER DEFAULT 0,"
      "profile_id INTEGER DEFAULT 0,"
      "resource_id INTEGER NOT NULL,"
      "session_id INTEGER DEFAULT 0,"
      "approval_ref INTEGER DEFAULT 0,"
      "subject TEXT NOT NULL,"
      "resource_scope TEXT NOT NULL,"
      "granted_at TEXT NOT NULL,"
      "expires_at TEXT NOT NULL,"
      "used_at TEXT,"
      "mission_ref TEXT,"
      "elevation_scope TEXT,"
      "status TEXT NOT NULL DEFAULT 'issued',"
      "credential_source TEXT DEFAULT 'vaulted',"
      "routing_constraint TEXT DEFAULT 'any',"
      "ticket_id TEXT,"
      "purpose TEXT,"
      "justification TEXT,"
      "mfa_requirement TEXT DEFAULT 'any'"
      ");";
  if (!sqlite.exec(access_grant_schema, err))
    std::cerr << "SQLite access_grants schema failed: " << err << '\n';

  // TOTP columns on users
  sqlite.exec("ALTER TABLE users ADD COLUMN bootstrap_password_change_required INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE users ADD COLUMN bootstrap_mfa_required INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE users ADD COLUMN totp_secret TEXT;", err);
  sqlite.exec("ALTER TABLE users ADD COLUMN preferred_mfa_method TEXT DEFAULT 'any';", err);

  const std::string webauthn_schema =
      "CREATE TABLE IF NOT EXISTS user_webauthn_credentials ("
      "id " + sqlite.autoinc_pk() + ","
      "user_id INTEGER NOT NULL,"
      "credential_id TEXT NOT NULL UNIQUE,"
      "public_key_spki TEXT NOT NULL,"
      "sign_count INTEGER NOT NULL DEFAULT 0,"
      "label TEXT,"
      "transports_csv TEXT,"
      "created_at TEXT NOT NULL,"
      "last_used_at TEXT,"
      "FOREIGN KEY (user_id) REFERENCES users(id)"
      ");";
  if (!sqlite.exec(webauthn_schema, err))
    std::cerr << "SQLite user_webauthn_credentials schema failed: " << err << '\n';

  // Password reuse history (PCI DSS v4 8.3.7 / ANSSI). Stores prior password
  // hashes per user so a new password can be checked against the last N.
  const std::string password_history_schema =
      "CREATE TABLE IF NOT EXISTS password_history ("
      "id " + sqlite.autoinc_pk() + ","
      "user_id INTEGER NOT NULL,"
      "password_hash TEXT NOT NULL,"
      "created_at TEXT NOT NULL"
      ");";
  if (!sqlite.exec(password_history_schema, err))
    std::cerr << "SQLite password_history schema failed: " << err << '\n';
  sqlite.exec(
      "CREATE INDEX IF NOT EXISTS idx_password_history_user "
      "ON password_history(user_id);",
      err);

  // Registered mobile devices (push notifications + signed approvals).
  const std::string user_devices_schema =
      "CREATE TABLE IF NOT EXISTS user_devices ("
      "id " + sqlite.autoinc_pk() + ","
      "user_id INTEGER NOT NULL,"
      "platform TEXT NOT NULL,"
      "label TEXT,"
      "push_provider TEXT,"
      "push_token TEXT,"
      "public_key TEXT,"
      "created_at TEXT NOT NULL,"
      "last_seen_at TEXT,"
      "UNIQUE(user_id, push_token)"
      ");";
  if (!sqlite.exec(user_devices_schema, err))
    std::cerr << "SQLite user_devices schema failed: " << err << '\n';

  // Integration configuration set from the admin console. It shadows the
  // matching environment variable (see settings.h); a secret is stored
  // encrypted with the vault key, which is why the row carries the flag rather
  // than the caller guessing from the key name.
  const std::string integration_settings_schema =
      "CREATE TABLE IF NOT EXISTS integration_settings ("
      "key TEXT PRIMARY KEY,"
      "value TEXT NOT NULL,"
      "is_secret INTEGER NOT NULL DEFAULT 0,"
      "updated_at TEXT NOT NULL,"
      "updated_by TEXT"
      ");";
  if (!sqlite.exec(integration_settings_schema, err))
    std::cerr << "SQLite integration_settings schema failed: " << err << '\n';

  // Seed the tamper-evident audit chain head from the existing log tail.
  init_audit_chain();

  // Seed the tamper-evident audit chain head from the existing log tail.
  init_audit_chain();

  // Load data into memory
  load_sessions_from_db();
  load_resources_from_db();
  load_users_from_db();
  load_webauthn_credentials_from_db();
  load_recordings_from_db();
  load_access_requests_from_db();
  load_ephemeral_credentials_from_db();

  // Grants left behind by deletes from older versions (which did not cascade)
  // would attach to whichever account or resource reuses the id: purge them.
  if (sqlite.is_open()) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    std::string purge_err;
    for (const char *sql :
         {"DELETE FROM user_resource_permissions WHERE "
          "user_id NOT IN (SELECT id FROM users) OR "
          "resource_id NOT IN (SELECT id FROM resources);",
          "DELETE FROM user_access_profiles WHERE "
          "user_id NOT IN (SELECT id FROM users);"}) {
      if (!sqlite.exec(sql, purge_err))
        std::cerr << "SQLite orphan grant purge failed: " << purge_err << '\n';
    }
  }
}

void AppContext::seed_default_admin() {
  std::lock_guard<std::mutex> lock(user_mutex);
  if (!users.empty()) return;

  UserAccount admin;
  admin.id = next_user_id.fetch_add(1);
  admin.username = "admin";
  admin.password = crypto::hash_password("Admin123");
  admin.role = "admin";
  admin.createdAt = now_utc();
  admin.updatedAt = admin.createdAt;
  admin.bootstrapPasswordChangeRequired = true;
  admin.bootstrapMfaRequired = true;
  users[admin.id] = admin;
  if (!insert_user(admin))
    std::cerr << "Failed to persist default admin user" << '\n';
  else
    std::cerr << "[SECURITY] Default admin created — change password immediately!" << '\n';
}

// ── Session CRUD ────────────────────────────────────────────────────────

void AppContext::load_sessions_from_db() {
  if (!sqlite.is_open()) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "SELECT id, resource_id, access_grant_id, target, \"user\", protocol, port, "
      "status, mission_ref, credential_source, max_duration_seconds, "
      "created_at, terminated_at FROM sessions");
  if (!stmt) {
    std::cerr << "SQLite select failed: " << sqlite.last_error() << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(session_mutex);
    while (stmt.step()) {
      Session s;
      s.id = stmt.column_int(0);
      s.resourceId = stmt.column_int(1);
      s.accessGrantId = stmt.column_int(2);
      s.target = stmt.column_text(3);
      s.user = stmt.column_text(4);
      s.protocol = stmt.column_text(5);
      s.port = stmt.column_int(6);
      if (s.port <= 0) s.port = 22;
      s.status = stmt.column_text(7);
      stmt.column_text_into(8, s.missionRef);
      stmt.column_text_into(9, s.credentialSource);
      if (s.credentialSource.empty()) s.credentialSource = "vaulted";
      s.maxDurationSeconds = stmt.column_int(10);
      s.createdAt = stmt.column_text(11);
      stmt.column_text_into(12, s.terminatedAt);
      sessions[s.id] = s;
      if (s.id > max_id) max_id = s.id;
    }
  }
  if (max_id > 0) next_session_id.store(max_id + 1);
}

bool AppContext::insert_session(const Session &session) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "INSERT INTO sessions (id, resource_id, access_grant_id, target, \"user\", "
      "protocol, status, port, mission_ref, credential_source, "
      "max_duration_seconds, created_at, terminated_at) "
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)");
  if (!stmt) {
    std::cerr << "SQLite insert prepare failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, session.id);
  stmt.bind_int(2, session.resourceId);
  stmt.bind_int(3, session.accessGrantId);
  stmt.bind_text(4, session.target);
  stmt.bind_text(5, session.user);
  stmt.bind_text(6, session.protocol);
  stmt.bind_text(7, session.status);
  stmt.bind_int(8, session.port);
  stmt.bind_text_or_null(9, session.missionRef);
  stmt.bind_text(10, session.credentialSource);
  stmt.bind_int(11, session.maxDurationSeconds);
  stmt.bind_text(12, session.createdAt);
  stmt.bind_text_or_null(13, session.terminatedAt);
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite insert failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::update_session_termination(const Session &session) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "UPDATE sessions SET status = ?1, terminated_at = ?2 WHERE id = ?3");
  if (!stmt) {
    std::cerr << "SQLite update prepare failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_text(1, session.status);
  stmt.bind_text(2, session.terminatedAt);
  stmt.bind_int(3, session.id);
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite update failed: " << sqlite.last_error() << '\n';
  return ok;
}

void AppContext::terminate_session(int session_id, const std::string &actor,
                                  const std::string &role,
                                  const std::string &event_type) {
  Session terminated;
  {
    std::lock_guard<std::mutex> lock(session_mutex);
    auto it = sessions.find(session_id);
    if (it == sessions.end() || it->second.status != "active") return;
    it->second.status = "terminated";
    it->second.terminatedAt = now_utc();
    terminated = it->second;
  }
  if (!update_session_termination(terminated)) return;

  if (sqlite.is_open() && terminated.accessGrantId > 0) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    auto stmt = sqlite.prepare(
        "UPDATE access_grants SET status=?1, used_at=?2 WHERE id=?3");
    if (stmt) {
      stmt.bind_text(1, "used");
      stmt.bind_text(2, now_utc());
      stmt.bind_int(3, terminated.accessGrantId);
      stmt.execute();
    }
  }

  AuditEvent event;
  event.id = next_audit_id.fetch_add(1);
  event.type = event_type;
  event.actor = actor;
  event.role = role;
  event.createdAt = now_utc();
  event.payloadJson = build_session_payload_json(terminated);
  event.payloadIsJson = true;
  append_audit(event);
  append_session_dna_entry(terminated.id, event.id, event.type,
                           event.payloadJson, event.createdAt);
  append_session_event(event_type, terminated);

  // Behavioral baseline update: maintain per-user stats and emit anomaly
  // events when command volume spikes significantly vs historical average.
  const int64_t input_events = consume_session_input_events(session_id);
  int prior_sessions = 0;
  int64_t prior_inputs = 0;
  bool behavior_ok = true;
  if (sqlite.is_open()) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    auto prior = sqlite.prepare(
        "SELECT total_sessions, total_input_events FROM user_behavior_stats "
        "WHERE username=?1");
    if (prior) {
      prior.bind_text(1, terminated.user);
      if (prior.step()) {
        prior_sessions = prior.column_int(0);
        prior_inputs = prior.column_int64(1);
      }
    }

    auto upsert = sqlite.prepare(
        "INSERT INTO user_behavior_stats "
        "(username,total_sessions,total_duration_ms,total_input_events,"
        "updated_at) "
        "VALUES (?1,1,?2,?3,?4) "
        "ON CONFLICT(username) DO UPDATE SET "
        "total_sessions=total_sessions+1,"
        "total_duration_ms=total_duration_ms+excluded.total_duration_ms,"
        "total_input_events=total_input_events+excluded.total_input_events,"
        "updated_at=excluded.updated_at");
    if (!upsert) {
      behavior_ok = false;
    } else {
      int64_t duration_ms = 0;
      if (!terminated.createdAt.empty() && !terminated.terminatedAt.empty()) {
        duration_ms = 0;  // ISO conversion omitted; event counts are primary signal.
      }
      upsert.bind_text(1, terminated.user);
      upsert.bind_int64(2, duration_ms);
      upsert.bind_int64(3, input_events);
      upsert.bind_text(4, now_utc());
      behavior_ok = upsert.execute();
    }
  }

  if (behavior_ok && prior_sessions >= 5) {
    const double avg_inputs =
        static_cast<double>(prior_inputs) / static_cast<double>(prior_sessions);
    if (input_events > 0 && avg_inputs > 0.0 &&
        static_cast<double>(input_events) > avg_inputs * 3.0) {
      AuditEvent anomaly;
      anomaly.id = next_audit_id.fetch_add(1);
      anomaly.type = "behavior.anomaly.command_spike";
      anomaly.actor = terminated.user;
      anomaly.role = "operator";
      anomaly.createdAt = now_utc();
      anomaly.payloadJson =
          "{\"sessionId\":" + std::to_string(session_id) +
          ",\"inputEvents\":" + std::to_string(input_events) +
          ",\"historicalAvg\":" +
          std::to_string(static_cast<int64_t>(avg_inputs)) + "}";
      anomaly.payloadIsJson = true;
      append_audit(anomaly);
    }
  }

  // Dynamic secrets (premium): tear down any ephemeral OS account bound to this
  // session. No-op in the Community edition (seam left unset).
  if (deprovision_dynamic_for_session) deprovision_dynamic_for_session(session_id);
}

// ── Resource CRUD ───────────────────────────────────────────────────────

void AppContext::load_resources_from_db() {
  if (!sqlite.is_open()) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, name, target, protocol, port, description, image_url, "
      "image_data, tags_csv, credential_source, http_username, http_password, "
      "created_at, updated_at, ssh_username, ssh_password, "
      "require_access_justification, require_dual_approval, "
      "enable_command_guard, adaptive_access_policy, risk_level, "
      "tunnel_ticket_rate_limit_max_attempts, agent_protocol FROM resources";
  auto stmt = sqlite.prepare(sql);
  if (!stmt) {
    std::cerr << "SQLite resource select failed: " << sqlite.last_error() << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(resource_mutex);
    while (stmt.step()) {
      Resource r;
      r.id = stmt.column_int(0);
      r.name = stmt.column_text(1);
      r.target = stmt.column_text(2);
      r.protocol = stmt.column_text(3);
      r.port = stmt.column_int(4);
      if (r.port <= 0) r.port = 22;
      stmt.column_text_into(5, r.description);
      stmt.column_text_into(6, r.imageUrl);
      stmt.column_text_into(7, r.imageData);
      stmt.column_text_into(8, r.tagsCsv);
      stmt.column_text_into(9, r.credentialSource);
      if (r.credentialSource.empty()) r.credentialSource = "vaulted";
      stmt.column_text_into(10, r.httpUsername);
      if (!stmt.column_is_null(11)) {
        r.httpPassword = crypto::aes256_decrypt(stmt.column_text(11));
      }
      r.createdAt = stmt.column_text(12);
      r.updatedAt = stmt.column_text(13);
      stmt.column_text_into(14, r.sshUsername);
      if (!stmt.column_is_null(15)) {
        r.sshPassword = crypto::aes256_decrypt(stmt.column_text(15));
      }
      r.requireAccessJustification = stmt.column_int(16) != 0;
      r.requireDualApproval = stmt.column_int(17) != 0;
      r.enableCommandGuard = stmt.column_int(18) != 0;
      r.adaptiveAccessPolicy = stmt.column_int(19) != 0;
      stmt.column_text_into(20, r.riskLevel);
      if (r.riskLevel.empty()) r.riskLevel = "low";
      r.tunnelTicketRateLimitMaxAttempts = stmt.column_int(21);
      if (r.tunnelTicketRateLimitMaxAttempts < 0) {
        r.tunnelTicketRateLimitMaxAttempts = 0;
      }
      stmt.column_text_into(22, r.agentProtocol);
      resources[r.id] = r;
      if (r.id > max_id) max_id = r.id;
    }
  }
  if (max_id > 0) next_resource_id.store(max_id + 1);
}

bool AppContext::insert_resource(const Resource &r) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "INSERT INTO resources (id, name, target, protocol, port, description, "
      "image_url, image_data, tags_csv, credential_source, http_username, "
      "http_password, created_at, updated_at, ssh_username, ssh_password, "
      "require_access_justification, require_dual_approval, "
      "enable_command_guard, adaptive_access_policy, risk_level, "
      "tunnel_ticket_rate_limit_max_attempts, agent_protocol) "
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, "
      "?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)");
  if (!stmt) {
    std::cerr << "SQLite resource insert failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, r.id);
  stmt.bind_text(2, r.name);
  stmt.bind_text(3, r.target);
  stmt.bind_text(4, r.protocol);
  stmt.bind_int(5, r.port);
  stmt.bind_text_or_null(6, r.description);
  stmt.bind_text_or_null(7, r.imageUrl);
  stmt.bind_text_or_null(8, r.imageData);
  stmt.bind_text_or_null(9, r.tagsCsv);
  stmt.bind_text(10, r.credentialSource);
  stmt.bind_text_or_null(11, r.httpUsername);
  // Secrets are encrypted before they ever reach the database.
  stmt.bind_text_or_null(
      12, r.httpPassword.empty() ? std::string()
                                 : crypto::seal_secret(r.httpPassword));
  stmt.bind_text(13, r.createdAt);
  stmt.bind_text(14, r.updatedAt);
  stmt.bind_text_or_null(15, r.sshUsername);
  stmt.bind_text_or_null(
      16, r.sshPassword.empty() ? std::string()
                                : crypto::seal_secret(r.sshPassword));
  stmt.bind_int(17, r.requireAccessJustification ? 1 : 0);
  stmt.bind_int(18, r.requireDualApproval ? 1 : 0);
  stmt.bind_int(19, r.enableCommandGuard ? 1 : 0);
  stmt.bind_int(20, r.adaptiveAccessPolicy ? 1 : 0);
  stmt.bind_text(21, r.riskLevel);
  stmt.bind_int(22, std::max(0, r.tunnelTicketRateLimitMaxAttempts));
  stmt.bind_text_or_null(23, r.agentProtocol);
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite resource insert failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::update_resource_db(const Resource &r) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "UPDATE resources SET name=?1, target=?2, protocol=?3, port=?4, "
      "description=?5, image_url=?6, image_data=?7, tags_csv=?8, "
      "credential_source=?9, http_username=?10, http_password=?11, "
      "updated_at=?12, ssh_username=?13, ssh_password=?14, "
      "require_access_justification=?15, require_dual_approval=?16, "
      "enable_command_guard=?17, adaptive_access_policy=?18, risk_level=?19, "
      "tunnel_ticket_rate_limit_max_attempts=?20, agent_protocol=?21 "
      "WHERE id=?22");
  if (!stmt) {
    std::cerr << "SQLite resource update failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_text(1, r.name);
  stmt.bind_text(2, r.target);
  stmt.bind_text(3, r.protocol);
  stmt.bind_int(4, r.port);
  stmt.bind_text_or_null(5, r.description);
  stmt.bind_text_or_null(6, r.imageUrl);
  stmt.bind_text_or_null(7, r.imageData);
  stmt.bind_text_or_null(8, r.tagsCsv);
  stmt.bind_text(9, r.credentialSource);
  stmt.bind_text_or_null(10, r.httpUsername);
  stmt.bind_text_or_null(
      11, r.httpPassword.empty() ? std::string()
                                 : crypto::seal_secret(r.httpPassword));
  stmt.bind_text(12, r.updatedAt);
  stmt.bind_text_or_null(13, r.sshUsername);
  stmt.bind_text_or_null(
      14, r.sshPassword.empty() ? std::string()
                                : crypto::seal_secret(r.sshPassword));
  stmt.bind_int(15, r.requireAccessJustification ? 1 : 0);
  stmt.bind_int(16, r.requireDualApproval ? 1 : 0);
  stmt.bind_int(17, r.enableCommandGuard ? 1 : 0);
  stmt.bind_int(18, r.adaptiveAccessPolicy ? 1 : 0);
  stmt.bind_text(19, r.riskLevel);
  stmt.bind_int(20, std::max(0, r.tunnelTicketRateLimitMaxAttempts));
  stmt.bind_text_or_null(21, r.agentProtocol);
  stmt.bind_int(22, r.id);
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite resource update failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::delete_resource_db(int resource_id) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  // SQLite does not enforce the declared foreign keys: drop the grants by hand,
  // or they would apply to the next resource handed this id (ids restart at
  // MAX(id)+1 after a restart).
  auto grants = sqlite.prepare(
      "DELETE FROM user_resource_permissions WHERE resource_id = ?1");
  if (grants) {
    grants.bind_int(1, resource_id);
    grants.execute();
  }
  auto stmt = sqlite.prepare("DELETE FROM resources WHERE id = ?1");
  if (!stmt) {
    std::cerr << "SQLite resource delete failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, resource_id);
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite resource delete failed: " << sqlite.last_error() << '\n';
  return ok;
}

// ── User CRUD ───────────────────────────────────────────────────────────

void AppContext::load_users_from_db() {
  if (!sqlite.is_open()) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, username, password, role, created_at, updated_at, "
      "bootstrap_password_change_required, bootstrap_mfa_required, "
      "totp_enabled, totp_secret, preferred_mfa_method FROM users";
  auto stmt = sqlite.prepare(sql);
  if (!stmt) {
    std::cerr << "SQLite user select failed: " << sqlite.last_error() << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    while (stmt.step()) {
      UserAccount u;
      u.id = stmt.column_int(0);
      u.username = stmt.column_text(1);
      u.password = stmt.column_text(2);
      u.role = stmt.column_text(3);
      u.createdAt = stmt.column_text(4);
      u.updatedAt = stmt.column_text(5);
      u.bootstrapPasswordChangeRequired = stmt.column_int(6) != 0;
      u.bootstrapMfaRequired = stmt.column_int(7) != 0;
      u.totpEnabled = stmt.column_int(8) != 0;
      stmt.column_text_into(9, u.totpSecret);
      stmt.column_text_into(10, u.preferredMfaMethod);
      users[u.id] = u;
      if (u.id > max_id) max_id = u.id;
    }
  }
  if (max_id > 0) next_user_id.store(max_id + 1);
}

bool AppContext::insert_user(const UserAccount &u) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "INSERT INTO users (id, username, password, role, created_at, "
      "updated_at, bootstrap_password_change_required, "
      "bootstrap_mfa_required, totp_enabled, totp_secret, preferred_mfa_method) "
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)");
  if (!stmt) {
    std::cerr << "SQLite user insert failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, u.id);
  stmt.bind_text(2, u.username);
  stmt.bind_text(3, u.password);
  stmt.bind_text(4, u.role);
  stmt.bind_text(5, u.createdAt);
  stmt.bind_text(6, u.updatedAt);
  stmt.bind_int(7, u.bootstrapPasswordChangeRequired ? 1 : 0);
  stmt.bind_int(8, u.bootstrapMfaRequired ? 1 : 0);
  stmt.bind_int(9, u.totpEnabled ? 1 : 0);
  stmt.bind_text_or_null(10, u.totpSecret);
  stmt.bind_text(11, u.preferredMfaMethod);
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite user insert failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::update_user_db(const UserAccount &u) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "UPDATE users SET password=?1, role=?2, updated_at=?3, "
      "bootstrap_password_change_required=?4, bootstrap_mfa_required=?5, "
      "totp_enabled=?6, totp_secret=?7, preferred_mfa_method=?8 WHERE id=?9");
  if (!stmt) {
    std::cerr << "SQLite user update failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_text(1, u.password);
  stmt.bind_text(2, u.role);
  stmt.bind_text(3, u.updatedAt);
  stmt.bind_int(4, u.bootstrapPasswordChangeRequired ? 1 : 0);
  stmt.bind_int(5, u.bootstrapMfaRequired ? 1 : 0);
  stmt.bind_int(6, u.totpEnabled ? 1 : 0);
  stmt.bind_text_or_null(7, u.totpSecret);
  stmt.bind_text(8, u.preferredMfaMethod);
  stmt.bind_int(9, u.id);
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite user update failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::delete_user_db(int user_id) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  // Drop the passkeys first so none is orphaned if the user delete fails.
  auto cleanup =
      sqlite.prepare("DELETE FROM user_webauthn_credentials WHERE user_id = ?1");
  if (cleanup) {
    cleanup.bind_int(1, user_id);
    cleanup.execute();
  }
  // Same for resource grants and access profiles: a later account reusing the
  // id must not inherit them.
  for (const char *sql :
       {"DELETE FROM user_resource_permissions WHERE user_id = ?1",
        "DELETE FROM user_access_profiles WHERE user_id = ?1"}) {
    auto dependent = sqlite.prepare(sql);
    if (dependent) {
      dependent.bind_int(1, user_id);
      dependent.execute();
    }
  }
  auto stmt = sqlite.prepare("DELETE FROM users WHERE id = ?1");
  if (!stmt) {
    std::cerr << "SQLite user delete failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, user_id);
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite user delete failed: " << sqlite.last_error() << '\n';
  return ok;
}

// ── Permissions ─────────────────────────────────────────────────────────

std::vector<int> AppContext::get_resource_permissions(int user_id) {
  std::unordered_set<int> unique_ids;
  std::vector<AccessProfile> assigned_profiles;
  if (!sqlite.is_open()) return {};
  {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    auto direct = sqlite.prepare(
        "SELECT resource_id FROM user_resource_permissions WHERE user_id = ?1");
    if (!direct) {
      std::cerr << "SQLite perm select failed: " << sqlite.last_error() << '\n';
      return {};
    }
    direct.bind_int(1, user_id);
    while (direct.step()) unique_ids.insert(direct.column_int(0));

    auto profiles = sqlite.prepare(
        "SELECT p.id, p.name, p.description, p.resource_tags_csv, "
        "p.resource_ids_csv, p.policy_id, p.created_at, p.updated_at "
        "FROM access_profiles p "
        "INNER JOIN user_access_profiles up ON up.profile_id = p.id "
        "WHERE up.user_id = ?1");
    if (profiles) {
      profiles.bind_int(1, user_id);
      while (profiles.step()) {
        AccessProfile profile;
        profile.id = profiles.column_int(0);
        profiles.column_text_into(1, profile.name);
        profiles.column_text_into(2, profile.description);
        profiles.column_text_into(3, profile.resourceTagsCsv);
        profiles.column_text_into(4, profile.resourceIdsCsv);
        profile.policyId = profiles.column_int(5);
        profiles.column_text_into(6, profile.createdAt);
        profiles.column_text_into(7, profile.updatedAt);
        assigned_profiles.push_back(profile);
      }
    }
  }

  for (const auto &profile : assigned_profiles) {
    for (const auto &token : split_csv_compact(profile.resourceIdsCsv)) {
      try {
        const int id = std::stoi(token);
        if (id > 0) unique_ids.insert(id);
      } catch (...) {
      }
    }
  }

  if (!assigned_profiles.empty()) {
    std::lock_guard<std::mutex> lock(resource_mutex);
    for (const auto &profile : assigned_profiles) {
      if (profile.resourceTagsCsv.empty()) continue;
      for (const auto &entry : resources) {
        if (csv_intersects(profile.resourceTagsCsv, entry.second.tagsCsv)) {
          unique_ids.insert(entry.first);
        }
      }
    }
  }

  std::vector<int> ids(unique_ids.begin(), unique_ids.end());
  std::sort(ids.begin(), ids.end());
  return ids;
}

bool AppContext::grant_resource_permission(int user_id, int resource_id) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "INSERT INTO user_resource_permissions "
      "(user_id, resource_id, created_at) VALUES (?1, ?2, ?3) "
      "ON CONFLICT DO NOTHING");
  if (!stmt) {
    std::cerr << "SQLite perm insert failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, user_id);
  stmt.bind_int(2, resource_id);
  stmt.bind_text(3, now_utc());
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite perm insert failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::revoke_resource_permission(int user_id, int resource_id) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "DELETE FROM user_resource_permissions WHERE user_id=?1 AND resource_id=?2");
  if (!stmt) {
    std::cerr << "SQLite perm delete failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, user_id);
  stmt.bind_int(2, resource_id);
  const bool ok = stmt.execute();
  if (!ok) std::cerr << "SQLite perm delete failed: " << sqlite.last_error() << '\n';
  return ok;
}

std::unordered_set<std::string> AppContext::get_effective_permissions(
    int user_id, const std::string &role) {
  (void)user_id;
  // Access decisions now follow a simpler role-policy model:
  // global capabilities come from the role, while concrete access scope is
  // enforced through per-resource assignments and resource-level controls.
  return default_permissions_for_role(role);
}

bool AppContext::has_permission(int user_id, const std::string &role,
                                const std::string &permission) {
  if (!is_known_permission(permission)) return false;
  const auto effective = get_effective_permissions(user_id, role);
  return permissions_contain(effective, permission);
}

// ── Session ownership ──────────────────────────────────────────────────

std::string AppContext::session_owner(const Session &session) {
  if (!sqlite.is_open() || session.accessGrantId <= 0) return "";
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt =
      sqlite.prepare("SELECT subject FROM access_grants WHERE id=?1");
  if (!stmt) return "";
  stmt.bind_int(1, session.accessGrantId);
  if (!stmt.step()) return "";
  return stmt.column_text(0);
}

std::unordered_map<int, std::string> AppContext::access_grant_subjects() {
  std::unordered_map<int, std::string> subjects;
  if (!sqlite.is_open()) return subjects;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare("SELECT id, subject FROM access_grants");
  if (!stmt) return subjects;
  while (stmt.step()) {
    // A NULL subject stays absent from the map rather than mapping to "",
    // so callers testing with count() keep seeing "no owner recorded".
    if (!stmt.column_is_null(1)) {
      subjects[stmt.column_int(0)] = stmt.column_text(1);
    }
  }
  return subjects;
}

bool AppContext::may_see_session(int user_id, const std::string &user,
                                 const std::string &role,
                                 const std::string &owner) {
  if (has_permission(user_id, role, "audit.read")) return true;
  return !owner.empty() && owner == user;
}

bool AppContext::may_operate_session(int user_id, const std::string &user,
                                     const std::string &role,
                                     const std::string &owner) {
  if (has_permission(user_id, role, "resources.manage")) return true;
  return !owner.empty() && owner == user;
}

bool AppContext::may_drive_session(const std::string &user,
                                   const std::string &owner) {
  return !owner.empty() && owner == user;
}

// ── 2FA / TOTP ─────────────────────────────────────────────────────────

bool AppContext::update_user_totp(int user_id, bool enabled,
                                   const std::string &secret) {
  // Update in-memory
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    auto it = users.find(user_id);
    if (it == users.end()) return false;
    it->second.totpEnabled = enabled;
    it->second.totpSecret = secret;
  }
  // Persist
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "UPDATE users SET totp_enabled=?1, totp_secret=?2 WHERE id=?3");
  if (!stmt) {
    std::cerr << "SQLite TOTP update failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, enabled ? 1 : 0);
  stmt.bind_text_or_null(2, secret);
  stmt.bind_int(3, user_id);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite TOTP update failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::update_user_mfa_preference(int user_id,
                                            const std::string &method) {
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    auto it = users.find(user_id);
    if (it == users.end()) return false;
    it->second.preferredMfaMethod = method;
    it->second.updatedAt = now_utc();
  }
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "UPDATE users SET preferred_mfa_method=?1, updated_at=?2 WHERE id=?3");
  if (!stmt) {
    std::cerr << "SQLite MFA preference update failed: " << sqlite.last_error()
              << '\n';
    return false;
  }
  stmt.bind_text(1, method);
  stmt.bind_text(2, now_utc());
  stmt.bind_int(3, user_id);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite MFA preference update failed: " << sqlite.last_error()
              << '\n';
  return ok;
}

void AppContext::load_webauthn_credentials_from_db() {
  if (!sqlite.is_open()) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, user_id, credential_id, public_key_spki, sign_count, label, "
      "transports_csv, created_at, last_used_at "
      "FROM user_webauthn_credentials";
  auto stmt = sqlite.prepare(sql);
  if (!stmt) {
    std::cerr << "SQLite WebAuthn select failed: " << sqlite.last_error()
              << '\n';
    return;
  }
  int max_id = 0;
  std::lock_guard<std::mutex> webauthn_lock(webauthn_mutex);
  std::lock_guard<std::mutex> user_lock(user_mutex);
  while (stmt.step()) {
    WebAuthnCredential credential;
    credential.id = stmt.column_int(0);
    credential.userId = stmt.column_int(1);
    credential.credentialId = stmt.column_text(2);
    credential.publicKeySpki = stmt.column_text(3);
    credential.signCount = stmt.column_int(4);
    stmt.column_text_into(5, credential.label);
    stmt.column_text_into(6, credential.transportsCsv);
    stmt.column_text_into(7, credential.createdAt);
    stmt.column_text_into(8, credential.lastUsedAt);

    webauthn_credentials[credential.id] = credential;
    webauthn_credential_by_external_id[credential.credentialId] = credential.id;
    auto user_it = users.find(credential.userId);
    if (user_it != users.end()) {
      user_it->second.webauthnCredentialCount += 1;
    }
    if (credential.id > max_id) max_id = credential.id;
  }
  if (max_id > 0) next_webauthn_credential_id.store(max_id + 1);
}

bool AppContext::insert_webauthn_credential(const WebAuthnCredential &credential) {
  {
    std::lock_guard<std::mutex> webauthn_lock(webauthn_mutex);
    if (webauthn_credential_by_external_id.count(credential.credentialId)) {
      return false;
    }
  }
  if (sqlite.is_open()) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    auto stmt = sqlite.prepare(
        "INSERT INTO user_webauthn_credentials "
        "(id, user_id, credential_id, public_key_spki, sign_count, label, "
        "transports_csv, created_at, last_used_at) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)");
    if (!stmt) {
      std::cerr << "SQLite WebAuthn insert failed: " << sqlite.last_error()
                << '\n';
      return false;
    }
    stmt.bind_int(1, credential.id);
    stmt.bind_int(2, credential.userId);
    stmt.bind_text(3, credential.credentialId);
    stmt.bind_text(4, credential.publicKeySpki);
    stmt.bind_int(5, credential.signCount);
    stmt.bind_text_or_null(6, credential.label);
    stmt.bind_text_or_null(7, credential.transportsCsv);
    stmt.bind_text(8, credential.createdAt);
    stmt.bind_text_or_null(9, credential.lastUsedAt);
    const bool ok = stmt.execute();
    if (!ok)
      std::cerr << "SQLite WebAuthn insert failed: " << sqlite.last_error()
                << '\n';
    if (!ok) return false;
  }

  std::lock_guard<std::mutex> webauthn_lock(webauthn_mutex);
  std::lock_guard<std::mutex> user_lock(user_mutex);
  webauthn_credentials[credential.id] = credential;
  webauthn_credential_by_external_id[credential.credentialId] = credential.id;
  auto user_it = users.find(credential.userId);
  if (user_it != users.end()) {
    user_it->second.webauthnCredentialCount += 1;
  }
  return true;
}

bool AppContext::update_webauthn_credential(const WebAuthnCredential &credential) {
  if (sqlite.is_open()) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    auto stmt = sqlite.prepare(
        "UPDATE user_webauthn_credentials SET sign_count=?1, label=?2, "
        "transports_csv=?3, last_used_at=?4 WHERE id=?5");
    if (!stmt) {
      std::cerr << "SQLite WebAuthn update failed: " << sqlite.last_error()
                << '\n';
      return false;
    }
    stmt.bind_int(1, credential.signCount);
    stmt.bind_text_or_null(2, credential.label);
    stmt.bind_text_or_null(3, credential.transportsCsv);
    stmt.bind_text_or_null(4, credential.lastUsedAt);
    stmt.bind_int(5, credential.id);
    const bool ok = stmt.execute();
    if (!ok)
      std::cerr << "SQLite WebAuthn update failed: " << sqlite.last_error()
                << '\n';
    if (!ok) return false;
  }

  std::lock_guard<std::mutex> lock(webauthn_mutex);
  auto it = webauthn_credentials.find(credential.id);
  if (it == webauthn_credentials.end()) return false;
  it->second = credential;
  return true;
}

bool AppContext::delete_webauthn_credential(int credential_id) {
  WebAuthnCredential existing;
  {
    std::lock_guard<std::mutex> lock(webauthn_mutex);
    auto it = webauthn_credentials.find(credential_id);
    if (it == webauthn_credentials.end()) return false;
    existing = it->second;
  }

  if (sqlite.is_open()) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    auto stmt =
        sqlite.prepare("DELETE FROM user_webauthn_credentials WHERE id=?1");
    if (!stmt) {
      std::cerr << "SQLite WebAuthn delete failed: " << sqlite.last_error()
                << '\n';
      return false;
    }
    stmt.bind_int(1, credential_id);
    const bool ok = stmt.execute();
    if (!ok)
      std::cerr << "SQLite WebAuthn delete failed: " << sqlite.last_error()
                << '\n';
    if (!ok) return false;
  }

  std::lock_guard<std::mutex> webauthn_lock(webauthn_mutex);
  std::lock_guard<std::mutex> user_lock(user_mutex);
  webauthn_credentials.erase(credential_id);
  webauthn_credential_by_external_id.erase(existing.credentialId);
  auto user_it = users.find(existing.userId);
  if (user_it != users.end() && user_it->second.webauthnCredentialCount > 0) {
    user_it->second.webauthnCredentialCount -= 1;
  }
  return true;
}

std::vector<WebAuthnCredential> AppContext::get_user_webauthn_credentials(
    int user_id) {
  std::vector<WebAuthnCredential> result;
  std::lock_guard<std::mutex> lock(webauthn_mutex);
  for (const auto &entry : webauthn_credentials) {
    if (entry.second.userId == user_id) {
      result.push_back(entry.second);
    }
  }
  std::sort(result.begin(), result.end(),
            [](const WebAuthnCredential &a, const WebAuthnCredential &b) {
              return a.createdAt < b.createdAt;
            });
  return result;
}

std::optional<WebAuthnCredential>
AppContext::find_webauthn_credential_by_external_id(
    const std::string &credential_id) {
  std::lock_guard<std::mutex> lock(webauthn_mutex);
  auto map_it = webauthn_credential_by_external_id.find(credential_id);
  if (map_it == webauthn_credential_by_external_id.end()) return std::nullopt;
  auto cred_it = webauthn_credentials.find(map_it->second);
  if (cred_it == webauthn_credentials.end()) return std::nullopt;
  return cred_it->second;
}

bool AppContext::user_has_webauthn(int user_id) {
  std::lock_guard<std::mutex> lock(user_mutex);
  auto it = users.find(user_id);
  return it != users.end() && it->second.webauthnCredentialCount > 0;
}

WebAuthnChallenge AppContext::create_webauthn_challenge(
    int user_id, const std::string &username, const std::string &purpose,
    const std::string &rp_id, const std::string &origin) {
  cleanup_expired_webauthn_challenges();
  WebAuthnChallenge challenge;
  challenge.requestId = generate_token();
  challenge.userId = user_id;
  challenge.username = username;
  challenge.purpose = purpose;
  challenge.challenge = generate_token();
  challenge.rpId = rp_id;
  challenge.origin = origin;
  challenge.createdAt = now_utc();
  challenge.expiresAtEpoch = now_epoch_seconds() + webauthn_challenge_ttl_seconds;
  challenge.expiresAt = utc_from_epoch_seconds(challenge.expiresAtEpoch);
  std::lock_guard<std::mutex> lock(webauthn_mutex);
  webauthn_challenges[challenge.requestId] = challenge;
  return challenge;
}

std::optional<WebAuthnChallenge> AppContext::consume_webauthn_challenge(
    const std::string &request_id, int user_id, const std::string &purpose) {
  cleanup_expired_webauthn_challenges();
  std::lock_guard<std::mutex> lock(webauthn_mutex);
  auto it = webauthn_challenges.find(request_id);
  if (it == webauthn_challenges.end()) return std::nullopt;
  if (it->second.userId != user_id || it->second.purpose != purpose ||
      it->second.expiresAtEpoch < now_epoch_seconds()) {
    webauthn_challenges.erase(it);
    return std::nullopt;
  }
  auto challenge = it->second;
  webauthn_challenges.erase(it);
  return challenge;
}

void AppContext::cleanup_expired_webauthn_challenges() {
  const int64_t now = now_epoch_seconds();
  std::lock_guard<std::mutex> lock(webauthn_mutex);
  for (auto it = webauthn_challenges.begin(); it != webauthn_challenges.end();) {
    if (it->second.expiresAtEpoch < now) {
      it = webauthn_challenges.erase(it);
    } else {
      ++it;
    }
  }
}

// ── Password management ────────────────────────────────────────────────

bool AppContext::update_user_password_hash(int user_id,
                                           const std::string &hash) {
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    auto it = users.find(user_id);
    if (it == users.end()) return false;
    it->second.password = hash;
    it->second.updatedAt = now_utc();
  }
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt =
      sqlite.prepare("UPDATE users SET password=?1, updated_at=?2 WHERE id=?3");
  if (!stmt) {
    std::cerr << "SQLite password update failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_text(1, hash);
  stmt.bind_text(2, now_utc());
  stmt.bind_int(3, user_id);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite password update failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::update_user_bootstrap_flags(int user_id,
                                             bool password_change_required,
                                             bool mfa_required) {
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    auto it = users.find(user_id);
    if (it == users.end()) return false;
    it->second.bootstrapPasswordChangeRequired = password_change_required;
    it->second.bootstrapMfaRequired = mfa_required;
    it->second.updatedAt = now_utc();
  }
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "UPDATE users SET bootstrap_password_change_required=?1, "
      "bootstrap_mfa_required=?2, updated_at=?3 WHERE id=?4");
  if (!stmt) {
    std::cerr << "SQLite bootstrap flag update failed: " << sqlite.last_error()
              << '\n';
    return false;
  }
  stmt.bind_int(1, password_change_required ? 1 : 0);
  stmt.bind_int(2, mfa_required ? 1 : 0);
  stmt.bind_text(3, now_utc());
  stmt.bind_int(4, user_id);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite bootstrap flag update failed: " << sqlite.last_error()
              << '\n';
  return ok;
}

// ── Session Recordings ─────────────────────────────────────────────────

void AppContext::init_recordings_dir() {
  // Create recordings directory if it doesn't exist
#ifdef _WIN32
  _mkdir(recordings_dir.c_str());
#else
  mkdir(recordings_dir.c_str(), 0755);
#endif
}

void AppContext::load_recordings_from_db() {
  if (!sqlite.is_open()) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, session_id, file_path, created_at, closed_at, "
      "duration_ms, file_size FROM session_recordings";
  auto stmt = sqlite.prepare(sql);
  if (!stmt) {
    std::cerr << "SQLite recording select failed: " << sqlite.last_error()
              << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(recording_mutex);
    while (stmt.step()) {
      SessionRecording r;
      r.id = stmt.column_int(0);
      r.sessionId = stmt.column_int(1);
      r.filePath = stmt.column_text(2);
      r.createdAt = stmt.column_text(3);
      stmt.column_text_into(4, r.closedAt);
      r.durationMs = stmt.column_int64(5);
      r.fileSize = static_cast<size_t>(stmt.column_int64(6));
      recordings[r.id] = r;
      if (r.id > max_id) max_id = r.id;
    }
  }
  if (max_id > 0) next_recording_id.store(max_id + 1);
}

bool AppContext::insert_recording(const SessionRecording &rec) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "INSERT INTO session_recordings (id, session_id, file_path, created_at) "
      "VALUES (?1, ?2, ?3, ?4)");
  if (!stmt) {
    std::cerr << "SQLite recording insert failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, rec.id);
  stmt.bind_int(2, rec.sessionId);
  stmt.bind_text(3, rec.filePath);
  stmt.bind_text(4, rec.createdAt);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite recording insert failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::update_recording_close(const SessionRecording &rec) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "UPDATE session_recordings SET closed_at=?1, duration_ms=?2, file_size=?3 "
      "WHERE id=?4");
  if (!stmt) {
    std::cerr << "SQLite recording update failed: " << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_text(1, rec.closedAt);
  stmt.bind_int64(2, rec.durationMs);
  stmt.bind_int64(3, static_cast<int64_t>(rec.fileSize));
  stmt.bind_int(4, rec.id);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite recording update failed: " << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::append_session_dna_entry(int session_id, int audit_event_id,
                                          const std::string &event_type,
                                          const std::string &payload_json,
                                          const std::string &created_at) {
  if (!sqlite.is_open() || session_id <= 0 || audit_event_id <= 0) return false;
  std::lock_guard<std::mutex> lock(sqlite.mutex);

  // A missing or NULL previous link keeps the chain anchored at GENESIS.
  std::string prev_hash = "GENESIS";
  {
    auto select = sqlite.prepare(
        "SELECT chain_hash FROM session_dna_chain WHERE session_id=?1 "
        "ORDER BY id DESC LIMIT 1");
    if (select) {
      select.bind_int(1, session_id);
      if (select.step()) select.column_text_into(0, prev_hash);
    }
  }

  const std::string payload_hash = crypto::sha256_hex(payload_json);
  const std::string chain_input = prev_hash + "|" + event_type + "|" +
                                  payload_hash + "|" + created_at;
  const std::string chain_hash = crypto::sha256_hex(chain_input);

  auto insert = sqlite.prepare(
      "INSERT INTO session_dna_chain "
      "(session_id, audit_event_id, event_type, created_at, prev_hash, "
      "payload_hash, chain_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)");
  if (!insert) {
    std::cerr << "SQLite session_dna insert prepare failed: "
              << sqlite.last_error() << '\n';
    return false;
  }
  insert.bind_int(1, session_id);
  insert.bind_int(2, audit_event_id);
  insert.bind_text(3, event_type);
  insert.bind_text(4, created_at);
  insert.bind_text(5, prev_hash);
  insert.bind_text(6, payload_hash);
  insert.bind_text(7, chain_hash);
  const bool ok = insert.execute();
  if (!ok) {
    std::cerr << "SQLite session_dna insert failed: " << sqlite.last_error()
              << '\n';
  }
  return ok;
}

std::vector<SessionDnaEntry> AppContext::get_session_dna_chain(int session_id) {
  std::vector<SessionDnaEntry> entries;
  if (!sqlite.is_open() || session_id <= 0) return entries;

  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "SELECT id, session_id, audit_event_id, event_type, created_at, "
      "prev_hash, payload_hash, chain_hash "
      "FROM session_dna_chain WHERE session_id=?1 ORDER BY id ASC");
  if (!stmt) {
    std::cerr << "SQLite session_dna select failed: " << sqlite.last_error()
              << '\n';
    return entries;
  }
  stmt.bind_int(1, session_id);
  while (stmt.step()) {
    SessionDnaEntry entry;
    entry.id = stmt.column_int(0);
    entry.sessionId = stmt.column_int(1);
    entry.auditEventId = stmt.column_int(2);
    entry.eventType = stmt.column_text(3);
    entry.createdAt = stmt.column_text(4);
    entry.prevHash = stmt.column_text(5);
    entry.payloadHash = stmt.column_text(6);
    entry.chainHash = stmt.column_text(7);
    entries.push_back(entry);
  }
  return entries;
}

// ── Access Requests ────────────────────────────────────────────────────

void AppContext::load_access_requests_from_db() {
  if (!sqlite.is_open()) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, resource_id, resource_name, requester, requester_role, "
      "status, justification, ticket_id, created_at, reviewed_at, reviewed_by "
      "FROM access_requests";
  auto stmt = sqlite.prepare(sql);
  if (!stmt) {
    std::cerr << "SQLite access request select failed: " << sqlite.last_error()
              << '\n';
    return;
  }

  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(access_request_mutex);
    while (stmt.step()) {
      AccessRequest req;
      req.id = stmt.column_int(0);
      req.resourceId = stmt.column_int(1);
      stmt.column_text_into(2, req.resourceName);
      req.requester = stmt.column_text(3);
      req.requesterRole = stmt.column_text(4);
      req.status = stmt.column_text(5);
      stmt.column_text_into(6, req.justification);
      stmt.column_text_into(7, req.ticketId);
      req.createdAt = stmt.column_text(8);
      stmt.column_text_into(9, req.reviewedAt);
      stmt.column_text_into(10, req.reviewedBy);

      access_requests[req.id] = req;
      if (req.id > max_id) max_id = req.id;
    }
  }
  if (max_id > 0) next_access_request_id.store(max_id + 1);
}

bool AppContext::insert_access_request(const AccessRequest &req) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "INSERT INTO access_requests "
      "(id, resource_id, resource_name, requester, requester_role, status, "
      "justification, ticket_id, created_at, reviewed_at, reviewed_by) "
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)");
  if (!stmt) {
    std::cerr << "SQLite access request insert failed: " << sqlite.last_error()
              << '\n';
    return false;
  }
  stmt.bind_int(1, req.id);
  stmt.bind_int(2, req.resourceId);
  stmt.bind_text_or_null(3, req.resourceName);
  stmt.bind_text(4, req.requester);
  stmt.bind_text(5, req.requesterRole);
  stmt.bind_text(6, req.status);
  stmt.bind_text_or_null(7, req.justification);
  stmt.bind_text_or_null(8, req.ticketId);
  stmt.bind_text(9, req.createdAt);
  stmt.bind_text_or_null(10, req.reviewedAt);
  stmt.bind_text_or_null(11, req.reviewedBy);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite access request insert failed: " << sqlite.last_error()
              << '\n';
  return ok;
}

bool AppContext::update_access_request(const AccessRequest &req) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "UPDATE access_requests SET status=?1, reviewed_at=?2, reviewed_by=?3 "
      "WHERE id=?4");
  if (!stmt) {
    std::cerr << "SQLite access request update failed: " << sqlite.last_error()
              << '\n';
    return false;
  }
  stmt.bind_text(1, req.status);
  stmt.bind_text_or_null(2, req.reviewedAt);
  stmt.bind_text_or_null(3, req.reviewedBy);
  stmt.bind_int(4, req.id);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite access request update failed: " << sqlite.last_error()
              << '\n';
  return ok;
}

// ── Runtime Behavior Counters ─────────────────────────────────────────

void AppContext::increment_session_input_event(int session_id) {
  if (session_id <= 0) return;
  std::lock_guard<std::mutex> lock(behavior_mutex);
  session_input_events[session_id] += 1;
}

int64_t AppContext::consume_session_input_events(int session_id) {
  std::lock_guard<std::mutex> lock(behavior_mutex);
  auto it = session_input_events.find(session_id);
  if (it == session_input_events.end()) return 0;
  const int64_t value = it->second;
  session_input_events.erase(it);
  return value;
}

// ── Ephemeral Credential Leases ───────────────────────────────────────

void AppContext::load_ephemeral_credentials_from_db() {
  if (!sqlite.is_open()) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, resource_id, requester, username, status, issued_at, "
      "expires_at, used_at FROM ephemeral_credentials";
  auto stmt = sqlite.prepare(sql);
  if (!stmt) {
    std::cerr << "SQLite ephemeral credential select failed: "
              << sqlite.last_error() << '\n';
    return;
  }

  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(ephemeral_credential_mutex);
    while (stmt.step()) {
      EphemeralCredentialLease lease;
      lease.id = stmt.column_int(0);
      lease.resourceId = stmt.column_int(1);
      lease.requester = stmt.column_text(2);
      lease.username = stmt.column_text(3);
      lease.status = stmt.column_text(4);
      lease.issuedAt = stmt.column_text(5);
      lease.expiresAt = stmt.column_text(6);
      stmt.column_text_into(7, lease.usedAt);
      ephemeral_credentials[lease.id] = lease;
      if (lease.id > max_id) max_id = lease.id;
    }
  }
  if (max_id > 0) next_ephemeral_credential_id.store(max_id + 1);
}

bool AppContext::insert_ephemeral_credential(
    const EphemeralCredentialLease &lease) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "INSERT INTO ephemeral_credentials "
      "(id, resource_id, requester, username, status, issued_at, expires_at, "
      "used_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
  if (!stmt) {
    std::cerr << "SQLite ephemeral credential insert failed: "
              << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_int(1, lease.id);
  stmt.bind_int(2, lease.resourceId);
  stmt.bind_text(3, lease.requester);
  stmt.bind_text(4, lease.username);
  stmt.bind_text(5, lease.status);
  stmt.bind_text(6, lease.issuedAt);
  stmt.bind_text(7, lease.expiresAt);
  stmt.bind_text_or_null(8, lease.usedAt);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite ephemeral credential insert failed: "
              << sqlite.last_error() << '\n';
  return ok;
}

bool AppContext::update_ephemeral_credential(
    const EphemeralCredentialLease &lease) {
  if (!sqlite.is_open()) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  auto stmt = sqlite.prepare(
      "UPDATE ephemeral_credentials SET status=?1, expires_at=?2, used_at=?3 "
      "WHERE id=?4");
  if (!stmt) {
    std::cerr << "SQLite ephemeral credential update failed: "
              << sqlite.last_error() << '\n';
    return false;
  }
  stmt.bind_text(1, lease.status);
  stmt.bind_text(2, lease.expiresAt);
  stmt.bind_text_or_null(3, lease.usedAt);
  stmt.bind_int(4, lease.id);
  const bool ok = stmt.execute();
  if (!ok)
    std::cerr << "SQLite ephemeral credential update failed: "
              << sqlite.last_error() << '\n';
  return ok;
}
