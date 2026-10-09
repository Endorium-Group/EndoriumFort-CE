// ─── EndoriumFort — AppContext implementation ───────────────────────────

#include "app_context.h"
#include "auth_mfa.h"
#include "crypto.h"
#include "utils.h"

#include <openssl/rand.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <arpa/inet.h>
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

// A one-time, high-entropy human-readable password for the bootstrap admin,
// drawn from the CSPRNG over an unambiguous alphabet (no 0/O/1/l/I). Used so no
// shared default credential ever ships in the binary (PCI 2.1 / ANSSI / CWE-798).
std::string random_readable_password(size_t len = 24) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  constexpr size_t kN = sizeof(kAlphabet) - 1;
  if (len > 64) len = 64;
  unsigned char buf[64];
  if (RAND_bytes(buf, static_cast<int>(len)) != 1) return {};
  std::string out;
  out.reserve(len);
  for (size_t i = 0; i < len; ++i) out.push_back(kAlphabet[buf[i] % kN]);
  return out;
}
}  // namespace

// ── Secure token generation (using /dev/urandom on Linux/macOS) ─────────

std::string AppContext::generate_token() {
  // These tokens back session/auth cookies, OIDC state/nonce/PKCE verifiers,
  // tunnel tickets and WebAuthn challenges, so they must come from a CSPRNG.
  // RAND_bytes is seeded from the OS CSPRNG and is portable (Windows included).
  unsigned char bytes[32];
  if (RAND_bytes(bytes, sizeof(bytes)) == 1) {
    return build_token_from_bytes(bytes, sizeof(bytes));
  }
#ifndef _WIN32
  // Fallback: read the OS CSPRNG directly if the OpenSSL path somehow failed.
  std::ifstream urandom("/dev/urandom", std::ios::binary);
  if (urandom.good()) {
    urandom.read(reinterpret_cast<char *>(bytes), sizeof(bytes));
    if (urandom.gcount() == sizeof(bytes)) {
      return build_token_from_bytes(bytes, sizeof(bytes));
    }
  }
#endif
  return {};
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
  
  // Calculate exponential backoff delay based on failure count
  // 10-19 failures: 30 seconds
  // 20-29 failures: 5 minutes
  // 30+ failures: 30 minutes
  int backoff_seconds = 30;
  if (entry.consecutive_failures >= 30) {
    backoff_seconds = 1800;  // 30 minutes
  } else if (entry.consecutive_failures >= 20) {
    backoff_seconds = 300;   // 5 minutes
  } else if (entry.consecutive_failures >= 10) {
    backoff_seconds = 30;    // 30 seconds
  }
  
  entry.block_until = now + std::chrono::seconds(backoff_seconds);
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

bool AppContext::is_safe_target(const std::string &host, bool allow_loopback) {
  // Block obvious loopback unless explicitly allowed (e.g. SSH dev jump hosts).
  if (!allow_loopback &&
      (host == "localhost" || host == "127.0.0.1" || host == "::1")) {
    return false;
  }

  // Always block unspecified address.
  if (host == "0.0.0.0") {
    return false;
  }

  // Block metadata endpoints (cloud providers)
  if (host == "169.254.169.254" || host == "metadata.google.internal" ||
      host == "metadata.internal") {
    return false;
  }

#ifndef _WIN32
  // Check if it's an IP address in blocked ranges
  struct in_addr addr;
  if (inet_pton(AF_INET, host.c_str(), &addr) == 1) {
    uint32_t ip = ntohl(addr.s_addr);
    // 127.0.0.0/8 (loopback)
    if (!allow_loopback && (ip >> 24) == 127) return false;
    // 169.254.0.0/16 (link-local)
    if ((ip >> 16) == 0xA9FE) return false;
    // 0.0.0.0/8
    if ((ip >> 24) == 0) return false;
  }
#endif

  return true;
}

// ── Auth helpers ────────────────────────────────────────────────────────

// Validate a session for one authenticated request: enforce both the absolute
// expiry and the inactivity (idle) timeout, and on success refresh last-seen so
// the idle window slides forward. Caller must hold auth_mutex. Returns nullptr
// (after erasing) if the session is expired/idle-timed-out.
AuthSession *AppContext::validate_and_touch_session(
    std::unordered_map<std::string, AuthSession>::iterator it) {
  if (it == auth_sessions.end()) return nullptr;

  // Absolute lifetime.
  if (!it->second.expiresAt.empty() && it->second.expiresAt < now_utc()) {
    auth_sessions.erase(it);
    return nullptr;
  }

  const int64_t now = now_epoch_seconds();
  // Inactivity timeout.
  if (idle_timeout_seconds > 0 && it->second.lastSeenEpoch > 0 &&
      now - it->second.lastSeenEpoch > idle_timeout_seconds) {
    auth_sessions.erase(it);
    return nullptr;
  }

  it->second.lastSeenEpoch = now;  // slide the idle window forward
  return &it->second;
}

std::optional<AuthSession> AppContext::find_auth(const crow::request &request) {
  auto token = extract_auth_token_from_request(request);

  if (!token) return std::nullopt;
  std::lock_guard<std::mutex> lock(auth_mutex);
  AuthSession *sess = validate_and_touch_session(auth_sessions.find(*token));
  if (!sess) return std::nullopt;
  return *sess;
}

std::optional<AuthSession> AppContext::find_auth_by_token(
    const std::string &token) {
  if (token.empty()) return std::nullopt;
  std::lock_guard<std::mutex> lock(auth_mutex);
  AuthSession *sess = validate_and_touch_session(auth_sessions.find(token));
  if (!sess) return std::nullopt;
  return *sess;
}

bool AppContext::mfa_required_for_role(const std::string &role) const {
  if (mfa_policy == "all") return true;
  if (mfa_policy == "admins") return is_user_role(role, "admin");
  return false;  // "none" or unknown → not enforced
}

bool AppContext::password_was_recently_used(int user_id,
                                            const std::string &new_plaintext) {
  if (password_history_count <= 0) return false;

  // Current password counts as "recently used".
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    auto it = users.find(user_id);
    if (it != users.end() && !it->second.password.empty() &&
        crypto::verify_password(new_plaintext, it->second.password)) {
      return true;
    }
  }

  // Snapshot the last N historical hashes, then verify outside the DB lock
  // (scrypt is deliberately slow — don't hold sqlite.mutex while hashing).
  std::vector<std::string> hashes;
  {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    if (!sqlite.db) return false;
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(
            sqlite.db,
            "SELECT password_hash FROM password_history WHERE user_id=?1 "
            "ORDER BY id DESC LIMIT ?2;",
            -1, &stmt, nullptr) == SQLITE_OK) {
      sqlite3_bind_int(stmt, 1, user_id);
      sqlite3_bind_int(stmt, 2, password_history_count);
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *h = sqlite3_column_text(stmt, 0);
        if (h) hashes.emplace_back(reinterpret_cast<const char *>(h));
      }
    }
    sqlite3_finalize(stmt);
  }
  for (const auto &h : hashes) {
    if (crypto::verify_password(new_plaintext, h)) return true;
  }
  return false;
}

void AppContext::record_password_in_history(int user_id,
                                            const std::string &password_hash) {
  if (password_history_count <= 0 || password_hash.empty()) return;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  if (!sqlite.db) return;

  sqlite3_stmt *ins = nullptr;
  if (sqlite3_prepare_v2(
          sqlite.db,
          "INSERT INTO password_history(user_id,password_hash,created_at) "
          "VALUES(?1,?2,?3);",
          -1, &ins, nullptr) == SQLITE_OK) {
    const std::string ts = now_utc();
    sqlite3_bind_int(ins, 1, user_id);
    sqlite3_bind_text(ins, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 3, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(ins);
  }
  sqlite3_finalize(ins);

  // Keep only the most recent N entries per user.
  sqlite3_stmt *del = nullptr;
  if (sqlite3_prepare_v2(
          sqlite.db,
          "DELETE FROM password_history WHERE user_id=?1 AND id NOT IN "
          "(SELECT id FROM password_history WHERE user_id=?1 "
          "ORDER BY id DESC LIMIT ?2);",
          -1, &del, nullptr) == SQLITE_OK) {
    sqlite3_bind_int(del, 1, user_id);
    sqlite3_bind_int(del, 2, password_history_count);
    sqlite3_step(del);
  }
  sqlite3_finalize(del);
}

namespace {
// Endpoints that must stay reachable for an authenticated-but-MFA-unenrolled
// user so they can actually enrol a factor (or get out). Everything else under
// /api is blocked until a second factor exists.
bool mfa_gate_path_allowed(const std::string &url) {
  const std::string path = url.substr(0, url.find('?'));
  if (path.rfind("/api/", 0) != 0) return true;  // SPA/static assets
  static const char *kAllow[] = {
      "/api/health",
      "/api/auth/login",
      "/api/auth/logout",
      "/api/auth/change-password",
      "/api/auth/bootstrap-status",
      "/api/auth/setup-2fa",
      "/api/auth/verify-2fa",
      "/api/auth/2fa-status",
      "/api/auth/mfa-preference",
      "/api/auth/webauthn/register/options",
      "/api/auth/webauthn/register/verify",
      "/api/license/status",
  };
  for (const char *p : kAllow) {
    if (path == p) return true;
  }
  return false;
}
}  // namespace

bool AppContext::mfa_enrollment_gate(const crow::request &req,
                                     crow::response &res) {
  if (mfa_policy == "none") return false;  // enforcement disabled
  if (mfa_gate_path_allowed(req.url)) return false;

  auto token = extract_auth_token_from_request(req);
  if (!token) return false;  // unauthenticated → the route's own auth answers
  auto auth = find_auth_by_token(*token);
  if (!auth) return false;
  if (!mfa_required_for_role(auth->role)) return false;

  {
    std::lock_guard<std::mutex> lock(user_mutex);
    auto it = users.find(auth->userId);
    if (it == users.end()) return false;  // unknown user → let the route decide
    if (user_has_any_mfa_enabled(it->second)) return false;  // already enrolled
  }

  crow::json::wvalue body;
  body["error"] = "mfa_enrollment_required";
  body["message"] =
      "Multi-factor authentication must be enrolled before accessing this "
      "resource.";
  res.code = 403;
  res.set_header("Content-Type", "application/json");
  res.body = body.dump();
  return true;
}

// Defined for the security middleware (which has no AppContext of its own).
extern AppContext *g_license_ctx;  // set in main.cc, defined in license.cc
namespace mfa_gate {
bool before(const crow::request &req, crow::response &res) {
  if (!g_license_ctx) return false;
  return g_license_ctx->mfa_enrollment_gate(req, res);
}
}  // namespace mfa_gate

// ── Token management ────────────────────────────────────────────────────

bool AppContext::invalidate_token(const std::string &token) {
  std::lock_guard<std::mutex> lock(auth_mutex);
  return auth_sessions.erase(token) > 0;
}

void AppContext::invalidate_user_tokens(int user_id) {
  std::lock_guard<std::mutex> lock(auth_mutex);
  for (auto it = auth_sessions.begin(); it != auth_sessions.end();) {
    if (it->second.userId == user_id)
      it = auth_sessions.erase(it);
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
  const int64_t now = now_epoch_seconds();
  std::lock_guard<std::mutex> lock(auth_mutex);
  for (auto it = auth_sessions.begin(); it != auth_sessions.end();) {
    const bool absolute_expired =
        !it->second.expiresAt.empty() && it->second.expiresAt < current;
    const bool idle_expired =
        idle_timeout_seconds > 0 && it->second.lastSeenEpoch > 0 &&
        now - it->second.lastSeenEpoch > idle_timeout_seconds;
    if (absolute_expired || idle_expired)
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
      if (res.ok) { res.ok = false; res.firstBrokenLine = n; }
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

void AppContext::init_database() {
  std::string err;
  if (!sqlite.open("endoriumfort.db", err)) {
    std::cerr << "SQLite open failed: " << err << '\n';
    return;
  }

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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
      "resource_id INTEGER DEFAULT 0,"
      "access_grant_id INTEGER DEFAULT 0,"
      "target TEXT NOT NULL,"
      "user TEXT NOT NULL,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
      "user_id INTEGER NOT NULL,"
      "profile_id INTEGER NOT NULL,"
      "created_at TEXT NOT NULL,"
      "UNIQUE(user_id, profile_id)"
      ");";
  if (!sqlite.exec(user_access_profile_schema, err))
    std::cerr << "SQLite user_access_profiles schema failed: " << err << '\n';

  const std::string access_grant_schema =
      "CREATE TABLE IF NOT EXISTS access_grants ("
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
      "id INTEGER PRIMARY KEY,"
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
}

void AppContext::seed_default_admin() {
  std::lock_guard<std::mutex> lock(user_mutex);
  if (!users.empty()) return;

  // No shared default password ships in the binary. An operator may inject one
  // for automated provisioning via ENDORIUMFORT_BOOTSTRAP_ADMIN_PASSWORD;
  // otherwise a one-time random password is generated and printed once.
  const char *env_pw = std::getenv("ENDORIUMFORT_BOOTSTRAP_ADMIN_PASSWORD");
  const bool from_env = env_pw && *env_pw;
  const std::string bootstrap_pw =
      from_env ? std::string(env_pw) : random_readable_password(24);

  UserAccount admin;
  admin.id = next_user_id.fetch_add(1);
  admin.username = "admin";
  admin.password = crypto::hash_password(bootstrap_pw);
  admin.role = "admin";
  admin.createdAt = now_utc();
  admin.updatedAt = admin.createdAt;
  admin.bootstrapPasswordChangeRequired = true;
  admin.bootstrapMfaRequired = true;
  users[admin.id] = admin;
  if (!insert_user(admin)) {
    std::cerr << "Failed to persist default admin user" << '\n';
  } else if (from_env) {
    std::cerr << "[SECURITY] Default admin 'admin' created with the password "
                 "from ENDORIUMFORT_BOOTSTRAP_ADMIN_PASSWORD. Change it right "
                 "after first login (change + MFA enrollment are enforced).\n";
  } else {
    std::cerr << "\n[SECURITY] Default admin 'admin' created with a one-time "
                 "random password (shown only once):\n\n    "
              << bootstrap_pw
              << "\n\nLog in now and change it; MFA enrollment is enforced.\n\n";
  }
}

// ── Session CRUD ────────────────────────────────────────────────────────

void AppContext::load_sessions_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, resource_id, access_grant_id, target, user, protocol, port, "
      "status, mission_ref, credential_source, max_duration_seconds, "
      "created_at, terminated_at FROM sessions";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite select failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(session_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      Session s;
      s.id = sqlite3_column_int(stmt, 0);
      s.resourceId = sqlite3_column_int(stmt, 1);
      s.accessGrantId = sqlite3_column_int(stmt, 2);
      s.target  = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      s.user    = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
      s.protocol = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
      s.port = sqlite3_column_int(stmt, 6);
      if (s.port <= 0) s.port = 22;
      s.status  = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 7));
      if (auto mission = sqlite3_column_text(stmt, 8))
        s.missionRef = reinterpret_cast<const char *>(mission);
      if (auto credential_source = sqlite3_column_text(stmt, 9))
        s.credentialSource =
            reinterpret_cast<const char *>(credential_source);
      if (s.credentialSource.empty()) s.credentialSource = "vaulted";
      s.maxDurationSeconds = sqlite3_column_int(stmt, 10);
      s.createdAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 11));
      const unsigned char *term = sqlite3_column_text(stmt, 12);
      if (term) s.terminatedAt = reinterpret_cast<const char *>(term);
      sessions[s.id] = s;
      if (s.id > max_id) max_id = s.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_session_id.store(max_id + 1);
}

bool AppContext::insert_session(const Session &session) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO sessions (id, resource_id, access_grant_id, target, user, "
      "protocol, status, port, mission_ref, credential_source, "
      "max_duration_seconds, created_at, terminated_at) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite insert prepare failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, session.id);
  sqlite3_bind_int(stmt, 2, session.resourceId);
  sqlite3_bind_int(stmt, 3, session.accessGrantId);
  sqlite3_bind_text(stmt, 4, session.target.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, session.user.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, session.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 7, session.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 8, session.port);
  if (session.missionRef.empty()) sqlite3_bind_null(stmt, 9);
  else sqlite3_bind_text(stmt, 9, session.missionRef.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 10, session.credentialSource.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 11, session.maxDurationSeconds);
  sqlite3_bind_text(stmt, 12, session.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  if (session.terminatedAt.empty()) sqlite3_bind_null(stmt, 13);
  else sqlite3_bind_text(stmt, 13, session.terminatedAt.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_session_termination(const Session &session) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql = "UPDATE sessions SET status = ?, terminated_at = ? WHERE id = ?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite update prepare failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, session.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, session.terminatedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, session.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
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

  if (sqlite.db && terminated.accessGrantId > 0) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    const char *sql =
        "UPDATE access_grants SET status=?, used_at=? WHERE id=?";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
      const std::string used_at = now_utc();
      sqlite3_bind_text(stmt, 1, "used", -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 2, used_at.c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_int(stmt, 3, terminated.accessGrantId);
      sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
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
  if (sqlite.db) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    sqlite3_stmt *stmt = nullptr;
    const char *select_sql =
        "SELECT total_sessions, total_input_events FROM user_behavior_stats "
        "WHERE username=?";
    if (sqlite3_prepare_v2(sqlite.db, select_sql, -1, &stmt, nullptr) ==
        SQLITE_OK) {
      sqlite3_bind_text(stmt, 1, terminated.user.c_str(), -1, SQLITE_TRANSIENT);
      if (sqlite3_step(stmt) == SQLITE_ROW) {
        prior_sessions = sqlite3_column_int(stmt, 0);
        prior_inputs = sqlite3_column_int64(stmt, 1);
      }
    }
    sqlite3_finalize(stmt);

    const char *upsert_sql =
        "INSERT INTO user_behavior_stats "
        "(username,total_sessions,total_duration_ms,total_input_events,"
        "updated_at) "
        "VALUES (?,1,?, ?,?) "
        "ON CONFLICT(username) DO UPDATE SET "
        "total_sessions=total_sessions+1,"
        "total_duration_ms=total_duration_ms+excluded.total_duration_ms,"
        "total_input_events=total_input_events+excluded.total_input_events,"
        "updated_at=excluded.updated_at";
    stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, upsert_sql, -1, &stmt, nullptr) !=
        SQLITE_OK) {
      behavior_ok = false;
    } else {
      int64_t duration_ms = 0;
      if (!terminated.createdAt.empty() && !terminated.terminatedAt.empty()) {
        duration_ms = 0;  // ISO conversion omitted; event counts are primary signal.
      }
      std::string updated_at = now_utc();
      sqlite3_bind_text(stmt, 1, terminated.user.c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_int64(stmt, 2, duration_ms);
      sqlite3_bind_int64(stmt, 3, input_events);
      sqlite3_bind_text(stmt, 4, updated_at.c_str(), -1, SQLITE_TRANSIENT);
      behavior_ok = sqlite3_step(stmt) == SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
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
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, name, target, protocol, port, description, image_url, "
      "image_data, tags_csv, credential_source, http_username, http_password, "
      "created_at, updated_at, ssh_username, ssh_password, "
      "require_access_justification, require_dual_approval, "
      "enable_command_guard, adaptive_access_policy, risk_level, "
      "tunnel_ticket_rate_limit_max_attempts, agent_protocol FROM resources";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite resource select failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(resource_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      Resource r;
      r.id       = sqlite3_column_int(stmt, 0);
      r.name     = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
      r.target   = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
      r.protocol = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      r.port     = sqlite3_column_int(stmt, 4);
      if (r.port <= 0) r.port = 22;
      auto desc  = sqlite3_column_text(stmt, 5);
      if (desc) r.description = reinterpret_cast<const char *>(desc);
      auto img   = sqlite3_column_text(stmt, 6);
      if (img) r.imageUrl = reinterpret_cast<const char *>(img);
      auto imgdata = sqlite3_column_text(stmt, 7);
      if (imgdata) r.imageData = reinterpret_cast<const char *>(imgdata);
      auto tags = sqlite3_column_text(stmt, 8);
      if (tags) r.tagsCsv = reinterpret_cast<const char *>(tags);
      auto credential_source = sqlite3_column_text(stmt, 9);
      if (credential_source) {
        r.credentialSource =
            reinterpret_cast<const char *>(credential_source);
      }
      if (r.credentialSource.empty()) r.credentialSource = "vaulted";
      auto hu    = sqlite3_column_text(stmt, 10);
      if (hu) r.httpUsername = reinterpret_cast<const char *>(hu);
      auto hp    = sqlite3_column_text(stmt, 11);
      if (hp) {
        std::string hp_encrypted = reinterpret_cast<const char *>(hp);
        r.httpPassword = crypto::aes256_decrypt(hp_encrypted);
      }
      r.createdAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 12));
      r.updatedAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 13));
      auto su    = sqlite3_column_text(stmt, 14);
      if (su) r.sshUsername = reinterpret_cast<const char *>(su);
      auto sp    = sqlite3_column_text(stmt, 15);
      if (sp) {
        std::string sp_encrypted = reinterpret_cast<const char *>(sp);
        r.sshPassword = crypto::aes256_decrypt(sp_encrypted);
      }
      r.requireAccessJustification = sqlite3_column_int(stmt, 16) != 0;
      r.requireDualApproval = sqlite3_column_int(stmt, 17) != 0;
      r.enableCommandGuard = sqlite3_column_int(stmt, 18) != 0;
      r.adaptiveAccessPolicy = sqlite3_column_int(stmt, 19) != 0;
      auto rl = sqlite3_column_text(stmt, 20);
      if (rl) r.riskLevel = reinterpret_cast<const char *>(rl);
      if (r.riskLevel.empty()) r.riskLevel = "low";
      r.tunnelTicketRateLimitMaxAttempts = sqlite3_column_int(stmt, 21);
      if (r.tunnelTicketRateLimitMaxAttempts < 0) {
        r.tunnelTicketRateLimitMaxAttempts = 0;
      }
      auto ap = sqlite3_column_text(stmt, 22);
      if (ap) r.agentProtocol = reinterpret_cast<const char *>(ap);
      resources[r.id] = r;
      if (r.id > max_id) max_id = r.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_resource_id.store(max_id + 1);
}

bool AppContext::insert_resource(const Resource &r) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
    const char *sql =
      "INSERT INTO resources (id, name, target, protocol, port, description, "
      "image_url, image_data, tags_csv, credential_source, http_username, "
      "http_password, created_at, updated_at, ssh_username, ssh_password, "
      "require_access_justification, require_dual_approval, "
      "enable_command_guard, adaptive_access_policy, risk_level, "
      "tunnel_ticket_rate_limit_max_attempts, agent_protocol) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite resource insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
    sqlite3_bind_int(stmt, 1, r.id);
    sqlite3_bind_text(stmt, 2, r.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, r.target.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, r.protocol.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, r.port);
    r.description.empty() ? sqlite3_bind_null(stmt, 6)
      : sqlite3_bind_text(stmt, 6, r.description.c_str(), -1, SQLITE_TRANSIENT);
    r.imageUrl.empty() ? sqlite3_bind_null(stmt, 7)
      : sqlite3_bind_text(stmt, 7, r.imageUrl.c_str(), -1, SQLITE_TRANSIENT);
    r.imageData.empty() ? sqlite3_bind_null(stmt, 8)
      : sqlite3_bind_text(stmt, 8, r.imageData.c_str(), -1, SQLITE_TRANSIENT);
    r.tagsCsv.empty() ? sqlite3_bind_null(stmt, 9)
      : sqlite3_bind_text(stmt, 9, r.tagsCsv.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, r.credentialSource.c_str(), -1, SQLITE_TRANSIENT);
    r.httpUsername.empty() ? sqlite3_bind_null(stmt, 11)
      : sqlite3_bind_text(stmt, 11, r.httpUsername.c_str(), -1, SQLITE_TRANSIENT);
    // Encrypt httpPassword before storing
    if (r.httpPassword.empty()) {
      sqlite3_bind_null(stmt, 12);
    } else {
      std::string encrypted_hp = crypto::aes256_encrypt(r.httpPassword);
      sqlite3_bind_text(stmt, 12, encrypted_hp.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(stmt, 13, r.createdAt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 14, r.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
    r.sshUsername.empty() ? sqlite3_bind_null(stmt, 15)
      : sqlite3_bind_text(stmt, 15, r.sshUsername.c_str(), -1, SQLITE_TRANSIENT);
    // Encrypt sshPassword before storing
    if (r.sshPassword.empty()) {
      sqlite3_bind_null(stmt, 16);
    } else {
      std::string encrypted_sp = crypto::aes256_encrypt(r.sshPassword);
      sqlite3_bind_text(stmt, 16, encrypted_sp.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, 17, r.requireAccessJustification ? 1 : 0);
    sqlite3_bind_int(stmt, 18, r.requireDualApproval ? 1 : 0);
    sqlite3_bind_int(stmt, 19, r.enableCommandGuard ? 1 : 0);
    sqlite3_bind_int(stmt, 20, r.adaptiveAccessPolicy ? 1 : 0);
    sqlite3_bind_text(stmt, 21, r.riskLevel.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 22, std::max(0, r.tunnelTicketRateLimitMaxAttempts));
    r.agentProtocol.empty() ? sqlite3_bind_null(stmt, 23)
      : sqlite3_bind_text(stmt, 23, r.agentProtocol.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite resource insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_resource_db(const Resource &r) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
    const char *sql =
      "UPDATE resources SET name=?, target=?, protocol=?, port=?, "
      "description=?, image_url=?, image_data=?, tags_csv=?, credential_source=?, "
      "http_username=?, http_password=?, updated_at=?, ssh_username=?, ssh_password=?, "
      "require_access_justification=?, require_dual_approval=?, "
      "enable_command_guard=?, adaptive_access_policy=?, risk_level=?, "
      "tunnel_ticket_rate_limit_max_attempts=?, agent_protocol=? "
      "WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite resource update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, r.name.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, r.target.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, r.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, r.port);
    r.description.empty() ? sqlite3_bind_null(stmt, 5)
      : sqlite3_bind_text(stmt, 5, r.description.c_str(), -1, SQLITE_TRANSIENT);
    r.imageUrl.empty() ? sqlite3_bind_null(stmt, 6)
      : sqlite3_bind_text(stmt, 6, r.imageUrl.c_str(), -1, SQLITE_TRANSIENT);
    r.imageData.empty() ? sqlite3_bind_null(stmt, 7)
      : sqlite3_bind_text(stmt, 7, r.imageData.c_str(), -1, SQLITE_TRANSIENT);
    r.tagsCsv.empty() ? sqlite3_bind_null(stmt, 8)
      : sqlite3_bind_text(stmt, 8, r.tagsCsv.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, r.credentialSource.c_str(), -1, SQLITE_TRANSIENT);
    r.httpUsername.empty() ? sqlite3_bind_null(stmt, 10)
      : sqlite3_bind_text(stmt, 10, r.httpUsername.c_str(), -1, SQLITE_TRANSIENT);
    // Encrypt httpPassword before storing
    if (r.httpPassword.empty()) {
      sqlite3_bind_null(stmt, 11);
    } else {
      std::string encrypted_hp = crypto::aes256_encrypt(r.httpPassword);
      sqlite3_bind_text(stmt, 11, encrypted_hp.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(stmt, 12, r.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
    r.sshUsername.empty() ? sqlite3_bind_null(stmt, 13)
      : sqlite3_bind_text(stmt, 13, r.sshUsername.c_str(), -1, SQLITE_TRANSIENT);
    // Encrypt sshPassword before storing
    if (r.sshPassword.empty()) {
      sqlite3_bind_null(stmt, 14);
    } else {
      std::string encrypted_sp = crypto::aes256_encrypt(r.sshPassword);
      sqlite3_bind_text(stmt, 14, encrypted_sp.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, 15, r.requireAccessJustification ? 1 : 0);
    sqlite3_bind_int(stmt, 16, r.requireDualApproval ? 1 : 0);
    sqlite3_bind_int(stmt, 17, r.enableCommandGuard ? 1 : 0);
    sqlite3_bind_int(stmt, 18, r.adaptiveAccessPolicy ? 1 : 0);
    sqlite3_bind_text(stmt, 19, r.riskLevel.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 20, std::max(0, r.tunnelTicketRateLimitMaxAttempts));
    r.agentProtocol.empty() ? sqlite3_bind_null(stmt, 21)
      : sqlite3_bind_text(stmt, 21, r.agentProtocol.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 22, r.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite resource update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::delete_resource_db(int resource_id) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql = "DELETE FROM resources WHERE id = ?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite resource delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, resource_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite resource delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

// ── User CRUD ───────────────────────────────────────────────────────────

void AppContext::load_users_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, username, password, role, created_at, updated_at, "
      "bootstrap_password_change_required, bootstrap_mfa_required, "
      "totp_enabled, totp_secret, preferred_mfa_method FROM users";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite user select failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      UserAccount u;
      u.id       = sqlite3_column_int(stmt, 0);
      u.username = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
      u.password = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
      u.role     = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      u.createdAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
      u.updatedAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
      u.bootstrapPasswordChangeRequired = sqlite3_column_int(stmt, 6) != 0;
      u.bootstrapMfaRequired = sqlite3_column_int(stmt, 7) != 0;
      u.totpEnabled = sqlite3_column_int(stmt, 8) != 0;
      auto secret = sqlite3_column_text(stmt, 9);
      if (secret) u.totpSecret = reinterpret_cast<const char *>(secret);
      auto preferred = sqlite3_column_text(stmt, 10);
      if (preferred) u.preferredMfaMethod = reinterpret_cast<const char *>(preferred);
      users[u.id] = u;
      if (u.id > max_id) max_id = u.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_user_id.store(max_id + 1);
}

bool AppContext::insert_user(const UserAccount &u) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO users (id, username, password, role, created_at, "
      "updated_at, bootstrap_password_change_required, "
      "bootstrap_mfa_required, totp_enabled, totp_secret, preferred_mfa_method) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite user insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, u.id);
  sqlite3_bind_text(stmt, 2, u.username.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, u.password.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, u.role.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, u.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, u.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 7, u.bootstrapPasswordChangeRequired ? 1 : 0);
  sqlite3_bind_int(stmt, 8, u.bootstrapMfaRequired ? 1 : 0);
  sqlite3_bind_int(stmt, 9, u.totpEnabled ? 1 : 0);
  u.totpSecret.empty()
      ? sqlite3_bind_null(stmt, 10)
      : sqlite3_bind_text(stmt, 10, u.totpSecret.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 11, u.preferredMfaMethod.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite user insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_user_db(const UserAccount &u) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE users SET password=?, role=?, updated_at=?, "
      "bootstrap_password_change_required=?, bootstrap_mfa_required=?, "
      "totp_enabled=?, totp_secret=?, preferred_mfa_method=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite user update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, u.password.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, u.role.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, u.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, u.bootstrapPasswordChangeRequired ? 1 : 0);
  sqlite3_bind_int(stmt, 5, u.bootstrapMfaRequired ? 1 : 0);
  sqlite3_bind_int(stmt, 6, u.totpEnabled ? 1 : 0);
  u.totpSecret.empty()
      ? sqlite3_bind_null(stmt, 7)
      : sqlite3_bind_text(stmt, 7, u.totpSecret.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 8, u.preferredMfaMethod.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 9, u.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite user update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::delete_user_db(int user_id) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  sqlite3_stmt *cleanup_stmt = nullptr;
  const char *cleanup_sql =
      "DELETE FROM user_webauthn_credentials WHERE user_id = ?";
  if (sqlite3_prepare_v2(sqlite.db, cleanup_sql, -1, &cleanup_stmt, nullptr) ==
      SQLITE_OK) {
    sqlite3_bind_int(cleanup_stmt, 1, user_id);
    sqlite3_step(cleanup_stmt);
  }
  sqlite3_finalize(cleanup_stmt);
  // RGPD erasure completeness: also drop the user's password history (hashes
  // derived from their secrets).
  sqlite3_stmt *ph_stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db,
                         "DELETE FROM password_history WHERE user_id = ?", -1,
                         &ph_stmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_int(ph_stmt, 1, user_id);
    sqlite3_step(ph_stmt);
  }
  sqlite3_finalize(ph_stmt);
  const char *sql = "DELETE FROM users WHERE id = ?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite user delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, user_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite user delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

// ── Permissions ─────────────────────────────────────────────────────────

std::vector<int> AppContext::get_resource_permissions(int user_id) {
  std::unordered_set<int> unique_ids;
  std::vector<AccessProfile> assigned_profiles;
  if (!sqlite.db) return {};
  {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    const char *sql =
        "SELECT resource_id FROM user_resource_permissions WHERE user_id = ?";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
      std::cerr << "SQLite perm select failed: " << sqlite3_errmsg(sqlite.db) << '\n';
      return {};
    }
    sqlite3_bind_int(stmt, 1, user_id);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      unique_ids.insert(sqlite3_column_int(stmt, 0));
    }
    sqlite3_finalize(stmt);

    const char *profile_sql =
        "SELECT p.id, p.name, p.description, p.resource_tags_csv, "
        "p.resource_ids_csv, p.policy_id, p.created_at, p.updated_at "
        "FROM access_profiles p "
        "INNER JOIN user_access_profiles up ON up.profile_id = p.id "
        "WHERE up.user_id = ?";
    stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, profile_sql, -1, &stmt, nullptr) ==
        SQLITE_OK) {
      sqlite3_bind_int(stmt, 1, user_id);
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        AccessProfile profile;
        profile.id = sqlite3_column_int(stmt, 0);
        if (auto value = sqlite3_column_text(stmt, 1))
          profile.name = reinterpret_cast<const char *>(value);
        if (auto value = sqlite3_column_text(stmt, 2))
          profile.description = reinterpret_cast<const char *>(value);
        if (auto value = sqlite3_column_text(stmt, 3))
          profile.resourceTagsCsv = reinterpret_cast<const char *>(value);
        if (auto value = sqlite3_column_text(stmt, 4))
          profile.resourceIdsCsv = reinterpret_cast<const char *>(value);
        profile.policyId = sqlite3_column_int(stmt, 5);
        if (auto value = sqlite3_column_text(stmt, 6))
          profile.createdAt = reinterpret_cast<const char *>(value);
        if (auto value = sqlite3_column_text(stmt, 7))
          profile.updatedAt = reinterpret_cast<const char *>(value);
        assigned_profiles.push_back(profile);
      }
    }
    sqlite3_finalize(stmt);
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
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT OR IGNORE INTO user_resource_permissions "
      "(user_id, resource_id, created_at) VALUES (?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite perm insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_int(stmt, 2, resource_id);
  sqlite3_bind_text(stmt, 3, now_utc().c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite perm insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::revoke_resource_permission(int user_id, int resource_id) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "DELETE FROM user_resource_permissions WHERE user_id=? AND resource_id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite perm delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_int(stmt, 2, resource_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite perm delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
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
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE users SET totp_enabled=?, totp_secret=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite TOTP update failed: " << sqlite3_errmsg(sqlite.db)
              << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, enabled ? 1 : 0);
  secret.empty()
      ? sqlite3_bind_null(stmt, 2)
      : sqlite3_bind_text(stmt, 2, secret.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, user_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite TOTP update failed: " << sqlite3_errmsg(sqlite.db)
              << '\n';
  sqlite3_finalize(stmt);
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
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE users SET preferred_mfa_method=?, updated_at=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite MFA preference update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  std::string ts = now_utc();
  sqlite3_bind_text(stmt, 1, method.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, ts.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, user_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite MFA preference update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

void AppContext::load_webauthn_credentials_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, user_id, credential_id, public_key_spki, sign_count, label, "
      "transports_csv, created_at, last_used_at "
      "FROM user_webauthn_credentials";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite WebAuthn select failed: " << sqlite3_errmsg(sqlite.db)
              << '\n';
    return;
  }
  int max_id = 0;
  std::lock_guard<std::mutex> webauthn_lock(webauthn_mutex);
  std::lock_guard<std::mutex> user_lock(user_mutex);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    WebAuthnCredential credential;
    credential.id = sqlite3_column_int(stmt, 0);
    credential.userId = sqlite3_column_int(stmt, 1);
    credential.credentialId =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
    credential.publicKeySpki =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
    credential.signCount = sqlite3_column_int(stmt, 4);
    if (auto value = sqlite3_column_text(stmt, 5))
      credential.label = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 6))
      credential.transportsCsv = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 7))
      credential.createdAt = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 8))
      credential.lastUsedAt = reinterpret_cast<const char *>(value);

    webauthn_credentials[credential.id] = credential;
    webauthn_credential_by_external_id[credential.credentialId] = credential.id;
    auto user_it = users.find(credential.userId);
    if (user_it != users.end()) {
      user_it->second.webauthnCredentialCount += 1;
    }
    if (credential.id > max_id) max_id = credential.id;
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_webauthn_credential_id.store(max_id + 1);
}

bool AppContext::insert_webauthn_credential(const WebAuthnCredential &credential) {
  {
    std::lock_guard<std::mutex> webauthn_lock(webauthn_mutex);
    if (webauthn_credential_by_external_id.count(credential.credentialId)) {
      return false;
    }
  }
  if (sqlite.db) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    const char *sql =
        "INSERT INTO user_webauthn_credentials "
        "(id, user_id, credential_id, public_key_spki, sign_count, label, "
        "transports_csv, created_at, last_used_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
      std::cerr << "SQLite WebAuthn insert failed: " << sqlite3_errmsg(sqlite.db)
                << '\n';
      return false;
    }
    sqlite3_bind_int(stmt, 1, credential.id);
    sqlite3_bind_int(stmt, 2, credential.userId);
    sqlite3_bind_text(stmt, 3, credential.credentialId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, credential.publicKeySpki.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, credential.signCount);
    credential.label.empty()
        ? sqlite3_bind_null(stmt, 6)
        : sqlite3_bind_text(stmt, 6, credential.label.c_str(), -1, SQLITE_TRANSIENT);
    credential.transportsCsv.empty()
        ? sqlite3_bind_null(stmt, 7)
        : sqlite3_bind_text(stmt, 7, credential.transportsCsv.c_str(), -1,
                            SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, credential.createdAt.c_str(), -1, SQLITE_TRANSIENT);
    credential.lastUsedAt.empty()
        ? sqlite3_bind_null(stmt, 9)
        : sqlite3_bind_text(stmt, 9, credential.lastUsedAt.c_str(), -1,
                            SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok)
      std::cerr << "SQLite WebAuthn insert failed: " << sqlite3_errmsg(sqlite.db)
                << '\n';
    sqlite3_finalize(stmt);
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
  if (sqlite.db) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    const char *sql =
        "UPDATE user_webauthn_credentials SET sign_count=?, label=?, "
        "transports_csv=?, last_used_at=? WHERE id=?";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
      std::cerr << "SQLite WebAuthn update failed: " << sqlite3_errmsg(sqlite.db)
                << '\n';
      return false;
    }
    sqlite3_bind_int(stmt, 1, credential.signCount);
    credential.label.empty()
        ? sqlite3_bind_null(stmt, 2)
        : sqlite3_bind_text(stmt, 2, credential.label.c_str(), -1, SQLITE_TRANSIENT);
    credential.transportsCsv.empty()
        ? sqlite3_bind_null(stmt, 3)
        : sqlite3_bind_text(stmt, 3, credential.transportsCsv.c_str(), -1,
                            SQLITE_TRANSIENT);
    credential.lastUsedAt.empty()
        ? sqlite3_bind_null(stmt, 4)
        : sqlite3_bind_text(stmt, 4, credential.lastUsedAt.c_str(), -1,
                            SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, credential.id);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok)
      std::cerr << "SQLite WebAuthn update failed: " << sqlite3_errmsg(sqlite.db)
                << '\n';
    sqlite3_finalize(stmt);
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

  if (sqlite.db) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    const char *sql = "DELETE FROM user_webauthn_credentials WHERE id=?";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
      std::cerr << "SQLite WebAuthn delete failed: " << sqlite3_errmsg(sqlite.db)
                << '\n';
      return false;
    }
    sqlite3_bind_int(stmt, 1, credential_id);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok)
      std::cerr << "SQLite WebAuthn delete failed: " << sqlite3_errmsg(sqlite.db)
                << '\n';
    sqlite3_finalize(stmt);
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
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql = "UPDATE users SET password=?, updated_at=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite password update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  std::string ts = now_utc();
  sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, ts.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, user_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite password update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
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
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE users SET bootstrap_password_change_required=?, "
      "bootstrap_mfa_required=?, updated_at=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite bootstrap flag update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  std::string ts = now_utc();
  sqlite3_bind_int(stmt, 1, password_change_required ? 1 : 0);
  sqlite3_bind_int(stmt, 2, mfa_required ? 1 : 0);
  sqlite3_bind_text(stmt, 3, ts.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, user_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite bootstrap flag update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
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
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, session_id, file_path, created_at, closed_at, "
      "duration_ms, file_size FROM session_recordings";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite recording select failed: " << sqlite3_errmsg(sqlite.db)
              << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(recording_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      SessionRecording r;
      r.id = sqlite3_column_int(stmt, 0);
      r.sessionId = sqlite3_column_int(stmt, 1);
      r.filePath =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
      r.createdAt =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      auto closed = sqlite3_column_text(stmt, 4);
      if (closed) r.closedAt = reinterpret_cast<const char *>(closed);
      r.durationMs = sqlite3_column_int64(stmt, 5);
      r.fileSize = static_cast<size_t>(sqlite3_column_int64(stmt, 6));
      recordings[r.id] = r;
      if (r.id > max_id) max_id = r.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_recording_id.store(max_id + 1);
}

bool AppContext::insert_recording(const SessionRecording &rec) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO session_recordings (id, session_id, file_path, created_at) "
      "VALUES (?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite recording insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, rec.id);
  sqlite3_bind_int(stmt, 2, rec.sessionId);
  sqlite3_bind_text(stmt, 3, rec.filePath.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite recording insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_recording_close(const SessionRecording &rec) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE session_recordings SET closed_at=?, duration_ms=?, file_size=? "
      "WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite recording update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, rec.closedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 2, rec.durationMs);
  sqlite3_bind_int64(stmt, 3, static_cast<int64_t>(rec.fileSize));
  sqlite3_bind_int(stmt, 4, rec.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite recording update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::append_session_dna_entry(int session_id, int audit_event_id,
                                          const std::string &event_type,
                                          const std::string &payload_json,
                                          const std::string &created_at) {
  if (!sqlite.db || session_id <= 0 || audit_event_id <= 0) return false;
  std::lock_guard<std::mutex> lock(sqlite.mutex);

  std::string prev_hash = "GENESIS";
  sqlite3_stmt *select_stmt = nullptr;
  const char *select_sql =
      "SELECT chain_hash FROM session_dna_chain WHERE session_id=? "
      "ORDER BY id DESC LIMIT 1";
  if (sqlite3_prepare_v2(sqlite.db, select_sql, -1, &select_stmt, nullptr) ==
      SQLITE_OK) {
    sqlite3_bind_int(select_stmt, 1, session_id);
    if (sqlite3_step(select_stmt) == SQLITE_ROW) {
      const unsigned char *hash_text = sqlite3_column_text(select_stmt, 0);
      if (hash_text) {
        prev_hash = reinterpret_cast<const char *>(hash_text);
      }
    }
  }
  sqlite3_finalize(select_stmt);

  const std::string payload_hash = crypto::sha256_hex(payload_json);
  const std::string chain_input = prev_hash + "|" + event_type + "|" +
                                  payload_hash + "|" + created_at;
  const std::string chain_hash = crypto::sha256_hex(chain_input);

  sqlite3_stmt *insert_stmt = nullptr;
  const char *insert_sql =
      "INSERT INTO session_dna_chain "
      "(session_id, audit_event_id, event_type, created_at, prev_hash, "
      "payload_hash, chain_hash) VALUES (?, ?, ?, ?, ?, ?, ?)";
  if (sqlite3_prepare_v2(sqlite.db, insert_sql, -1, &insert_stmt, nullptr) !=
      SQLITE_OK) {
    std::cerr << "SQLite session_dna insert prepare failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(insert_stmt, 1, session_id);
  sqlite3_bind_int(insert_stmt, 2, audit_event_id);
  sqlite3_bind_text(insert_stmt, 3, event_type.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 4, created_at.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 5, prev_hash.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 6, payload_hash.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 7, chain_hash.c_str(), -1, SQLITE_TRANSIENT);
  const bool ok = sqlite3_step(insert_stmt) == SQLITE_DONE;
  if (!ok) {
    std::cerr << "SQLite session_dna insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  }
  sqlite3_finalize(insert_stmt);
  return ok;
}

std::vector<SessionDnaEntry> AppContext::get_session_dna_chain(int session_id) {
  std::vector<SessionDnaEntry> entries;
  if (!sqlite.db || session_id <= 0) return entries;

  std::lock_guard<std::mutex> lock(sqlite.mutex);
  sqlite3_stmt *stmt = nullptr;
  const char *sql =
      "SELECT id, session_id, audit_event_id, event_type, created_at, "
      "prev_hash, payload_hash, chain_hash "
      "FROM session_dna_chain WHERE session_id=? ORDER BY id ASC";
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite session_dna select failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return entries;
  }
  sqlite3_bind_int(stmt, 1, session_id);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    SessionDnaEntry entry;
    entry.id = sqlite3_column_int(stmt, 0);
    entry.sessionId = sqlite3_column_int(stmt, 1);
    entry.auditEventId = sqlite3_column_int(stmt, 2);
    entry.eventType =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
    entry.createdAt =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
    entry.prevHash =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
    entry.payloadHash =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
    entry.chainHash =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 7));
    entries.push_back(entry);
  }
  sqlite3_finalize(stmt);
  return entries;
}

// ── Access Requests ────────────────────────────────────────────────────

void AppContext::load_access_requests_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, resource_id, resource_name, requester, requester_role, "
      "status, justification, ticket_id, created_at, reviewed_at, reviewed_by "
      "FROM access_requests";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite access request select failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }

  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(access_request_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      AccessRequest req;
      req.id = sqlite3_column_int(stmt, 0);
      req.resourceId = sqlite3_column_int(stmt, 1);
      auto name = sqlite3_column_text(stmt, 2);
      if (name) req.resourceName = reinterpret_cast<const char *>(name);
      req.requester = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      req.requesterRole =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
      req.status = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
      auto just = sqlite3_column_text(stmt, 6);
      if (just) req.justification = reinterpret_cast<const char *>(just);
      auto ticket = sqlite3_column_text(stmt, 7);
      if (ticket) req.ticketId = reinterpret_cast<const char *>(ticket);
      req.createdAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 8));
      auto reviewed_at = sqlite3_column_text(stmt, 9);
      if (reviewed_at) req.reviewedAt = reinterpret_cast<const char *>(reviewed_at);
      auto reviewed_by = sqlite3_column_text(stmt, 10);
      if (reviewed_by) req.reviewedBy = reinterpret_cast<const char *>(reviewed_by);

      access_requests[req.id] = req;
      if (req.id > max_id) max_id = req.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_access_request_id.store(max_id + 1);
}

bool AppContext::insert_access_request(const AccessRequest &req) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO access_requests "
      "(id, resource_id, resource_name, requester, requester_role, status, "
      "justification, ticket_id, created_at, reviewed_at, reviewed_by) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite access request insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, req.id);
  sqlite3_bind_int(stmt, 2, req.resourceId);
  req.resourceName.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, req.resourceName.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, req.requester.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, req.requesterRole.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, req.status.c_str(), -1, SQLITE_TRANSIENT);
  req.justification.empty()
      ? sqlite3_bind_null(stmt, 7)
      : sqlite3_bind_text(stmt, 7, req.justification.c_str(), -1,
                          SQLITE_TRANSIENT);
  req.ticketId.empty()
      ? sqlite3_bind_null(stmt, 8)
      : sqlite3_bind_text(stmt, 8, req.ticketId.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, req.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  req.reviewedAt.empty()
      ? sqlite3_bind_null(stmt, 10)
      : sqlite3_bind_text(stmt, 10, req.reviewedAt.c_str(), -1,
                          SQLITE_TRANSIENT);
  req.reviewedBy.empty()
      ? sqlite3_bind_null(stmt, 11)
      : sqlite3_bind_text(stmt, 11, req.reviewedBy.c_str(), -1,
                          SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite access request insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_access_request(const AccessRequest &req) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE access_requests SET status=?, reviewed_at=?, reviewed_by=? "
      "WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite access request update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, req.status.c_str(), -1, SQLITE_TRANSIENT);
  req.reviewedAt.empty()
      ? sqlite3_bind_null(stmt, 2)
      : sqlite3_bind_text(stmt, 2, req.reviewedAt.c_str(), -1,
                          SQLITE_TRANSIENT);
  req.reviewedBy.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, req.reviewedBy.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, req.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite access request update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
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
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, resource_id, requester, username, status, issued_at, "
      "expires_at, used_at FROM ephemeral_credentials";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite ephemeral credential select failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }

  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(ephemeral_credential_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      EphemeralCredentialLease lease;
      lease.id = sqlite3_column_int(stmt, 0);
      lease.resourceId = sqlite3_column_int(stmt, 1);
      lease.requester =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
      lease.username =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      lease.status = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
      lease.issuedAt =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
      lease.expiresAt =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
      auto used_at = sqlite3_column_text(stmt, 7);
      if (used_at) lease.usedAt = reinterpret_cast<const char *>(used_at);
      ephemeral_credentials[lease.id] = lease;
      if (lease.id > max_id) max_id = lease.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_ephemeral_credential_id.store(max_id + 1);
}

bool AppContext::insert_ephemeral_credential(
    const EphemeralCredentialLease &lease) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO ephemeral_credentials "
      "(id, resource_id, requester, username, status, issued_at, expires_at, "
      "used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite ephemeral credential insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }

  sqlite3_bind_int(stmt, 1, lease.id);
  sqlite3_bind_int(stmt, 2, lease.resourceId);
  sqlite3_bind_text(stmt, 3, lease.requester.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, lease.username.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, lease.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, lease.issuedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 7, lease.expiresAt.c_str(), -1, SQLITE_TRANSIENT);
  lease.usedAt.empty()
      ? sqlite3_bind_null(stmt, 8)
      : sqlite3_bind_text(stmt, 8, lease.usedAt.c_str(), -1, SQLITE_TRANSIENT);

  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite ephemeral credential insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_ephemeral_credential(
    const EphemeralCredentialLease &lease) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE ephemeral_credentials SET status=?, expires_at=?, used_at=? "
      "WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite ephemeral credential update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }

  sqlite3_bind_text(stmt, 1, lease.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, lease.expiresAt.c_str(), -1, SQLITE_TRANSIENT);
  lease.usedAt.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, lease.usedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, lease.id);

  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite ephemeral credential update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}
