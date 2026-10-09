#pragma once
// ─── EndoriumFort — TOTP / 2FA implementation ──────────────────────────
// TOTP (RFC 6238). HMAC-SHA1 (RFC-mandated) and the secret CSPRNG both come
// from OpenSSL — no hand-rolled crypto primitives.

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace totp {

// ═══════════════════════════════════════════════════════════════════════
//  SHA-1 (FIPS 180-4) – minimal implementation
// ═══════════════════════════════════════════════════════════════════════

namespace detail {

// HMAC-SHA1 via OpenSSL (RFC 2104). SHA-1 is mandated by RFC 6238 for the
// default TOTP, so the algorithm is fixed; routing it through OpenSSL keeps the
// output standard while removing the hand-rolled SHA-1/HMAC implementation.
inline std::array<uint8_t, 20> hmac_sha1(const uint8_t *key, size_t key_len,
                                         const uint8_t *msg, size_t msg_len) {
  std::array<uint8_t, 20> out{};
  size_t out_len = 0;
  EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA1", nullptr, key, key_len, msg,
            msg_len, out.data(), out.size(), &out_len);
  return out;
}

}  // namespace detail

// ═══════════════════════════════════════════════════════════════════════
//  Base32 encode / decode (RFC 4648)
// ═══════════════════════════════════════════════════════════════════════

inline std::string base32_encode(const uint8_t *data, size_t len) {
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  std::string result;
  result.reserve((len * 8 + 4) / 5);

  uint32_t buffer = 0;
  int bits_left = 0;
  for (size_t i = 0; i < len; ++i) {
    buffer = (buffer << 8) | data[i];
    bits_left += 8;
    while (bits_left >= 5) {
      result += alphabet[(buffer >> (bits_left - 5)) & 0x1F];
      bits_left -= 5;
    }
  }
  if (bits_left > 0)
    result += alphabet[(buffer << (5 - bits_left)) & 0x1F];

  // Pad to multiple of 8
  while (result.size() % 8 != 0)
    result += '=';

  return result;
}

inline std::vector<uint8_t> base32_decode(const std::string &input) {
  auto b32val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
  };

  std::vector<uint8_t> result;
  uint32_t buffer = 0;
  int bits_left = 0;
  for (char c : input) {
    if (c == '=' || c == ' ') continue;
    int val = b32val(c);
    if (val < 0) continue;
    buffer = (buffer << 5) | static_cast<uint32_t>(val);
    bits_left += 5;
    if (bits_left >= 8) {
      result.push_back(static_cast<uint8_t>((buffer >> (bits_left - 8)) & 0xFF));
      bits_left -= 8;
    }
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════════
//  TOTP (RFC 6238) — 6-digit, 30-second period, SHA1
// ═══════════════════════════════════════════════════════════════════════

inline std::string generate_secret(int byte_count = 20) {
  // The TOTP shared secret is a long-lived MFA root key: it MUST come from a
  // CSPRNG. (mt19937 seeded from a single random_device draw would cap the
  // secret's entropy at the 32-bit seed, making it brute-forceable.)
  std::vector<uint8_t> secret(byte_count);
  if (RAND_bytes(secret.data(), byte_count) != 1) return {};
  return base32_encode(secret.data(), secret.size());
}

inline uint32_t compute_totp(const std::string &base32_secret, uint64_t time_step) {
  auto key = base32_decode(base32_secret);

  uint8_t msg[8];
  for (int i = 7; i >= 0; --i) {
    msg[i] = static_cast<uint8_t>(time_step & 0xFF);
    time_step >>= 8;
  }

  auto hmac = detail::hmac_sha1(key.data(), key.size(), msg, 8);

  int offset = hmac[19] & 0x0F;
  uint32_t code = ((static_cast<uint32_t>(hmac[offset]) & 0x7F) << 24) |
                  ((static_cast<uint32_t>(hmac[offset + 1]) & 0xFF) << 16) |
                  ((static_cast<uint32_t>(hmac[offset + 2]) & 0xFF) << 8) |
                  ((static_cast<uint32_t>(hmac[offset + 3]) & 0xFF));

  return code % 1000000;
}

inline std::string generate_code(const std::string &base32_secret,
                                  int period = 30) {
  uint64_t time_step = static_cast<uint64_t>(std::time(nullptr)) / period;
  uint32_t code = compute_totp(base32_secret, time_step);
  std::ostringstream oss;
  oss << std::setw(6) << std::setfill('0') << code;
  return oss.str();
}

inline bool verify_code(const std::string &base32_secret,
                        const std::string &user_code,
                        int period = 30, int window = 1) {
  uint64_t current = static_cast<uint64_t>(std::time(nullptr)) / period;
  for (int i = -window; i <= window; ++i) {
    uint32_t expected = compute_totp(base32_secret, current + i);
    std::ostringstream oss;
    oss << std::setw(6) << std::setfill('0') << expected;
    if (user_code == oss.str())
      return true;
  }
  return false;
}

inline std::string build_otpauth_uri(const std::string &issuer,
                                      const std::string &account,
                                      const std::string &base32_secret) {
  // otpauth://totp/Issuer:account?secret=XXX&issuer=Issuer&digits=6&period=30
  std::ostringstream oss;
  oss << "otpauth://totp/" << issuer << ":" << account
      << "?secret=" << base32_secret
      << "&issuer=" << issuer
      << "&digits=6&period=30&algorithm=SHA1";
  return oss.str();
}

} // namespace totp
