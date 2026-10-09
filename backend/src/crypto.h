#pragma once
// ─── EndoriumFort — Cryptographic utilities ─────────────────────────────
// SHA-256 helpers, password hashing with migration support, and password policy.

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace crypto {

// ═══════════════════════════════════════════════════════════════════════
//  SHA-256 (via OpenSSL EVP — no home-grown hash implementation)
// ═══════════════════════════════════════════════════════════════════════

/// Compute SHA-256 hash of arbitrary data.
inline std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len) {
  std::array<uint8_t, 32> digest{};
  unsigned int out_len = 0;
  EVP_Digest(data, len, digest.data(), &out_len, EVP_sha256(), nullptr);
  return digest;
}

inline std::string sha256_hex(const std::string &input) {
  auto digest =
      sha256(reinterpret_cast<const uint8_t *>(input.data()), input.size());
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (auto byte : digest) {
    out += hex[byte >> 4];
    out += hex[byte & 0x0F];
  }
  return out;
}

inline std::string hmac_sha256_hex(const std::string &key,
                                   const std::string &message) {
  unsigned char mac[EVP_MAX_MD_SIZE];
  size_t mac_len = 0;
  if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr,
                 key.data(), key.size(),
                 reinterpret_cast<const unsigned char *>(message.data()),
                 message.size(), mac, sizeof(mac), &mac_len)) {
    return {};
  }
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(mac_len * 2);
  for (size_t i = 0; i < mac_len; ++i) {
    out += hex[mac[i] >> 4];
    out += hex[mac[i] & 0x0F];
  }
  return out;
}

inline bool constant_time_equals(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  // OpenSSL's constant-time comparison (avoids a home-grown timing-safe loop).
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  Salt generation
// ═══════════════════════════════════════════════════════════════════════

/// Generate a random 16-byte hex salt (32 hex chars) from the CSPRNG.
inline std::string generate_salt() {
  unsigned char buf[16];
  if (RAND_bytes(buf, sizeof(buf)) != 1) return {};
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(sizeof(buf) * 2);
  for (unsigned char b : buf) {
    out += hex[b >> 4];
    out += hex[b & 0x0F];
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════
//  Password hashing: scrypt (primary), legacy SHA-256 migration support
// ═══════════════════════════════════════════════════════════════════════

inline std::string hex_encode(const unsigned char *data, size_t len) {
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    const unsigned char byte = data[i];
    out += hex[byte >> 4];
    out += hex[byte & 0x0F];
  }
  return out;
}

inline bool hex_decode(const std::string &hex_value, std::string &out) {
  if (hex_value.size() % 2 != 0) return false;
  auto decode_nibble = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
    return -1;
  };
  out.clear();
  out.reserve(hex_value.size() / 2);
  for (size_t i = 0; i < hex_value.size(); i += 2) {
    const int hi = decode_nibble(hex_value[i]);
    const int lo = decode_nibble(hex_value[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.push_back(static_cast<char>((hi << 4) | lo));
  }
  return true;
}

inline std::string hash_password_legacy_sha256(const std::string &password,
                                               const std::string &salt) {
  const int iterations = 10000;
  std::string current = salt + ":" + password;
  for (int i = 0; i < iterations; ++i) {
    current = sha256_hex(current);
  }
  return "sha256:10000:" + salt + ":" + current;
}

inline std::string hash_password_legacy_sha256(const std::string &password) {
  return hash_password_legacy_sha256(password, generate_salt());
}

inline std::string hash_password_scrypt(const std::string &password,
                                        const std::string &salt_hex) {
  constexpr uint64_t n = 1ULL << 15;
  constexpr uint64_t r = 8;
  constexpr uint64_t p = 1;
  constexpr size_t derived_key_len = 32;
  constexpr uint64_t maxmem = 64ULL * 1024ULL * 1024ULL;
  std::string salt_bytes;
  if (!hex_decode(salt_hex, salt_bytes)) return {};
  unsigned char derived_key[derived_key_len];
  if (EVP_PBE_scrypt(password.c_str(), password.size(),
                     reinterpret_cast<const unsigned char *>(salt_bytes.data()),
                     salt_bytes.size(), n, r, p, maxmem, derived_key,
                     sizeof(derived_key)) != 1) {
    return {};
  }
  return "scrypt:32768:8:1:" + salt_hex + ":" +
         hex_encode(derived_key, sizeof(derived_key));
}

inline std::string hash_password(const std::string &password,
                                 const std::string &salt_hex) {
  return hash_password_scrypt(password, salt_hex);
}

inline std::string hash_password(const std::string &password) {
  return hash_password(password, generate_salt());
}

inline bool verify_password_legacy_sha256(const std::string &password,
                                          const std::string &stored) {
  size_t p1 = stored.find(':', 7);
  if (p1 == std::string::npos) return false;
  size_t p2 = stored.find(':', p1 + 1);
  if (p2 == std::string::npos) return false;
  const std::string salt = stored.substr(p1 + 1, p2 - p1 - 1);
  const std::string expected_hash = stored.substr(p2 + 1);
  int iterations = 10000;
  try {
    iterations = std::stoi(stored.substr(7, p1 - 7));
  } catch (...) {}

  std::string current = salt + ":" + password;
  for (int i = 0; i < iterations; ++i) {
    current = sha256_hex(current);
  }
  return current == expected_hash;
}

inline bool verify_password_scrypt(const std::string &password,
                                   const std::string &stored) {
  const std::string prefix = "scrypt:";
  constexpr uint64_t maxmem = 64ULL * 1024ULL * 1024ULL;
  if (stored.rfind(prefix, 0) != 0) return false;
  const size_t p1 = stored.find(':', prefix.size());
  const size_t p2 = stored.find(':', p1 == std::string::npos ? p1 : p1 + 1);
  const size_t p3 = stored.find(':', p2 == std::string::npos ? p2 : p2 + 1);
  const size_t p4 = stored.find(':', p3 == std::string::npos ? p3 : p3 + 1);
  if (p1 == std::string::npos || p2 == std::string::npos ||
      p3 == std::string::npos || p4 == std::string::npos) {
    return false;
  }

  uint64_t n = 0;
  uint64_t r = 0;
  uint64_t p = 0;
  try {
    n = static_cast<uint64_t>(std::stoull(stored.substr(prefix.size(), p1 - prefix.size())));
    r = static_cast<uint64_t>(std::stoull(stored.substr(p1 + 1, p2 - p1 - 1)));
    p = static_cast<uint64_t>(std::stoull(stored.substr(p2 + 1, p3 - p2 - 1)));
  } catch (...) {
    return false;
  }
  const std::string salt_hex = stored.substr(p3 + 1, p4 - p3 - 1);
  const std::string expected_hex = stored.substr(p4 + 1);
  std::string salt_bytes;
  if (!hex_decode(salt_hex, salt_bytes)) return false;
  std::string expected_bytes;
  if (!hex_decode(expected_hex, expected_bytes)) return false;
  std::vector<unsigned char> derived_key(expected_bytes.size(), 0);
  if (EVP_PBE_scrypt(password.c_str(), password.size(),
                     reinterpret_cast<const unsigned char *>(salt_bytes.data()),
                     salt_bytes.size(), n, r, p, maxmem, derived_key.data(),
                     derived_key.size()) != 1) {
    return false;
  }
  return constant_time_equals(
      std::string(reinterpret_cast<const char *>(derived_key.data()),
                  derived_key.size()),
      expected_bytes);
}

inline bool password_hash_needs_rehash(const std::string &stored) {
  return stored.rfind("scrypt:", 0) != 0;
}

/// Verify a password against a stored hash string.
/// Supports scrypt, legacy SHA-256, and legacy plaintext.
inline bool verify_password(const std::string &password,
                            const std::string &stored) {
  if (stored.rfind("scrypt:", 0) == 0) {
    return verify_password_scrypt(password, stored);
  }

  if (stored.rfind("sha256:", 0) == 0) {
    return verify_password_legacy_sha256(password, stored);
  }

  // Legacy: plaintext comparison (for migration)
  return stored == password;
}

// ═══════════════════════════════════════════════════════════════════════
//  Password policy validation
// ═══════════════════════════════════════════════════════════════════════

struct PasswordPolicyResult {
  bool valid = false;
  std::string message;
};

/// Reject commonly-used / expected / compromised passwords (NIST 800-63B
/// §5.1.1.2). This is a curated deny-list of the values attackers try first,
/// not a full breach corpus; it blocks the obvious cases offline.
inline bool is_common_password(const std::string &password) {
  std::string lower = password;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  static const char *const kBanned[] = {
      "password",   "password1", "password123", "123456",     "1234567",
      "12345678",   "123456789", "1234567890",  "qwerty",     "azerty",
      "qwertyuiop", "admin",     "administrator", "root",      "welcome",
      "letmein",    "changeme",  "iloveyou",    "monkey",     "dragon",
      "111111",     "000000",    "abc123",      "passw0rd",   "p@ssw0rd",
      "admin123",   "motdepasse", "secret",      "superadmin", "default",
      "endorium",   "endoriumfort", "bastion",   "test1234",
  };
  for (const char *b : kBanned) {
    if (lower == b) return true;
  }
  // Also reject a banned token with only a trivial suffix (e.g. "admin1!").
  for (const char *b : kBanned) {
    const std::string token(b);
    if (token.size() >= 5 && lower.rfind(token, 0) == 0 &&
        lower.size() - token.size() <= 3) {
      return true;
    }
  }
  return false;
}

/// Validate password strength. Minimum length is configurable (compliant
/// default 12 — PCI DSS v4 8.3.6, ANSSI) with an absolute floor of 8. Keeps the
/// alphanumeric composition PCI requires and rejects common passwords (NIST).
inline PasswordPolicyResult validate_password(const std::string &password,
                                              size_t min_length = 12) {
  if (min_length < 8) min_length = 8;  // never go below the absolute floor
  if (password.size() < min_length)
    return {false, "Password must be at least " + std::to_string(min_length) +
                       " characters long"};

  bool has_upper = false, has_lower = false, has_digit = false;
  for (char c : password) {
    if (c >= 'A' && c <= 'Z') has_upper = true;
    if (c >= 'a' && c <= 'z') has_lower = true;
    if (c >= '0' && c <= '9') has_digit = true;
  }

  if (!has_upper)
    return {false, "Password must contain at least one uppercase letter"};
  if (!has_lower)
    return {false, "Password must contain at least one lowercase letter"};
  if (!has_digit)
    return {false, "Password must contain at least one digit"};

  if (is_common_password(password))
    return {false,
            "Password is too common or easily guessed; choose a stronger one"};

  return {true, "ok"};
}

// ═══════════════════════════════════════════════════════════════════════
//  AES-256-GCM vault encryption/decryption
// ═══════════════════════════════════════════════════════════════════════

// Decode a 64-hex-char key into 32 raw bytes; empty on any format error.
inline std::string decode_vault_key(const std::string &key_hex) {
  std::string key_bytes;
  if (key_hex.size() != 64 || !hex_decode(key_hex, key_bytes) ||
      key_bytes.size() != 32) {
    return {};
  }
  return key_bytes;
}

/// All vault keys usable for DECRYPTION, primary first. The primary comes from
/// ENDORIUMFORT_VAULT_KEY; previous keys (comma-separated 64-hex) come from
/// ENDORIUMFORT_VAULT_KEY_OLD. This lets an operator rotate keys with no
/// downtime: set a new primary, keep the old one(s) in _OLD so existing
/// ciphertext still decrypts, and re-encrypt over time (PCI DSS 3.6.4/3.7).
inline std::vector<std::string> get_vault_keys() {
  std::vector<std::string> keys;
  if (const char *primary = std::getenv("ENDORIUMFORT_VAULT_KEY")) {
    std::string raw = decode_vault_key(std::string(primary));
    if (!raw.empty()) keys.push_back(raw);
  }
  if (const char *olds = std::getenv("ENDORIUMFORT_VAULT_KEY_OLD")) {
    const std::string s(olds);
    size_t start = 0;
    while (start <= s.size()) {
      const size_t comma = s.find(',', start);
      std::string tok = s.substr(
          start, comma == std::string::npos ? std::string::npos : comma - start);
      // Trim surrounding whitespace.
      size_t b = tok.find_first_not_of(" \t\r\n");
      size_t e = tok.find_last_not_of(" \t\r\n");
      if (b != std::string::npos) tok = tok.substr(b, e - b + 1);
      else tok.clear();
      std::string raw = decode_vault_key(tok);
      if (!raw.empty()) keys.push_back(raw);
      if (comma == std::string::npos) break;
      start = comma + 1;
    }
  }
  return keys;
}

/// The primary key used for ENCRYPTION (the first of get_vault_keys).
inline std::optional<std::string> get_vault_encryption_key() {
  auto keys = get_vault_keys();
  if (keys.empty()) return std::nullopt;
  return keys.front();
}

/// Encrypt plaintext using AES-256-GCM; returns format "aes256:v1:iv:tag:ciphertext" (all hex).
/// Returns empty string on error.
inline std::string aes256_encrypt(const std::string &plaintext) {
  auto key_opt = get_vault_encryption_key();
  if (!key_opt) {
    return {};  // No key configured, return plaintext as-is (unencrypted)
  }
  const std::string &key = *key_opt;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return {};

  // 96-bit GCM IV from the CSPRNG. IV uniqueness is critical for GCM, so this
  // must never come from a non-cryptographic PRNG (e.g. mt19937).
  unsigned char iv[12];
  if (RAND_bytes(iv, sizeof(iv)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }

  unsigned char tag[16];
  std::vector<unsigned char> ciphertext(plaintext.size() + 16);

  int len = 0;
  int ciphertext_len = 0;

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                         reinterpret_cast<const unsigned char *>(key.data()),
                         iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }

  if (EVP_EncryptUpdate(
          ctx, ciphertext.data(), &len,
          reinterpret_cast<const unsigned char *>(plaintext.data()),
          plaintext.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }
  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }
  ciphertext_len += len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }

  EVP_CIPHER_CTX_free(ctx);

  // Format: "aes256:v1:{iv_hex}:{tag_hex}:{ciphertext_hex}"
  std::string iv_hex = hex_encode(iv, 12);
  std::string tag_hex = hex_encode(tag, 16);
  std::string ciphertext_hex = hex_encode(ciphertext.data(), ciphertext_len);

  return "aes256:v1:" + iv_hex + ":" + tag_hex + ":" + ciphertext_hex;
}

// Attempt one AES-256-GCM decryption with a specific 32-byte key. Returns true
// and fills `out` only when the GCM tag authenticates (so trying keys in turn
// is safe: a wrong key simply fails the tag check).
inline bool aes256_gcm_try_decrypt(const std::string &key,
                                   const std::string &iv_bytes,
                                   const std::string &tag_bytes,
                                   const std::string &ciphertext_bytes,
                                   std::string &out) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  std::vector<unsigned char> plaintext(ciphertext_bytes.size() + 1);
  int len = 0;
  int plaintext_len = 0;
  bool ok = false;
  if (EVP_DecryptInit_ex(
          ctx, EVP_aes_256_gcm(), nullptr,
          reinterpret_cast<const unsigned char *>(key.data()),
          reinterpret_cast<const unsigned char *>(iv_bytes.data())) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                          reinterpret_cast<unsigned char *>(
                              const_cast<char *>(tag_bytes.data()))) == 1 &&
      EVP_DecryptUpdate(
          ctx, plaintext.data(), &len,
          reinterpret_cast<const unsigned char *>(ciphertext_bytes.data()),
          static_cast<int>(ciphertext_bytes.size())) == 1) {
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) == 1) {
      plaintext_len += len;
      out.assign(reinterpret_cast<char *>(plaintext.data()), plaintext_len);
      ok = true;
    }
  }
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

/// Decrypt ciphertext (format "aes256:v1:iv:tag:ciphertext") using AES-256-GCM.
/// Tries the primary key then any configured previous keys (rotation support).
/// Returns plaintext on success, empty string on error.
inline std::string aes256_decrypt(const std::string &ciphertext_packed) {
  auto keys = get_vault_keys();
  if (keys.empty()) {
    // No key, assume plaintext (for backward compatibility)
    return ciphertext_packed;
  }

  // Parse format: "aes256:v1:iv:tag:ciphertext"
  const std::string prefix = "aes256:v1:";
  if (ciphertext_packed.rfind(prefix, 0) != 0) {
    // Not encrypted or wrong format, return as-is
    return ciphertext_packed;
  }

  size_t pos = prefix.size();
  size_t iv_end = ciphertext_packed.find(':', pos);
  if (iv_end == std::string::npos) return {};

  size_t tag_end = ciphertext_packed.find(':', iv_end + 1);
  if (tag_end == std::string::npos) return {};

  std::string iv_hex = ciphertext_packed.substr(pos, iv_end - pos);
  std::string tag_hex = ciphertext_packed.substr(iv_end + 1, tag_end - iv_end - 1);
  std::string ciphertext_hex = ciphertext_packed.substr(tag_end + 1);

  std::string iv_bytes, tag_bytes, ciphertext_bytes;
  if (!hex_decode(iv_hex, iv_bytes) || iv_bytes.size() != 12) return {};
  if (!hex_decode(tag_hex, tag_bytes) || tag_bytes.size() != 16) return {};
  if (!hex_decode(ciphertext_hex, ciphertext_bytes)) return {};

  for (const auto &key : keys) {
    std::string out;
    if (aes256_gcm_try_decrypt(key, iv_bytes, tag_bytes, ciphertext_bytes, out))
      return out;
  }
  return {};  // no configured key could authenticate this ciphertext
}

}  // namespace crypto
