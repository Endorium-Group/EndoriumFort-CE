// Unit tests for mobile device registration persistence (CE core) + ES256
// signed-approval verification.
#include "app_context.h"

#include <openssl/evp.h>

#include <cstdint>
#include <iostream>
#include <string>
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

std::string b64url_encode(const unsigned char *data, size_t len) {
  static const char tbl[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  int buf = 0, bits = 0;
  for (size_t i = 0; i < len; ++i) {
    buf = (buf << 8) | data[i];
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push_back(tbl[(buf >> bits) & 0x3F]);
    }
  }
  if (bits > 0) out.push_back(tbl[(buf << (6 - bits)) & 0x3F]);
  return out;  // no padding (base64url)
}
}  // namespace

int main() {
  AppContext ctx;
  std::string err;
  if (!ctx.sqlite.open(":memory:", err)) {
    std::cerr << "cannot open in-memory db: " << err << std::endl;
    return 1;
  }
  ctx.sqlite.exec(
      "CREATE TABLE IF NOT EXISTS user_devices ("
      "id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, platform TEXT NOT NULL,"
      "label TEXT, push_provider TEXT, push_token TEXT, public_key TEXT,"
      "created_at TEXT NOT NULL, last_seen_at TEXT, UNIQUE(user_id, push_token));",
      err);

  UserDevice d;
  d.userId = 1;
  d.platform = "ios";
  d.label = "Alice iPhone";
  d.pushProvider = "apns";
  d.pushToken = "tok-aaa";
  d.publicKey = "pk1";
  const int id1 = ctx.register_user_device(d);
  expect(id1 > 0, "register returns a positive id");

  auto list1 = ctx.list_user_devices(1);
  expect(list1.size() == 1, "user 1 has exactly 1 device");
  expect(!list1.empty() && list1[0].platform == "ios" &&
             list1[0].pushProvider == "apns" && list1[0].label == "Alice iPhone",
         "device fields persisted");

  // Upsert: same (user, push_token) refreshes in place, no duplicate row.
  d.label = "Alice iPhone 15";
  d.pushProvider = "unifiedpush";
  const int id1b = ctx.register_user_device(d);
  expect(id1b == id1, "re-register keeps the same id (upsert)");
  auto list1b = ctx.list_user_devices(1);
  expect(list1b.size() == 1, "no duplicate after upsert");
  expect(!list1b.empty() && list1b[0].pushProvider == "unifiedpush",
         "upsert updated the provider");

  // A second, distinct device for user 1.
  UserDevice d2;
  d2.userId = 1;
  d2.platform = "android";
  d2.pushProvider = "fcm";
  d2.pushToken = "tok-bbb";
  const int id2 = ctx.register_user_device(d2);
  expect(id2 > 0 && id2 != id1, "second device gets a distinct id");
  expect(ctx.list_user_devices(1).size() == 2, "user 1 now has 2 devices");

  // Scoping: another user sees none of user 1's devices.
  expect(ctx.list_user_devices(2).empty(), "user 2 sees no devices");

  // Delete is owner-scoped.
  expect(!ctx.delete_user_device(2, id1), "cross-user delete is refused");
  expect(ctx.list_user_devices(1).size() == 2, "device survives refused delete");
  expect(ctx.delete_user_device(1, id1), "owner can delete own device");
  expect(ctx.list_user_devices(1).size() == 1, "one device left after delete");
  expect(!ctx.delete_user_device(1, 999999), "deleting a missing device is false");

  // ── ES256 signed-approval verification ──
  {
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    expect(pkey != nullptr, "generated EC P-256 key");

    unsigned char *spki = nullptr;
    const int spki_len = i2d_PUBKEY(pkey, &spki);
    expect(spki_len > 0, "exported SPKI public key");
    const std::string spki_b64 = b64url_encode(spki, spki_len);
    OPENSSL_free(spki);

    UserDevice signer;
    signer.userId = 7;
    signer.platform = "ios";
    signer.pushProvider = "apns";
    signer.pushToken = "tok-signer";
    signer.publicKey = spki_b64;
    const int signer_id = ctx.register_user_device(signer);
    expect(signer_id > 0, "registered device with real public key");

    const std::string message = "approve:42:2026-10-09T00:00:00Z";
    auto sign = [&](const std::string &msg) -> std::string {
      EVP_MD_CTX *md = EVP_MD_CTX_new();
      std::string out;
      if (md && EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
        size_t n = 0;
        EVP_DigestSign(md, nullptr, &n,
                       reinterpret_cast<const unsigned char *>(msg.data()),
                       msg.size());
        std::vector<unsigned char> sig(n);
        if (EVP_DigestSign(md, sig.data(), &n,
                           reinterpret_cast<const unsigned char *>(msg.data()),
                           msg.size()) == 1) {
          out = b64url_encode(sig.data(), n);
        }
      }
      if (md) EVP_MD_CTX_free(md);
      return out;
    };

    const std::string good_sig = sign(message);
    expect(!good_sig.empty(), "produced ES256 signature");
    expect(ctx.verify_device_signature(7, signer_id, message, good_sig),
           "valid signature verifies");
    expect(!ctx.verify_device_signature(7, signer_id,
                                        "approve:43:2026-10-09T00:00:00Z",
                                        good_sig),
           "signature rejected for a different message (no replay across ids)");
    expect(!ctx.verify_device_signature(999, signer_id, message, good_sig),
           "signature rejected for the wrong owner");
    expect(!ctx.verify_device_signature(7, signer_id, message, "not-a-signature"),
           "garbage signature rejected");

    EVP_PKEY_free(pkey);
  }

  if (failures == 0) std::cerr << "[device_test] ALL PASS" << std::endl;
  return failures == 0 ? 0 : 1;
}
