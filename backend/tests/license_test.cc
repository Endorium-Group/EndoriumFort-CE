// ─── EndoriumFort — license verifier unit tests ─────────────────────────────
// Generates ephemeral Ed25519 + ML-DSA-65 keypairs in-process (OpenSSL >= 3.5),
// signs tokens exactly like `openssl pkeyutl -sign -rawin` (EVP one-shot), and
// exercises the hybrid verifier + entitlement logic. No key fixtures on disk.

#include "license.h"

#include <openssl/evp.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

int g_failures = 0;

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    ++g_failures;
    return false;
  }
  std::cout << "[ok] " << message << std::endl;
  return true;
}

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

PkeyPtr keygen(const char *alg) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, alg, nullptr);
  if (!ctx) return {nullptr, &EVP_PKEY_free};
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx_guard(
      ctx, &EVP_PKEY_CTX_free);
  if (EVP_PKEY_keygen_init(ctx) != 1) return {nullptr, &EVP_PKEY_free};
  EVP_PKEY *key = nullptr;
  if (EVP_PKEY_keygen(ctx, &key) != 1) return {nullptr, &EVP_PKEY_free};
  return {key, &EVP_PKEY_free};
}

std::string spki_der(EVP_PKEY *pkey) {
  unsigned char *buf = nullptr;
  const int len = i2d_PUBKEY(pkey, &buf);
  if (len <= 0) return {};
  std::string out(reinterpret_cast<char *>(buf), static_cast<size_t>(len));
  OPENSSL_free(buf);
  return out;
}

// One-shot sign, matching `pkeyutl -sign -rawin` semantics (null digest).
std::string sign_raw(EVP_PKEY *pkey, const std::string &msg) {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                              &EVP_MD_CTX_free);
  if (!ctx) return {};
  if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey) != 1) {
    return {};
  }
  size_t siglen = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &siglen,
                     reinterpret_cast<const unsigned char *>(msg.data()),
                     msg.size()) != 1) {
    return {};
  }
  std::string sig(siglen, '\0');
  if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char *>(&sig[0]),
                     &siglen, reinterpret_cast<const unsigned char *>(msg.data()),
                     msg.size()) != 1) {
    return {};
  }
  sig.resize(siglen);
  return sig;
}

// Build a compact token. If ed_signer/ml_signer are null, that signature slot is
// filled with garbage (to test the hybrid AND requirement / wrong-key paths).
std::string make_token(const std::string &kid, const std::string &payload_json,
                       EVP_PKEY *ed_signer, EVP_PKEY *ml_signer) {
  crow::json::wvalue header;
  header["typ"] = license::kLicenseTyp;
  header["alg"] = license::kHybridAlg;
  header["kid"] = kid;
  const std::string header_b64 = webauthn::base64url_encode(header.dump());
  const std::string payload_b64 = webauthn::base64url_encode(payload_json);
  const std::string signed_input = header_b64 + "." + payload_b64;

  std::string sig_ed = ed_signer ? sign_raw(ed_signer, signed_input) : "garbage-ed";
  std::string sig_ml = ml_signer ? sign_raw(ml_signer, signed_input) : "garbage-ml";

  crow::json::wvalue sigs;
  sigs["ed25519"] = webauthn::base64url_encode(sig_ed);
  sigs["ml-dsa-65"] = webauthn::base64url_encode(sig_ml);
  const std::string sigs_b64 = webauthn::base64url_encode(sigs.dump());

  return signed_input + "." + sigs_b64;
}

std::string payload_json(const std::string &tier, const std::string &kind,
                         int64_t issuedAt, int64_t notBefore, int64_t notAfter,
                         const std::string &licenseId,
                         const std::vector<std::string> &features) {
  crow::json::wvalue p;
  p["v"] = license::kSupportedVersion;
  p["licenseId"] = licenseId;
  p["kind"] = kind;
  p["tier"] = tier;
  p["customer"] = "ACME Test";
  p["issuedAt"] = issuedAt;
  p["notBefore"] = notBefore;
  p["notAfter"] = notAfter;
  crow::json::wvalue::list feats;
  for (const auto &f : features) feats.push_back(crow::json::wvalue(f));
  p["features"] = std::move(feats);
  crow::json::wvalue binding;
  binding["type"] = "none";
  binding["value"] = "";
  p["binding"] = std::move(binding);
  return p.dump();
}

}  // namespace

int main() {
  const int64_t kNow = 1'700'000'000;  // fixed reference time
  const int64_t kDay = license::kSecondsPerDay;

  auto ed = keygen("ED25519");
  auto ml = keygen("ML-DSA-65");
  auto ed_wrong = keygen("ED25519");
  auto ml_wrong = keygen("ML-DSA-65");
  if (!expect(ed && ml && ed_wrong && ml_wrong, "keypairs generated (needs OpenSSL >= 3.5)")) {
    return 1;  // cannot proceed without keys
  }

  license::IssuerKey issuer;
  issuer.kid = "efort-test";
  issuer.ed25519_spki_der_b64url = webauthn::base64url_encode(spki_der(ed.get()));
  issuer.mldsa_spki_der_b64url = webauthn::base64url_encode(spki_der(ml.get()));
  const std::vector<license::IssuerKey> issuers = {issuer};
  const std::unordered_set<std::string> no_denylist;

  // 1. valid standard (~30d)
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "standard", kNow, kNow, kNow + 30 * kDay,
                     "efl_std", {}),
        ed.get(), ml.get());
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::Valid, "standard: Valid");
    expect(st.claims.tier == "enterprise", "standard: tier=enterprise");
    expect(st.daysRemaining >= 29 && st.daysRemaining <= 30, "standard: ~30 days remaining");
  }

  // 2. valid labs (~7d)
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("pro", "labs", kNow, kNow, kNow + 7 * kDay, "efl_lab", {}),
        ed.get(), ml.get());
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::Valid, "labs: Valid");
    expect(st.daysRemaining >= 6 && st.daysRemaining <= 7, "labs: ~7 days remaining");
  }

  // 3. valid annual (~365d)
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "annual", kNow, kNow, kNow + 365 * kDay,
                     "efl_year", {}),
        ed.get(), ml.get());
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::Valid, "annual: Valid");
    expect(st.daysRemaining >= 364 && st.daysRemaining <= 365, "annual: ~365 days remaining");
  }

  // 4. expired
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "standard", kNow - 60 * kDay, kNow - 60 * kDay,
                     kNow - 30 * kDay, "efl_exp", {}),
        ed.get(), ml.get());
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::Expired, "expired: Expired");
    expect(!license::license_allows(st, "cluster"), "expired: premium blocked");
    expect(license::license_allows(st, "sessions.create"), "expired: core still allowed");
  }

  // 5. not yet valid
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "standard", kNow, kNow + 10 * kDay,
                     kNow + 40 * kDay, "efl_future", {}),
        ed.get(), ml.get());
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::NotYetValid, "future: NotYetValid");
  }

  // 6. tampered payload (flip the token's payload segment)
  {
    std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "standard", kNow, kNow, kNow + 30 * kDay,
                     "efl_tamper", {}),
        ed.get(), ml.get());
    // Corrupt one char in the payload (2nd segment).
    const size_t first_dot = tok.find('.');
    tok[first_dot + 5] = (tok[first_dot + 5] == 'A') ? 'B' : 'A';
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::Invalid, "tampered: Invalid");
  }

  // 7. only Ed25519 valid (ML-DSA garbage) -> hybrid AND fails
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "standard", kNow, kNow, kNow + 30 * kDay,
                     "efl_edonly", {}),
        ed.get(), nullptr);
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::Invalid, "ed-only: Invalid (hybrid AND)");
  }

  // 8. only ML-DSA valid (Ed25519 garbage)
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "standard", kNow, kNow, kNow + 30 * kDay,
                     "efl_mlonly", {}),
        nullptr, ml.get());
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::Invalid, "ml-only: Invalid (hybrid AND)");
  }

  // 9. wrong signing keys (valid sigs, but not the embedded issuer keys)
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "standard", kNow, kNow, kNow + 30 * kDay,
                     "efl_wrongkey", {}),
        ed_wrong.get(), ml_wrong.get());
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::Invalid, "wrong-key: Invalid");
  }

  // 10. unknown kid
  {
    const std::string tok = make_token(
        "efort-unknown",
        payload_json("enterprise", "standard", kNow, kNow, kNow + 30 * kDay,
                     "efl_kid", {}),
        ed.get(), ml.get());
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, no_denylist);
    expect(st.state == license::LicenseState::Invalid, "unknown-kid: Invalid");
  }

  // 11. revoked
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "standard", kNow, kNow, kNow + 30 * kDay,
                     "efl_revoked", {}),
        ed.get(), ml.get());
    const std::unordered_set<std::string> denylist = {"efl_revoked"};
    const auto st = license::parse_and_verify(tok, issuers, kNow, 0, denylist);
    expect(st.state == license::LicenseState::Revoked, "revoked: Revoked");
  }

  // 12. clock handling
  {
    const std::string tok = make_token(
        "efort-test",
        payload_json("enterprise", "standard", kNow - 60 * kDay, kNow - 60 * kDay,
                     kNow - 30 * kDay, "efl_clock", {}),
        ed.get(), ml.get());
    // Watermark advanced past notAfter; clock rewound to before notAfter.
    const int64_t watermark = kNow;                 // "highest time seen"
    const int64_t rewound = kNow - 45 * kDay;       // rolled back, but still > watermark-skew? no
    // rewound is far below watermark -> gross rollback -> ClockAnomaly
    const auto anomaly =
        license::parse_and_verify(tok, issuers, rewound, watermark, no_denylist);
    expect(anomaly.state == license::LicenseState::ClockAnomaly,
           "clock: gross rollback -> ClockAnomaly");
    // Small rollback within skew, but watermark still past notAfter -> Expired
    const int64_t small_rollback = kNow - 3600;  // 1h back
    const auto expired = license::parse_and_verify(tok, issuers, small_rollback,
                                                   watermark, no_denylist);
    expect(expired.state == license::LicenseState::Expired,
           "clock: watermark keeps expired license expired");
  }

  // 13. entitlement matrix
  {
    // free tier blocks a pro feature
    const std::string free_tok = make_token(
        "efort-test",
        payload_json("free", "standard", kNow, kNow, kNow + 30 * kDay, "efl_free", {}),
        ed.get(), ml.get());
    const auto free_st = license::parse_and_verify(free_tok, issuers, kNow, 0, no_denylist);
    expect(free_st.state == license::LicenseState::Valid, "matrix: free license valid");
    expect(!license::license_allows(free_st, "rdp"), "matrix: free blocks pro (rdp)");

    // pro tier allows pro, blocks enterprise
    const std::string pro_tok = make_token(
        "efort-test",
        payload_json("pro", "standard", kNow, kNow, kNow + 30 * kDay, "efl_pro", {}),
        ed.get(), ml.get());
    const auto pro_st = license::parse_and_verify(pro_tok, issuers, kNow, 0, no_denylist);
    expect(license::license_allows(pro_st, "rdp"), "matrix: pro allows pro (rdp)");
    expect(!license::license_allows(pro_st, "cluster"), "matrix: pro blocks enterprise (cluster)");

    // pro tier + explicit enterprise add-on unlocks that one feature
    const std::string addon_tok = make_token(
        "efort-test",
        payload_json("pro", "standard", kNow, kNow, kNow + 30 * kDay, "efl_addon",
                     {"cluster"}),
        ed.get(), ml.get());
    const auto addon_st = license::parse_and_verify(addon_tok, issuers, kNow, 0, no_denylist);
    expect(license::license_allows(addon_st, "cluster"),
           "matrix: explicit add-on unlocks enterprise feature on pro tier");
    expect(!license::license_allows(addon_st, "session.dna"),
           "matrix: add-on does not unlock other enterprise features");

    // wildcard add-on
    const std::string wild_tok = make_token(
        "efort-test",
        payload_json("pro", "standard", kNow, kNow, kNow + 30 * kDay, "efl_wild",
                     {"sso.*"}),
        ed.get(), ml.get());
    const auto wild_st = license::parse_and_verify(wild_tok, issuers, kNow, 0, no_denylist);
    expect(license::license_allows(wild_st, "sso.saml"), "matrix: wildcard add-on (sso.*)");

    // core/unknown always allowed even with no license
    license::LicenseStatus none_status;  // state=None
    expect(license::license_allows(none_status, "sessions.create"),
           "matrix: no license -> core allowed");
    expect(!license::license_allows(none_status, "cluster"),
           "matrix: no license -> premium blocked");
  }

  if (g_failures == 0) {
    std::cout << "\nAll license tests passed." << std::endl;
    return 0;
  }
  std::cerr << "\n" << g_failures << " license test(s) failed." << std::endl;
  return 1;
}
