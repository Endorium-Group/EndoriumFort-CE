#pragma once
// ─── EndoriumFort — Offline license verification ────────────────────────────
// Freemium / open-core enforcement. A license is a compact JWS-style triad
//   header_b64url . payload_b64url . signatures_b64url
// signed OFFLINE with a HYBRID scheme: Ed25519 (classical) + ML-DSA-65
// (post-quantum, FIPS 204). BOTH signatures must verify (logical AND) — this
// follows ANSSI hybrid-transition guidance. Verification is fully offline and
// reuses the exact EVP_DigestVerify one-shot pattern already used for WebAuthn
// (see webauthn.h:verify_assertion_signature). ML-DSA is provided natively by
// OpenSSL >= 3.5 (no extra dependency); the same d2i_PUBKEY + EVP_DigestVerify
// path handles both key types.
//
// This module lives in the CORE (public / community edition) so that:
//   * the Community build reports its edition and can surface upgrade prompts,
//   * the Enterprise build reuses the very same verifier and entitlement logic.
//
// The verifier is a pure function (parse_and_verify) that takes injectable
// issuer keys, "now", a monotonic clock watermark, and a revocation denylist —
// which keeps it unit-testable without any global state. Runtime wiring
// (AppContext state, env loading, HTTP routes) lives in license.cc.

#include "webauthn.h"  // base64url_encode/decode (+ crow::json, OpenSSL EVP/x509)

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace license {

// ── Constants ───────────────────────────────────────────────────────────────
inline constexpr const char *kLicenseTyp = "EFLIC";           // license token
inline constexpr const char *kRevocationTyp = "EFLRL";        // revocation list
inline constexpr const char *kHybridAlg = "Ed25519+ML-DSA-65";
inline constexpr int kSupportedVersion = 1;
inline constexpr int64_t kSecondsPerDay = 86400;
// A backward clock jump larger than this (relative to the persisted watermark)
// is treated as tampering rather than a benign NTP correction.
inline constexpr int64_t kClockRollbackSkewSeconds = 24 * 3600;

// ── Types ────────────────────────────────────────────────────────────────────
enum class LicenseState {
  None,          // no license configured -> Community/free tier
  Valid,         // signatures valid and within [notBefore, notAfter)
  Expired,       // signatures valid but past notAfter (or watermark past it)
  NotYetValid,   // signatures valid but before notBefore
  Invalid,       // malformed / signature mismatch / unknown issuer
  Revoked,       // licenseId present in the signed revocation list
  ClockAnomaly,  // gross backward clock movement detected
};

inline const char *to_string(LicenseState state) {
  switch (state) {
    case LicenseState::None: return "none";
    case LicenseState::Valid: return "valid";
    case LicenseState::Expired: return "expired";
    case LicenseState::NotYetValid: return "not_yet_valid";
    case LicenseState::Invalid: return "invalid";
    case LicenseState::Revoked: return "revoked";
    case LicenseState::ClockAnomaly: return "clock_anomaly";
  }
  return "unknown";
}

// A trust anchor. Public keys only — safe to compile into the binary.
// Both key materials are the SPKI DER of the public key, base64url-encoded.
struct IssuerKey {
  std::string kid;
  std::string ed25519_spki_der_b64url;
  std::string mldsa_spki_der_b64url;
};

struct LicenseClaims {
  int version = 0;
  std::string licenseId;
  std::string kind;      // "labs" | "standard" | "annual"
  std::string tier;      // "free" | "pro" | "enterprise"
  std::string customer;
  std::vector<std::string> features;  // explicit add-ons (wildcards allowed)
  int64_t issuedAt = 0;
  int64_t notBefore = 0;
  int64_t notAfter = 0;
  std::string bindingType = "none";
  std::string bindingValue;
  int maxNodes = 0;
  int maxSeats = 0;
};

struct LicenseStatus {
  LicenseState state = LicenseState::None;
  LicenseClaims claims;
  int64_t daysRemaining = 0;
  std::string reason;
};

// ── Embedded trust anchors (public keys only — safe to compile in) ────────────
// Populate with the base64url of the issuer public-key SPKI DER, e.g. from
//   openssl pkey -in issuer_priv.pem -pubout -outform DER | base64 -w0 | tr '+/' '-_' | tr -d '='
// or the header lines printed by scripts/gen-dev-license.sh. Rotation = append a
// new kid; keep the old one until every customer has re-issued, then remove it.
// The dev key is guarded so it can never validate a production deployment.
inline const std::vector<IssuerKey> &issuer_keys() {
  static const std::vector<IssuerKey> keys = {
#ifdef ENDORIUMFORT_LICENSE_PROD_KEY
      {"efort-issuer-2026",
       "<PROD_ED25519_SPKI_DER_B64URL>",
       "<PROD_MLDSA_SPKI_DER_B64URL>"},
#endif
#ifdef ENDORIUMFORT_LICENSE_DEV_KEY
      // Non-production dev issuer (public keys only). Private keys live in the
      // gitignored keys/dev/ and are held only by the maintainer.
      {"efort-dev",
       "MCowBQYDK2VwAyEAoLH5IsOTcuSGCfLzyM5EyZnMtVTh7_9x1UeDaAsdVjE",
       "MIIHsjALBglghkgBZQMEAxIDggehAApd4s7yCgTVGqCqsOZldivoVOVxjb_JgizwlkzdZUAyPEDzo_2gNhs67didjI4XbNUHinsUB0gBzoBEJmPNyEWc31j33gntv0GL0N5aYtuSYQR1E5lZzDjaVNU-Ee2CD3q7qYA5EN6JzlKg6w317MMzyXO2cooWBLZrONqpgy9VUdSEgAQfQxAxN4geL2OlHD4xiZPk1zStXk1YMr-eryloJhVS5XVNGo6fu2udpTezPQCfqeCVIdeUwaKE0sPujQi0z4f2OOMfPc3JYYF8m1Q-tLDIfVTtxRdZ6-yfueGWJWs5ofPUB7dwLmNVEMVV1180HsTeABCFLpEfB80D0RCeF0Ya9xlRNbNLs8i07miBVC9lgdReOL7ruwZ68f5nG_8prm0vSd7bVk9kGVEDYElImgCe64nBksfezLMYyGTU0L_FJMqZ0uyHeF0a0YNotCrYvKvXkvbUUe8ksrurbaiZSE11GTcsOd1cj2pIxdWvWVd0HL3c4q7dGtSOXZ2ub01q1zziaTZfE3r4WAJcodtP0VccEjG6ON7EWuR-v_qtXTPmpPWHHOjx1S102CKsAzjHM1KUfQ0uwFfwPlL6rJxEpK0CJ332tpM9XFcoF8y9Mu6Ct7QVFmocDfSn-uBpWgHH6ddONDkVCBmCPual1pOOdYkuEMwuX0f6-pFZBZFKhQ_bvInEZNI17aBJkcKF6yozxN_NMLsXwCb_iTY_jVX70ayfLyn-1m2rVTmTXPAbP1z3BDKockPO5Ndfaqg85sa7DzuldNdXP-cr5UBpZE8GcMn93u3sEHzi7vv_a1ADnU-4KDnfjP4N6hUEsDuiHyu4Cf8sg49NkyQc8wETp2PewgO_g4UpGhqFD0fuQi97qRU-HdaecId_jQHbtLUOJPnpu9X1CBIEt6DPjurJVjAYKGS1r83oNDon4aNNZqBblLiFoh34-YCtFt3H8eFTk45t1tNXd9bZAFNqcRBpMAH70ay9cUESLr5Pq0gam2K9fUfQs4-QkCkuW85oFl6oeEqy3N_Jln2XCJa7-oF0Bgh44j_sDaFEkrXWGdnHoyQMEuepqJJnmO8yll8QlJG6f01ExxDYUpLtGDHCgXd9OBuQh_FWVmaHbVDAAtwDk3Ih6fRa0oKsjvjmMx5dN08ZQHr0FSRxVdtRPiHbQRunhmjWX8n71PI33dW-Esj2UsclI4-oBTee5aDEDrAAtbgAHd0eOjLkKJC2XjIFszIinLh-a9_MDI6a6wRZwnQebnhWBCMyBFnImVWF2ZRdYR1L0fQsiCHZpg0Dtfgaw28VLE7ztbj3B527ztViq01QjcVHqosMxV97eRtuNExWLBJqo6dlM-I7xn_yasJGyGjlvQo7o6a6y3u0O6_qbFqEC4ALf-aN0BWIYb7yeOIOfPWDiiJqO2q_PVK1c52gzSZwg3ezrXpaBANzcYFs5mmu8WXdcObms5gMl1409Eo3SGTIzGs0q_09QDXLoY4BeMHzayPVmgBqlKxBi8YZWmtJss9K2Nv9thkYT55ia0kTV-laaH9cW4TK1K3Hp9i-IRsYspNTQ9Cvf7Og5i0Mf3Nv5rO6sLQcmK5nyjvpnHwPgWNUYZ1pgRdt-dAV5LxZv48gUlHOosXtWKe5PwyOQTcnxtqaWAJEImLOLgnsTdoVRkEKcn_Pi8MavWRnm4rZfC8TP4Xypm4aGG1iDRYcLZUYgMYLG_W2Vc1FLtPb9PWlgoBCUs9rop2dhaKVne9yjYB8cARXP-7hA636tOW9ZG8ricpPoceXCwGSJjNLM1sOGkNvABA3ZSPLc6gMjUqdHpKW-R0UDXstqGsKHR5qSPx6tZiRvRZd_Wf4lpAH2nUyjh7o9BuWrzzZ5vY9Tx_3WHVSFknqgtRguIZ4hdz9EV9xiqYRYcFgwp5-pNCTSS9luFgRFwZNEFXMWXnt-LgumIlaDRgdP2x6X9I99dsNeN59mRZB105KzjC2xXSCzn3opt1vhmSGDgMD-VBATCEuWL0aowDncl51rFuzoVrdA1phJcXeUVooOOprCJrDlk46DqOIWj-brIdBRaIvHCLMETwKJJDpFj1pK-dsL6roFhk9IRutNd14u63kkocafrgvLlMChXBzqRo66FTPvDOY8umEt-l1Ozwii5h7Vr2YmmqirvgtM66PA8nljWBBh3IPPy6NHAY7P0P_gPlBVJJ5P8YTi0VkbbqjiWkIF2t291Kei_CWIkxzR4Ej9GGLDwqCtJfjm7nHo50KSPVmmkunWoJxcdXJFSb8Ey6aT-FG-UGHXUr38AtYWRTWd97j4W2J43cRBOUp9sPkGqPjcKy4G2K0Gb88aWYJq0u7Rv0lxihbdF7QYfIdy_irYCIKkpatSpCevi1PMFEszFkWxTVLnMvllVScmiqSY-oofaNyzGoLxVSgVYG59qkZ12Kg6NMW_whYw2gWvJE_94N8l9i16irLc9znQcL4YbZ_JiKLShZtL_qxvnzY--LEWsbcZ3zvYcl6skM-Qe7YqQoVIwYXoVHFnYG6eAwgAAbawSvyDYbwvGcr5pmNL-eaQPP4mMY0A-tNiJBzDzE-_YenYEGFBednVWzo64DintabnFp2MBs0bIEg"},
#endif
  };
  return keys;
}

// ── Tier ranking ──────────────────────────────────────────────────────────────
inline int tier_rank(const std::string &tier) {
  if (tier == "enterprise") return 2;
  if (tier == "pro") return 1;
  if (tier == "free") return 0;
  return -1;  // unknown tier never satisfies a requirement
}

// ── Feature entitlement catalog (data-driven) ──────────────────────────────────
// Which enforcement seam a feature uses. Global = short-circuit an entire URL
// prefix in the security middleware; PerRoute = a check next to has_permission.
enum class GateLayer { PerRoute, Global };

struct FeatureEntitlement {
  const char *feature;   // e.g. "sso.saml", "cluster", "relay"
  const char *minTier;   // "pro" | "enterprise"
  const char *envFlag;   // existing env toggle, or nullptr
  GateLayer layer;
};

// The single source of truth for the free/paid split. Editing this table (not
// code) changes what is gated. A feature that is NOT in this catalog is treated
// as core and always allowed (default-allow for core/unknown, default-deny only
// for enumerated premium features).
inline const std::vector<FeatureEntitlement> &feature_catalog() {
  static const std::vector<FeatureEntitlement> catalog = {
      // Enterprise identity
      {"sso.oidc", "enterprise", "ENDORIUMFORT_SSO_OIDC_ENABLED", GateLayer::PerRoute},
      {"sso.saml", "enterprise", "ENDORIUMFORT_SSO_SAML_ENABLED", GateLayer::PerRoute},
      {"ldap", "enterprise", "ENDORIUMFORT_LDAP_ENABLED", GateLayer::PerRoute},
      {"scim", "enterprise", nullptr, GateLayer::PerRoute},
      // HA / infrastructure
      {"cluster", "enterprise", "ENDORIUMFORT_CLUSTER_ENABLED", GateLayer::Global},
      {"relay", "pro", nullptr, GateLayer::Global},
      // Advanced connectivity
      {"rdp", "pro", "ENDORIUMFORT_RDP_ENABLED", GateLayer::Global},
      {"vnc", "pro", nullptr, GateLayer::Global},
      {"tunnel", "pro", nullptr, GateLayer::Global},
      // Integrations
      {"siem", "pro", nullptr, GateLayer::PerRoute},
      {"itsm", "pro", nullptr, GateLayer::PerRoute},
      // Governance / compliance
      {"recording", "pro", nullptr, GateLayer::Global},
      {"session.dna", "enterprise", nullptr, GateLayer::PerRoute},
      {"evidence.packs", "enterprise", nullptr, GateLayer::PerRoute},
      {"security.center", "enterprise", nullptr, GateLayer::PerRoute},
      {"jit.governance", "pro", nullptr, GateLayer::PerRoute},
      // New flagship premium features
      {"ssh.ca", "enterprise", nullptr, GateLayer::PerRoute},
      {"automation.scheduler", "pro", nullptr, GateLayer::PerRoute},
      {"vault.rotation", "enterprise", nullptr, GateLayer::PerRoute},
  };
  return catalog;
}

inline const FeatureEntitlement *find_feature(const std::string &feature) {
  for (const auto &entry : feature_catalog()) {
    if (feature == entry.feature) return &entry;
  }
  return nullptr;
}

// Minimal wildcard matcher for license `features[]` entries: exact match,
// "*" (all), or a "prefix.*" / "prefix*" trailing wildcard.
inline bool feature_pattern_match(const std::string &granted,
                                  const std::string &required) {
  if (granted == "*") return true;
  if (granted == required) return true;
  if (granted.size() > 1 && granted.back() == '*') {
    const std::string prefix = granted.substr(0, granted.size() - 1);
    return required.rfind(prefix, 0) == 0;
  }
  return false;
}

// Pure entitlement decision from a resolved license status. A feature not in
// the catalog is always allowed (core). Otherwise the license must be Valid and
// either meet the minimum tier OR explicitly grant the feature via features[].
inline bool license_allows(const LicenseStatus &status,
                           const std::string &feature) {
  const FeatureEntitlement *entry = find_feature(feature);
  if (!entry) return true;  // core / unknown -> allowed
  if (status.state != LicenseState::Valid) return false;

  if (tier_rank(status.claims.tier) >= tier_rank(entry->minTier)) return true;

  for (const auto &granted : status.claims.features) {
    if (feature_pattern_match(granted, feature)) return true;
  }
  return false;
}

// ── Signature verification (works for Ed25519 AND ML-DSA-65) ──────────────────
// spki_der: raw DER bytes of the SubjectPublicKeyInfo. Both algorithms are
// "pure" one-shot schemes: EVP_DigestVerifyInit with a null digest + a single
// EVP_DigestVerify, matching `openssl pkeyutl -sign -rawin`.
inline bool verify_raw_signature(const std::string &spki_der,
                                 const std::string &message,
                                 const std::string &signature) {
  if (spki_der.empty() || signature.empty()) return false;
  const unsigned char *der_ptr =
      reinterpret_cast<const unsigned char *>(spki_der.data());
  EVP_PKEY *raw_pkey =
      d2i_PUBKEY(nullptr, &der_ptr, static_cast<long>(spki_der.size()));
  if (!raw_pkey) return false;
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(raw_pkey,
                                                           &EVP_PKEY_free);

  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                              &EVP_MD_CTX_free);
  if (!ctx) return false;
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) !=
      1) {
    return false;
  }
  return EVP_DigestVerify(
             ctx.get(),
             reinterpret_cast<const unsigned char *>(signature.data()),
             signature.size(),
             reinterpret_cast<const unsigned char *>(message.data()),
             message.size()) == 1;
}

// ── Internal helpers ──────────────────────────────────────────────────────────
namespace detail {

inline std::vector<std::string> split_dots(const std::string &value) {
  std::vector<std::string> parts;
  size_t start = 0;
  while (true) {
    const size_t dot = value.find('.', start);
    if (dot == std::string::npos) {
      parts.push_back(value.substr(start));
      break;
    }
    parts.push_back(value.substr(start, dot - start));
    start = dot + 1;
  }
  return parts;
}

inline std::optional<std::string> json_string(const crow::json::rvalue &obj,
                                              const char *key) {
  if (!obj.has(key)) return std::nullopt;
  const auto &field = obj[key];
  if (field.t() != crow::json::type::String) return std::nullopt;
  return static_cast<std::string>(field.s());
}

inline int64_t json_int(const crow::json::rvalue &obj, const char *key,
                        int64_t fallback = 0) {
  if (!obj.has(key)) return fallback;
  try {
    const auto &field = obj[key];
    if (field.t() != crow::json::type::Number) return fallback;
    return static_cast<int64_t>(field.i());
  } catch (...) {
    return fallback;
  }
}

}  // namespace detail

// Verify a compact signed document (header.payload.signatures) with the hybrid
// scheme and check header typ/alg. On success, returns true and sets
// out_payload_json to the decoded payload JSON. Used for the revocation list
// (typ EFLRL); the license path uses parse_and_verify below.
inline bool verify_signed_payload(const std::string &compact,
                                  const std::vector<IssuerKey> &issuers,
                                  const char *expected_typ,
                                  std::string &out_payload_json) {
  const auto parts = detail::split_dots(compact);
  if (parts.size() != 3 || parts[0].empty() || parts[1].empty() ||
      parts[2].empty()) {
    return false;
  }
  const auto header_json = webauthn::base64url_decode(parts[0]);
  const auto payload_json = webauthn::base64url_decode(parts[1]);
  const auto sigs_json = webauthn::base64url_decode(parts[2]);
  if (!header_json || !payload_json || !sigs_json) return false;
  const auto header = crow::json::load(*header_json);
  const auto sigs = crow::json::load(*sigs_json);
  if (!header || !sigs) return false;
  if (detail::json_string(header, "typ").value_or("") != expected_typ ||
      detail::json_string(header, "alg").value_or("") != kHybridAlg) {
    return false;
  }
  const std::string kid = detail::json_string(header, "kid").value_or("");
  const IssuerKey *issuer = nullptr;
  for (const auto &candidate : issuers) {
    if (candidate.kid == kid) {
      issuer = &candidate;
      break;
    }
  }
  if (!issuer) return false;
  const std::string signed_input = parts[0] + "." + parts[1];
  const auto sig_ed = detail::json_string(sigs, "ed25519");
  const auto sig_ml = detail::json_string(sigs, "ml-dsa-65");
  if (!sig_ed || !sig_ml) return false;
  const auto sig_ed_bytes = webauthn::base64url_decode(*sig_ed);
  const auto sig_ml_bytes = webauthn::base64url_decode(*sig_ml);
  const auto ed_pub = webauthn::base64url_decode(issuer->ed25519_spki_der_b64url);
  const auto ml_pub = webauthn::base64url_decode(issuer->mldsa_spki_der_b64url);
  if (!sig_ed_bytes || !sig_ml_bytes || !ed_pub || !ml_pub) return false;
  if (!verify_raw_signature(*ed_pub, signed_input, *sig_ed_bytes)) return false;
  if (!verify_raw_signature(*ml_pub, signed_input, *sig_ml_bytes)) return false;
  out_payload_json = *payload_json;
  return true;
}

// ── Temporal / revocation evaluation (cheap; no signature work) ───────────────
// Given already-trusted claims, decide the live state. `effective_now` is
// max(now, watermark) so a rolled-back clock cannot un-expire a license. This is
// split out so the runtime can verify the signature once and re-evaluate expiry
// cheaply on every request.
inline LicenseStatus evaluate_claims(
    const LicenseClaims &claims, int64_t now, int64_t watermark,
    const std::unordered_set<std::string> &denylist) {
  LicenseStatus status;
  status.claims = claims;

  if (watermark > 0 && now + kClockRollbackSkewSeconds < watermark) {
    status.state = LicenseState::ClockAnomaly;
    status.reason = "system clock moved backwards";
    return status;
  }

  const int64_t effective_now = std::max(now, watermark);
  if (claims.notBefore > 0 && effective_now < claims.notBefore) {
    status.state = LicenseState::NotYetValid;
    status.reason = "license not yet valid";
    return status;
  }
  if (claims.notAfter > 0 && effective_now >= claims.notAfter) {
    status.state = LicenseState::Expired;
    status.reason = "license expired";
    return status;
  }
  if (!claims.licenseId.empty() &&
      denylist.find(claims.licenseId) != denylist.end()) {
    status.state = LicenseState::Revoked;
    status.reason = "license revoked";
    return status;
  }

  status.state = LicenseState::Valid;
  status.daysRemaining =
      claims.notAfter > 0 ? (claims.notAfter - effective_now) / kSecondsPerDay : 0;
  status.reason = "ok";
  return status;
}

// ── Full parse + verify ───────────────────────────────────────────────────────
// Verifies the hybrid signature against the issuer whose kid matches the header,
// then evaluates temporal/revocation state via evaluate_claims().
inline LicenseStatus parse_and_verify(
    const std::string &compact, const std::vector<IssuerKey> &issuers,
    int64_t now, int64_t watermark,
    const std::unordered_set<std::string> &denylist) {
  LicenseStatus status;

  const auto parts = detail::split_dots(compact);
  if (parts.size() != 3 || parts[0].empty() || parts[1].empty() ||
      parts[2].empty()) {
    status.state = LicenseState::Invalid;
    status.reason = "malformed token";
    return status;
  }

  const auto header_json = webauthn::base64url_decode(parts[0]);
  const auto payload_json = webauthn::base64url_decode(parts[1]);
  const auto sigs_json = webauthn::base64url_decode(parts[2]);
  if (!header_json || !payload_json || !sigs_json) {
    status.state = LicenseState::Invalid;
    status.reason = "base64url decode failed";
    return status;
  }

  const auto header = crow::json::load(*header_json);
  const auto payload = crow::json::load(*payload_json);
  const auto sigs = crow::json::load(*sigs_json);
  if (!header || !payload || !sigs) {
    status.state = LicenseState::Invalid;
    status.reason = "json parse failed";
    return status;
  }

  if (detail::json_string(header, "typ").value_or("") != kLicenseTyp ||
      detail::json_string(header, "alg").value_or("") != kHybridAlg) {
    status.state = LicenseState::Invalid;
    status.reason = "unsupported header";
    return status;
  }

  const std::string kid = detail::json_string(header, "kid").value_or("");
  const IssuerKey *issuer = nullptr;
  for (const auto &candidate : issuers) {
    if (candidate.kid == kid) {
      issuer = &candidate;
      break;
    }
  }
  if (!issuer) {
    status.state = LicenseState::Invalid;
    status.reason = "unknown issuer kid";
    return status;
  }

  // The signed message is the raw ASCII "header_b64.payload_b64".
  const std::string signed_input = parts[0] + "." + parts[1];

  const auto sig_ed = detail::json_string(sigs, "ed25519");
  const auto sig_ml = detail::json_string(sigs, "ml-dsa-65");
  if (!sig_ed || !sig_ml) {
    status.state = LicenseState::Invalid;
    status.reason = "missing signature";
    return status;
  }
  const auto sig_ed_bytes = webauthn::base64url_decode(*sig_ed);
  const auto sig_ml_bytes = webauthn::base64url_decode(*sig_ml);
  const auto ed_pub = webauthn::base64url_decode(issuer->ed25519_spki_der_b64url);
  const auto ml_pub = webauthn::base64url_decode(issuer->mldsa_spki_der_b64url);
  if (!sig_ed_bytes || !sig_ml_bytes || !ed_pub || !ml_pub) {
    status.state = LicenseState::Invalid;
    status.reason = "signature decode failed";
    return status;
  }

  // HYBRID: both signatures must verify.
  const bool ed_ok = verify_raw_signature(*ed_pub, signed_input, *sig_ed_bytes);
  const bool ml_ok = verify_raw_signature(*ml_pub, signed_input, *sig_ml_bytes);
  if (!ed_ok || !ml_ok) {
    status.state = LicenseState::Invalid;
    status.reason = ed_ok ? "ml-dsa signature invalid" : "ed25519 signature invalid";
    return status;
  }

  // ── Parse claims ──
  LicenseClaims claims;
  claims.version = static_cast<int>(detail::json_int(payload, "v", 0));
  if (claims.version != kSupportedVersion) {
    status.state = LicenseState::Invalid;
    status.reason = "unsupported license version";
    return status;
  }
  claims.licenseId = detail::json_string(payload, "licenseId").value_or("");
  claims.kind = detail::json_string(payload, "kind").value_or("");
  claims.tier = detail::json_string(payload, "tier").value_or("free");
  claims.customer = detail::json_string(payload, "customer").value_or("");
  claims.issuedAt = detail::json_int(payload, "issuedAt");
  claims.notBefore = detail::json_int(payload, "notBefore");
  claims.notAfter = detail::json_int(payload, "notAfter");
  claims.maxNodes = static_cast<int>(detail::json_int(payload, "maxNodes"));
  claims.maxSeats = static_cast<int>(detail::json_int(payload, "maxSeats"));
  if (payload.has("features") &&
      payload["features"].t() == crow::json::type::List) {
    for (const auto &item : payload["features"]) {
      if (item.t() == crow::json::type::String) {
        claims.features.push_back(static_cast<std::string>(item.s()));
      }
    }
  }
  if (payload.has("binding") &&
      payload["binding"].t() == crow::json::type::Object) {
    claims.bindingType =
        detail::json_string(payload["binding"], "type").value_or("none");
    claims.bindingValue =
        detail::json_string(payload["binding"], "value").value_or("");
  }

  // Signature is trusted; evaluate live temporal/revocation state.
  // (Binding is "none" per current product decision — no node lock enforced.)
  return evaluate_claims(claims, now, watermark, denylist);
}

}  // namespace license
