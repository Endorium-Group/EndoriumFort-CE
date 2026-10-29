#pragma once
// ─── EndoriumFort — runtime integration settings ────────────────────────────
//
// Lets an operator configure the integrations (SIEM, LDAP, SSO, ITSM, RBI
// transfer policy) from the admin console instead of redeploying with new
// environment variables.
//
// How it plugs in: every integration already reads its configuration through
// env_flag_enabled / env_string_value / env_int_value (route_common) and, for
// the per-provider OIDC keys, through enterprise.cc's dynamic_env_* helpers.
// Those helpers now consult this store FIRST, so a stored value takes effect
// without touching a single call site. The environment remains the bootstrap
// default: clearing a key in the UI falls back to it.
//
// Two deliberate limits:
//
//   * Only keys in `catalog()` can be stored. A blanket "any env var" override
//     would hand an admin-console user the license, the vault key and the
//     browser's executable path — the catalog is the security boundary, not a
//     convenience list.
//   * Anything naming an executable or passing process arguments
//     (ENDORIUMFORT_RBI_CHROMIUM / _HELPER / _FLAGS / _ENGINE) is absent on
//     purpose, and those keys are read with raw getenv so they cannot be
//     reached from here even by mistake. Configuring the bastion must not be a
//     path to running code inside it.
//
// Values are validated before they are stored (type, range, enum, URL scheme,
// no control characters), because they flow into syslog lines, HTTP requests
// and LDAP DNs where a stray newline is an injection.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct AppContext;

namespace settings {

enum class Kind {
  Bool,
  Int,
  String,
  Secret,  // write-only: stored encrypted, never returned by the API
  Enum,
  Url,
  Csv,
};

struct Descriptor {
  std::string key;         // the environment variable name; the identity
  std::string group;       // "siem" | "ldap" | "sso" | "itsm" | "rbi" | "ssh" | "general"
  std::string subgroup;    // optional section inside a group ("syslog", "okta", …)
  Kind kind = Kind::String;
  std::string label;       // short human label
  std::string hint;        // one line of guidance
  std::string defaultValue;
  std::vector<std::string> enumValues;  // Kind::Enum
  int minValue = 0;                     // Kind::Int
  int maxValue = 0;
};

// Every settable key, in display order.
const std::vector<Descriptor> &catalog();
const Descriptor *find(const std::string &key);
bool is_secret(const std::string &key);

// The stored value for `key`, or nullopt when the store has none (so the caller
// falls back to the environment). Safe to call from any thread and from the
// audit path: it only reads an in-memory cache.
std::optional<std::string> stored_value(const std::string &key);

// Loads the table into the cache and starts the refresher. Called once at
// startup, after the database is open.
void init(AppContext &ctx);

// Validates a value without storing it, so a form can be refused as a whole
// instead of applying half of it.
bool check(const std::string &key, const std::string &value, std::string &error);

// Validates and stores one value. `error` explains a refusal (unknown key, bad
// type, out of range, secret without a vault key).
bool set(AppContext &ctx, const std::string &key, const std::string &value,
         const std::string &actor, std::string &error);

// Removes the stored value, so the environment (or the built-in default)
// applies again.
bool clear(AppContext &ctx, const std::string &key, const std::string &actor,
           std::string &error);

// ── Reporting (for the admin console) ──────────────────────────────────────
struct Resolved {
  const Descriptor *descriptor = nullptr;
  std::string value;        // effective value; empty for a secret
  std::string source;       // "store" | "env" | "default"
  bool configured = false;  // a value exists somewhere (used for secrets)
  bool envShadowed = false; // the store overrides an environment value
  std::string updatedAt;
  std::string updatedBy;
};

std::vector<Resolved> resolve_all();

// Registers GET/PUT /api/settings/integrations.
struct CrowAppTag;  // keeps crow out of this header

}  // namespace settings
