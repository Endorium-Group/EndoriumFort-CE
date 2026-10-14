// Covers the integration settings catalog and its validation. The catalog is a
// security boundary — it decides which environment variables an admin-console
// user can rewrite — so the absences are asserted as firmly as the presences.
#include "settings.h"

#include <cstdlib>
#include <iostream>
#include <set>
#include <string>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

bool refused(const std::string &key, const std::string &value) {
  std::string error;
  return !settings::check(key, value, error) && !error.empty();
}

bool accepted(const std::string &key, const std::string &value) {
  std::string error;
  const bool ok = settings::check(key, value, error);
  if (!ok) std::cerr << "        (" << key << " = " << value << " -> " << error << ")\n";
  return ok;
}

}  // namespace

int main() {
  bool ok = true;

  // ── Catalog shape ────────────────────────────────────────────────────────
  {
    const auto &catalog = settings::catalog();
    ok &= expect(!catalog.empty(), "the catalog is populated");

    std::set<std::string> seen;
    bool duplicates = false;
    bool prefixed = true;
    bool grouped = true;
    for (const auto &entry : catalog) {
      if (!seen.insert(entry.key).second) duplicates = true;
      if (entry.key.rfind("ENDORIUMFORT_", 0) != 0) prefixed = false;
      if (entry.group.empty() || entry.label.empty()) grouped = false;
      if (entry.kind == settings::Kind::Enum && entry.enumValues.empty()) grouped = false;
      if (entry.kind == settings::Kind::Int && entry.maxValue <= entry.minValue) grouped = false;
    }
    ok &= expect(!duplicates, "no key appears twice");
    ok &= expect(prefixed, "every key is an ENDORIUMFORT_ variable");
    ok &= expect(grouped, "every entry has a group, a label and usable bounds");

    ok &= expect(settings::find("ENDORIUMFORT_SIEM_SYSLOG_HOST") != nullptr,
                 "the syslog collector is settable");
    ok &= expect(settings::find("ENDORIUMFORT_LDAP_HOST") != nullptr,
                 "the directory host is settable");
    ok &= expect(settings::is_secret("ENDORIUMFORT_SIEM_WEBHOOK_TOKEN"),
                 "a webhook token is a secret");
    ok &= expect(settings::is_secret("ENDORIUMFORT_ITSM_SERVICENOW_PASSWORD"),
                 "a ServiceNow password is a secret");
    ok &= expect(!settings::is_secret("ENDORIUMFORT_SIEM_SYSLOG_HOST"),
                 "a hostname is not a secret");
  }

  // ── The security boundary ────────────────────────────────────────────────
  {
    // Anything that names an executable, passes process arguments or governs
    // the trust base must not be rewritable from a web session: that would
    // turn "configure the bastion" into "run code inside the bastion".
    const char *forbidden[] = {
        "ENDORIUMFORT_RBI_CHROMIUM",   // browser binary path
        "ENDORIUMFORT_RBI_HELPER",     // helper binary
        "ENDORIUMFORT_RBI_FLAGS",      // extra process arguments
        "ENDORIUMFORT_RBI_ENGINE",
        "ENDORIUMFORT_LICENSE",        // entitlement
        "ENDORIUMFORT_LICENSE_FILE",
        "ENDORIUMFORT_VAULT_KEY",      // encryption key at rest
        "ENDORIUMFORT_DB_DSN",         // where the data lives
        "ENDORIUMFORT_PORT",
        "ENDORIUMFORT_CLUSTER_SHARED_SECRET",
        "ENDORIUMFORT_RELAY_ENROLL_SECRET",
        "ENDORIUMFORT_SETTINGS_REFRESH_SECONDS",  // governs the store itself
    };
    for (const char *key : forbidden) {
      ok &= expect(settings::find(key) == nullptr,
                   std::string("absent from the catalog: ") + key);
      ok &= expect(refused(key, "anything"),
                   std::string("refused by check(): ") + key);
    }
    ok &= expect(refused("ENDORIUMFORT_NOT_A_REAL_KEY", "x"), "an unknown key is refused");
    ok &= expect(refused("", "x"), "an empty key is refused");
  }

  // ── Validation ───────────────────────────────────────────────────────────
  {
    // Integers are range-checked rather than silently clamped, so a typo comes
    // back to the operator instead of becoming a surprising setting.
    ok &= expect(accepted("ENDORIUMFORT_SIEM_SYSLOG_PORT", "5514"), "a valid port is accepted");
    ok &= expect(refused("ENDORIUMFORT_SIEM_SYSLOG_PORT", "0"), "port 0 is refused");
    ok &= expect(refused("ENDORIUMFORT_SIEM_SYSLOG_PORT", "99999"), "an out-of-range port is refused");
    ok &= expect(refused("ENDORIUMFORT_SIEM_SYSLOG_PORT", "514abc"), "a trailing-garbage number is refused");
    ok &= expect(refused("ENDORIUMFORT_SIEM_SYSLOG_PORT", "not-a-number"), "a non-number is refused");

    ok &= expect(accepted("ENDORIUMFORT_SIEM_SYSLOG_PROTOCOL", "tls"), "a listed transport is accepted");
    ok &= expect(accepted("ENDORIUMFORT_SIEM_SYSLOG_PROTOCOL", "TCP"), "an enum is case-insensitive");
    ok &= expect(refused("ENDORIUMFORT_SIEM_SYSLOG_PROTOCOL", "carrier-pigeon"),
                 "an unlisted transport is refused");

    ok &= expect(accepted("ENDORIUMFORT_SIEM_SYSLOG_ENABLED", "true"), "a boolean word is accepted");
    ok &= expect(accepted("ENDORIUMFORT_SIEM_SYSLOG_ENABLED", "0"), "a boolean digit is accepted");
    ok &= expect(refused("ENDORIUMFORT_SIEM_SYSLOG_ENABLED", "maybe"), "a non-boolean is refused");

    // A URL goes to the raw HTTP client, so the scheme is what keeps it
    // pointed at a collector instead of at the local filesystem.
    ok &= expect(accepted("ENDORIUMFORT_SIEM_WEBHOOK_URL",
                          "http://vl:9428/insert/jsonline?_msg_field=_msg"),
                 "an http URL with a query string is accepted");
    ok &= expect(accepted("ENDORIUMFORT_SIEM_WEBHOOK_URL", "https://logs.example.com/in"),
                 "an https URL is accepted");
    ok &= expect(refused("ENDORIUMFORT_SIEM_WEBHOOK_URL", "file:///etc/passwd"),
                 "a file:// URL is refused");
    ok &= expect(refused("ENDORIUMFORT_SIEM_WEBHOOK_URL", "logs.example.com"),
                 "a bare hostname is refused");

    // These values are interpolated into syslog lines, HTTP requests and LDAP
    // DNs, where a newline is an injection.
    ok &= expect(refused("ENDORIUMFORT_SIEM_SYSLOG_APP_NAME", "app\nname"),
                 "a newline is refused");
    ok &= expect(refused("ENDORIUMFORT_LDAP_BASE_DN", std::string("dc=x\0dc=y", 8)),
                 "a NUL byte is refused");
    ok &= expect(refused("ENDORIUMFORT_LDAP_ROLE_MAP", std::string(5000, 'a')),
                 "an oversized value is refused");
    ok &= expect(accepted("ENDORIUMFORT_LDAP_BASE_DN", "dc=example,dc=com"),
                 "an ordinary DN is accepted");

    // Empty means "clear", which is how the UI reverts to the environment.
    ok &= expect(accepted("ENDORIUMFORT_SIEM_SYSLOG_PROTOCOL", ""),
                 "an empty value is always accepted as a clear");
  }

  // ── Secrets need a vault key ─────────────────────────────────────────────
  {
    unsetenv("ENDORIUMFORT_VAULT_KEY");
    ok &= expect(refused("ENDORIUMFORT_SIEM_WEBHOOK_TOKEN", "s3cret"),
                 "a secret is refused with no vault key, rather than stored in the clear");
    setenv("ENDORIUMFORT_VAULT_KEY",
           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
    ok &= expect(accepted("ENDORIUMFORT_SIEM_WEBHOOK_TOKEN", "s3cret"),
                 "a secret is accepted once a vault key is configured");
    unsetenv("ENDORIUMFORT_VAULT_KEY");
  }

  // ── Nothing is stored before init() ──────────────────────────────────────
  {
    ok &= expect(!settings::stored_value("ENDORIUMFORT_SIEM_SYSLOG_HOST").has_value(),
                 "an unloaded store resolves to the environment");
  }

  if (ok) std::cout << "settings tests passed" << std::endl;
  return ok ? 0 : 1;
}
