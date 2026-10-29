// ─── EndoriumFort — runtime integration settings (implementation) ───────────
//
// A tiny key/value store in front of the environment. The hot path is
// stored_value(), called by env_string_value / env_flag_enabled /
// env_int_value for every integration lookup — including once per audit event
// on the SIEM path — so it only ever touches an in-memory map under a shared
// lock. The database is read at startup and by the refresher thread.
//
// Secrets are kept encrypted in the table and decrypted into the cache, so an
// integration reads them exactly like any other value while a database dump
// carries only ciphertext.

#include "settings.h"

#include "app_context.h"
#include "crypto.h"
#include "database.h"
#include "route_common.h"
#include "utils.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

namespace settings {
namespace {

struct CachedValue {
  std::string value;  // plaintext, decrypted for a secret
  bool isSecret = false;
  std::string updatedAt;
  std::string updatedBy;
};

struct Store {
  std::shared_mutex mutex;
  std::unordered_map<std::string, CachedValue> values;
  // The refresher lets a second node pick up a change written by the first
  // one; without it a stored value would only apply after a restart.
  std::mutex wake_mutex;
  std::condition_variable wake;
  bool stop = false;
  bool started = false;
  std::thread worker;

  ~Store() {
    {
      std::lock_guard<std::mutex> lock(wake_mutex);
      stop = true;
    }
    wake.notify_all();
    if (worker.joinable()) worker.join();
  }
};

Store &store() {
  static Store instance;
  return instance;
}

// Longest value accepted. Role maps and blocked-extension lists are the only
// long ones; everything else is a host, a URL or a DN.
constexpr size_t kMaxValueBytes = 4096;

bool parse_bool_text(const std::string &raw, bool &out) {
  const std::string value = to_lower(trim_copy(raw));
  if (value == "1" || value == "true" || value == "yes" || value == "on") {
    out = true;
    return true;
  }
  if (value == "0" || value == "false" || value == "no" || value == "off") {
    out = false;
    return true;
  }
  return false;
}

const std::unordered_map<std::string, const Descriptor *> &index() {
  static const auto *map = [] {
    auto *built = new std::unordered_map<std::string, const Descriptor *>();
    for (const auto &entry : catalog()) built->emplace(entry.key, &entry);
    return built;
  }();
  return *map;
}

// Reads every row into `out`, decrypting secrets. Returns false when the query
// itself failed, so a transient database error does not wipe a live cache.
bool read_rows(AppContext &ctx, std::unordered_map<std::string, CachedValue> &out) {
  if (!ctx.sqlite.is_open()) return false;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  auto stmt = ctx.sqlite.prepare(
      "SELECT key, value, is_secret, updated_at, updated_by FROM integration_settings");
  if (!stmt) return false;
  while (stmt.step()) {
    const std::string key = stmt.column_text(0);
    if (index().find(key) == index().end()) continue;  // dropped from the catalog
    CachedValue cached;
    const std::string raw = stmt.column_text(1);
    cached.isSecret = stmt.column_int(2) != 0;
    cached.value = cached.isSecret ? crypto::aes256_decrypt(raw) : raw;
    if (cached.isSecret && cached.value.empty() && !raw.empty()) {
      // Wrong or missing vault key: skip the row rather than hand an
      // integration an empty credential it would then report as a failure.
      continue;
    }
    cached.updatedAt = stmt.column_text(3);
    cached.updatedBy = stmt.column_text(4);
    out.emplace(key, std::move(cached));
  }
  return true;
}

void refresh_from_db(AppContext &ctx) {
  std::unordered_map<std::string, CachedValue> fresh;
  if (!read_rows(ctx, fresh)) return;
  Store &s = store();
  std::unique_lock<std::shared_mutex> lock(s.mutex);
  s.values = std::move(fresh);
}

int refresh_seconds() {
  // Not in the catalog on purpose: it governs the store itself.
  const char *raw = std::getenv("ENDORIUMFORT_SETTINGS_REFRESH_SECONDS");
  if (!raw || !*raw) return 15;
  try {
    const int value = std::stoi(raw);
    return value < 0 ? 15 : std::min(value, 3600);
  } catch (...) {
    return 15;
  }
}

void refresher_loop(AppContext *ctx) {
  Store &s = store();
  for (;;) {
    const int interval = refresh_seconds();
    {
      std::unique_lock<std::mutex> lock(s.wake_mutex);
      s.wake.wait_for(lock, std::chrono::seconds(std::max(1, interval)),
                      [&s] { return s.stop; });
      if (s.stop) return;
    }
    if (interval > 0) refresh_from_db(*ctx);
  }
}

void audit_change(AppContext &ctx, const std::string &type, const std::string &key,
                  const std::string &actor, const std::string &detail) {
  AuditEvent event;
  event.id = ctx.next_audit_id.fetch_add(1);
  event.type = type;
  event.actor = actor.empty() ? "system" : actor;
  event.role = "admin";
  event.createdAt = now_utc();
  std::ostringstream payload;
  payload << "{\"key\":\"" << json_escape(key) << "\"";
  if (!detail.empty()) payload << ",\"value\":\"" << json_escape(detail) << "\"";
  payload << "}";
  event.payloadJson = payload.str();
  event.payloadIsJson = true;
  ctx.append_audit(event);
}

bool validate(const Descriptor &descriptor, const std::string &value, std::string &error) {
  if (value.size() > kMaxValueBytes) {
    error = "value is too long";
    return false;
  }
  // These values end up in syslog lines, HTTP requests and LDAP DNs, where a
  // newline or a NUL is an injection rather than a typo.
  for (char raw : value) {
    const unsigned char ch = static_cast<unsigned char>(raw);
    if (ch < 0x20 || ch == 0x7f) {
      error = "value contains a control character";
      return false;
    }
  }
  switch (descriptor.kind) {
    case Kind::Bool: {
      bool parsed = false;
      if (!parse_bool_text(value, parsed)) {
        error = "expected a boolean";
        return false;
      }
      return true;
    }
    case Kind::Int: {
      int parsed = 0;
      try {
        size_t consumed = 0;
        parsed = std::stoi(value, &consumed);
        if (consumed != value.size()) throw std::invalid_argument("trailing");
      } catch (...) {
        error = "expected a whole number";
        return false;
      }
      if (parsed < descriptor.minValue || parsed > descriptor.maxValue) {
        error = "must be between " + std::to_string(descriptor.minValue) + " and " +
                std::to_string(descriptor.maxValue);
        return false;
      }
      return true;
    }
    case Kind::Enum: {
      const std::string normalized = to_lower(value);
      if (std::find(descriptor.enumValues.begin(), descriptor.enumValues.end(),
                    normalized) == descriptor.enumValues.end()) {
        error = "must be one of " + join_csv_compact(descriptor.enumValues);
        return false;
      }
      return true;
    }
    case Kind::Url: {
      // Only http(s): a file:// or gopher:// "URL" would be handed to the raw
      // HTTP client, and the scheme is what keeps it pointed at a collector.
      if (!parse_endpoint_url(value)) {
        error = "expected an absolute http:// or https:// URL";
        return false;
      }
      return true;
    }
    case Kind::String:
    case Kind::Secret:
    case Kind::Csv:
      return true;
  }
  return true;
}

// Stored form of a value: normalized for the types that have one canonical
// spelling, so the UI and the integrations agree on what was saved.
std::string normalize(const Descriptor &descriptor, const std::string &value) {
  switch (descriptor.kind) {
    case Kind::Bool: {
      bool parsed = false;
      parse_bool_text(value, parsed);
      return parsed ? "1" : "0";
    }
    case Kind::Enum: return to_lower(trim_copy(value));
    case Kind::Secret: return value;  // never touched
    default: return trim_copy(value);
  }
}

}  // namespace
// Generated catalog — see the table in the commit that introduced this file.
const std::vector<Descriptor> &catalog() {
  static const std::vector<Descriptor> entries = {
      {"ENDORIUMFORT_SIEM_HOSTNAME", "siem", "pipeline", Kind::String,
       "Bastion hostname",
       "Stamped on every event as `host`. Defaults to the system hostname, which a container changes on every restart.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_QUEUE_LIMIT", "siem", "pipeline", Kind::Int,
       "Queue depth",
       "Events held in memory when the collector is slow or down. Past it the oldest are dropped.",
       "20000", {}, 100, 1000000},
      {"ENDORIUMFORT_SIEM_BATCH_MAX", "siem", "pipeline", Kind::Int,
       "Batch size",
       "Events grouped into one delivery.",
       "50", {}, 1, 1000},
      {"ENDORIUMFORT_SIEM_RETRY_ATTEMPTS", "siem", "pipeline", Kind::Int,
       "Retry attempts",
       "Delivery attempts per batch before the events are given up on.",
       "4", {}, 1, 20},
      {"ENDORIUMFORT_SIEM_RETRY_BASE_MS", "siem", "pipeline", Kind::Int,
       "First backoff (ms)",
       "Delay before the second attempt; doubled for each one after.",
       "1000", {}, 50, 60000},
      {"ENDORIUMFORT_SIEM_RETRY_MAX_MS", "siem", "pipeline", Kind::Int,
       "Backoff cap (ms)",
       "Upper bound on the growing retry delay.",
       "30000", {}, 50, 300000},
      {"ENDORIUMFORT_SIEM_HEARTBEAT_SECONDS", "siem", "pipeline", Kind::Int,
       "Heartbeat (s)",
       "Interval of the integration.siem.heartbeat event, which lets a SOC alert on silence. 0 disables it.",
       "300", {}, 0, 86400},
      {"ENDORIUMFORT_SIEM_DRAIN_SECONDS", "siem", "pipeline", Kind::Int,
       "Shutdown drain (s)",
       "How long a shutdown keeps shipping the backlog before giving up.",
       "5", {}, 0, 120},
      {"ENDORIUMFORT_SIEM_SYSLOG_ENABLED", "siem", "syslog", Kind::Bool,
       "Enabled",
       "Ship audit events to a syslog collector.",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_HOST", "siem", "syslog", Kind::String,
       "Collector host",
       "Hostname or address of the syslog receiver.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_PORT", "siem", "syslog", Kind::Int,
       "Port",
       "",
       "514", {}, 1, 65535},
      {"ENDORIUMFORT_SIEM_SYSLOG_PROTOCOL", "siem", "syslog", Kind::Enum,
       "Transport",
       "UDP confirms nothing: prefer TCP or TLS for a SOC.",
       "udp", {"udp", "tcp", "tls"}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_FORMAT", "siem", "syslog", Kind::Enum,
       "Format",
       "",
       "rfc5424", {"rfc5424", "rfc3164"}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_MESSAGE", "siem", "syslog", Kind::Enum,
       "Message body",
       "`cee` prefixes the JSON with an @cee: cookie, which VictoriaLogs and rsyslog expand back into log fields.",
       "cee", {"cee", "json", "text"}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_FRAMING", "siem", "syslog", Kind::Enum,
       "Stream framing",
       "TCP/TLS only. Octet counting (RFC 6587) cannot split a message in two.",
       "octet", {"octet", "lf"}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_FACILITY", "siem", "syslog", Kind::Int,
       "Facility",
       "RFC 5424 facility; 13 is `log audit`.",
       "13", {}, 0, 23},
      {"ENDORIUMFORT_SIEM_SYSLOG_APP_NAME", "siem", "syslog", Kind::String,
       "APP-NAME",
       "Syslog application name.",
       "endoriumfort", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_TLS_VERIFY", "siem", "syslog", Kind::Bool,
       "Verify certificate",
       "Checks the collector's certificate chain and its hostname. Turning this off accepts any certificate.",
       "1", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_CA_FILE", "siem", "syslog", Kind::String,
       "CA bundle path",
       "PEM file inside the container that signs the collector certificate. Empty uses the system CAs.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_SERVER_NAME", "siem", "syslog", Kind::String,
       "Expected certificate name",
       "SNI and verification name, when it differs from the host.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SYSLOG_MAX_BYTES", "siem", "syslog", Kind::Int,
       "Max line bytes",
       "Longer lines are truncated. Empty picks 8192 on UDP, 65000 on a stream.",
       "", {}, 480, 1048576},
      {"ENDORIUMFORT_SIEM_SYSLOG_CONNECT_TIMEOUT_MS", "siem", "syslog", Kind::Int,
       "Connect timeout (ms)",
       "Bounded so a collector behind a DROPping firewall cannot stall the worker.",
       "5000", {}, 100, 60000},
      {"ENDORIUMFORT_SIEM_SYSLOG_WRITE_TIMEOUT_MS", "siem", "syslog", Kind::Int,
       "Write timeout (ms)",
       "",
       "10000", {}, 100, 120000},
      {"ENDORIUMFORT_SIEM_WEBHOOK_ENABLED", "siem", "webhook", Kind::Bool,
       "Enabled",
       "POST each audit event as JSON.",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_WEBHOOK_URL", "siem", "webhook", Kind::Url,
       "URL",
       "Full URL, query string included. VictoriaLogs: /insert/jsonline?_time_field=_time&_msg_field=_msg",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_WEBHOOK_TOKEN", "siem", "webhook", Kind::Secret,
       "Bearer token",
       "Sent as the Authorization header.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_WEBHOOK_NDJSON", "siem", "webhook", Kind::Bool,
       "Batch as NDJSON",
       "One request per batch, one JSON object per line. Required for /insert/jsonline to be efficient; a plain webhook usually wants one object per request.",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SPLUNK_ENABLED", "siem", "splunk", Kind::Bool,
       "Enabled",
       "Ship to a Splunk HTTP Event Collector.",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SPLUNK_URL", "siem", "splunk", Kind::Url,
       "HEC URL",
       "e.g. https://splunk:8088/services/collector",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SPLUNK_TOKEN", "siem", "splunk", Kind::Secret,
       "HEC token",
       "",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SPLUNK_INDEX", "siem", "splunk", Kind::String,
       "Index",
       "Target index. Empty uses the token's default.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SIEM_SENTINEL_ENABLED", "siem", "sentinel", Kind::Bool,
       "Enabled",
       "Microsoft Sentinel has no transport in this build; use the JSON webhook towards a Data Collector endpoint.",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_ENABLED", "ldap", "connection", Kind::Bool,
       "Enabled",
       "Authenticate users against the directory.",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_HOST", "ldap", "connection", Kind::String,
       "Host",
       "Directory server. An ldap:// or ldaps:// URL is also accepted.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_PORT", "ldap", "connection", Kind::Int,
       "Port",
       "Defaults to 389, or 636 when TLS is on.",
       "", {}, 1, 65535},
      {"ENDORIUMFORT_LDAP_USE_TLS", "ldap", "connection", Kind::Bool,
       "LDAPS",
       "Connect over TLS (port 636).",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_STARTTLS", "ldap", "connection", Kind::Bool,
       "StartTLS",
       "Upgrade a plain connection to TLS.",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_REQUIRE_CERT", "ldap", "connection", Kind::Bool,
       "Verify certificate",
       "Refuse a directory certificate that does not validate.",
       "1", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_BASE_DN", "ldap", "identity", Kind::String,
       "Base DN",
       "e.g. dc=example,dc=com",
       "", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_USER_ATTRIBUTE", "ldap", "identity", Kind::String,
       "User attribute",
       "Attribute holding the login name.",
       "sAMAccountName", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_BIND_DN_TEMPLATE", "ldap", "identity", Kind::String,
       "Bind DN template",
       "e.g. uid={username},ou=people,dc=example,dc=com",
       "", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_USER_TEMPLATE", "ldap", "identity", Kind::String,
       "User template",
       "Legacy alias for the bind DN template.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_AD_DOMAIN", "ldap", "identity", Kind::String,
       "Active Directory domain",
       "Binds as {username}@domain.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_DEFAULT_ROLE", "ldap", "roles", Kind::Enum,
       "Default role",
       "Role given to a directory user with no mapping.",
       "operator", {"operator", "admin", "auditor"}, 0, 0},
      {"ENDORIUMFORT_LDAP_SYNC_ROLE", "ldap", "roles", Kind::Bool,
       "Sync role on login",
       "Re-apply the mapped role at each login.",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_ROLE_MAP", "ldap", "roles", Kind::Csv,
       "Role map",
       "Comma-separated group=role pairs.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_ROLE_ADMIN_MATCHERS", "ldap", "roles", Kind::Csv,
       "Admin matchers",
       "Comma-separated patterns granting the admin role.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_LDAP_ROLE_AUDITOR_MATCHERS", "ldap", "roles", Kind::Csv,
       "Auditor matchers",
       "Comma-separated patterns granting the auditor role.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_ITSM_PROVIDER", "itsm", "general", Kind::Enum,
       "Provider",
       "Ticketing system checked before a session opens. Empty picks the first enabled one.",
       "", {"servicenow", "jira"}, 0, 0},
      {"ENDORIUMFORT_ITSM_FAIL_MODE", "itsm", "general", Kind::Enum,
       "When unreachable",
       "fail-closed refuses the session when the ticketing system cannot be reached.",
       "fail-closed", {"fail-open", "fail-closed"}, 0, 0},
      {"ENDORIUMFORT_ITSM_SERVICENOW_ENABLED", "itsm", "servicenow", Kind::Bool,
       "Enabled",
       "",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_ITSM_SERVICENOW_URL", "itsm", "servicenow", Kind::Url,
       "Instance URL",
       "e.g. https://example.service-now.com",
       "", {}, 0, 0},
      {"ENDORIUMFORT_ITSM_SERVICENOW_USER", "itsm", "servicenow", Kind::String,
       "User",
       "",
       "", {}, 0, 0},
      {"ENDORIUMFORT_ITSM_SERVICENOW_PASSWORD", "itsm", "servicenow", Kind::Secret,
       "Password",
       "",
       "", {}, 0, 0},
      {"ENDORIUMFORT_ITSM_JIRA_ENABLED", "itsm", "jira", Kind::Bool,
       "Enabled",
       "",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_ITSM_JIRA_URL", "itsm", "jira", Kind::Url,
       "Base URL",
       "e.g. https://example.atlassian.net",
       "", {}, 0, 0},
      {"ENDORIUMFORT_ITSM_JIRA_USER", "itsm", "jira", Kind::String,
       "User",
       "Account e-mail for the API token.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_ITSM_JIRA_TOKEN", "itsm", "jira", Kind::Secret,
       "API token",
       "",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENABLED", "sso", "general", Kind::Bool,
       "OIDC enabled",
       "",
       "1", {}, 0, 0},
      {"ENDORIUMFORT_SSO_SAML_ENABLED", "sso", "general", Kind::Bool,
       "SAML enabled",
       "",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_SSO_DEFAULT_PROVIDER", "sso", "general", Kind::Enum,
       "Default provider",
       "Provider offered first on the login page.",
       "keycloak", {"entra_id", "okta", "google_workspace", "keycloak", "saml_generic"}, 0, 0},
      {"ENDORIUMFORT_SSO_ENTRA_ID_ENABLED", "sso", "general", Kind::Bool,
       "Microsoft Entra ID enabled",
       "",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OKTA_ENABLED", "sso", "general", Kind::Bool,
       "Okta enabled",
       "",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_SSO_GOOGLE_WORKSPACE_ENABLED", "sso", "general", Kind::Bool,
       "Google Workspace enabled",
       "",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_SSO_KEYCLOAK_ENABLED", "sso", "general", Kind::Bool,
       "Keycloak enabled",
       "",
       "0", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_CLIENT_ID", "sso", "oidc", Kind::String,
       "Client ID",
       "Applies to every OIDC provider unless overridden.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_CLIENT_SECRET", "sso", "oidc", Kind::Secret,
       "Client secret",
       "Applies to every OIDC provider unless overridden.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_AUTHORIZATION_ENDPOINT", "sso", "oidc", Kind::Url,
       "Authorization endpoint",
       "Applies to every OIDC provider unless overridden.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_TOKEN_ENDPOINT", "sso", "oidc", Kind::Url,
       "Token endpoint",
       "Applies to every OIDC provider unless overridden.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_USERINFO_ENDPOINT", "sso", "oidc", Kind::Url,
       "Userinfo endpoint",
       "Applies to every OIDC provider unless overridden.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_REDIRECT_URI", "sso", "oidc", Kind::Url,
       "Redirect URI",
       "Must match the one registered with the provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_SCOPE", "sso", "oidc", Kind::String,
       "Scope",
       "Applies to every OIDC provider unless overridden.",
       "openid profile email", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ROLE_CLAIM", "sso", "oidc", Kind::String,
       "Role claim",
       "Claim carrying the user's role.",
       "role", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_DEFAULT_ROLE", "sso", "oidc", Kind::Enum,
       "Default role",
       "Applies to every OIDC provider unless overridden.",
       "operator", {"operator", "admin", "auditor"}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_SYNC_ROLE", "sso", "oidc", Kind::Bool,
       "Sync role on login",
       "Applies to every OIDC provider unless overridden.",
       "1", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_CLIENT_ID", "sso", "entra_id", Kind::String,
       "Client ID",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_CLIENT_SECRET", "sso", "entra_id", Kind::Secret,
       "Client secret",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_AUTHORIZATION_ENDPOINT", "sso", "entra_id", Kind::Url,
       "Authorization endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_TOKEN_ENDPOINT", "sso", "entra_id", Kind::Url,
       "Token endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_USERINFO_ENDPOINT", "sso", "entra_id", Kind::Url,
       "Userinfo endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_REDIRECT_URI", "sso", "entra_id", Kind::Url,
       "Redirect URI",
       "Must match the one registered with the provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_SCOPE", "sso", "entra_id", Kind::String,
       "Scope",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_ROLE_CLAIM", "sso", "entra_id", Kind::String,
       "Role claim",
       "Claim carrying the user's role.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_DEFAULT_ROLE", "sso", "entra_id", Kind::Enum,
       "Default role",
       "Overrides the shared OIDC value for this provider.",
       "", {"operator", "admin", "auditor"}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_ENTRA_ID_SYNC_ROLE", "sso", "entra_id", Kind::Bool,
       "Sync role on login",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_CLIENT_ID", "sso", "okta", Kind::String,
       "Client ID",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_CLIENT_SECRET", "sso", "okta", Kind::Secret,
       "Client secret",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_AUTHORIZATION_ENDPOINT", "sso", "okta", Kind::Url,
       "Authorization endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_TOKEN_ENDPOINT", "sso", "okta", Kind::Url,
       "Token endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_USERINFO_ENDPOINT", "sso", "okta", Kind::Url,
       "Userinfo endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_REDIRECT_URI", "sso", "okta", Kind::Url,
       "Redirect URI",
       "Must match the one registered with the provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_SCOPE", "sso", "okta", Kind::String,
       "Scope",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_ROLE_CLAIM", "sso", "okta", Kind::String,
       "Role claim",
       "Claim carrying the user's role.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_DEFAULT_ROLE", "sso", "okta", Kind::Enum,
       "Default role",
       "Overrides the shared OIDC value for this provider.",
       "", {"operator", "admin", "auditor"}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_OKTA_SYNC_ROLE", "sso", "okta", Kind::Bool,
       "Sync role on login",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_CLIENT_ID", "sso", "google_workspace", Kind::String,
       "Client ID",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_CLIENT_SECRET", "sso", "google_workspace", Kind::Secret,
       "Client secret",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_AUTHORIZATION_ENDPOINT", "sso", "google_workspace", Kind::Url,
       "Authorization endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_TOKEN_ENDPOINT", "sso", "google_workspace", Kind::Url,
       "Token endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_USERINFO_ENDPOINT", "sso", "google_workspace", Kind::Url,
       "Userinfo endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_REDIRECT_URI", "sso", "google_workspace", Kind::Url,
       "Redirect URI",
       "Must match the one registered with the provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_SCOPE", "sso", "google_workspace", Kind::String,
       "Scope",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_ROLE_CLAIM", "sso", "google_workspace", Kind::String,
       "Role claim",
       "Claim carrying the user's role.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_DEFAULT_ROLE", "sso", "google_workspace", Kind::Enum,
       "Default role",
       "Overrides the shared OIDC value for this provider.",
       "", {"operator", "admin", "auditor"}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_GOOGLE_WORKSPACE_SYNC_ROLE", "sso", "google_workspace", Kind::Bool,
       "Sync role on login",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_CLIENT_ID", "sso", "keycloak", Kind::String,
       "Client ID",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_CLIENT_SECRET", "sso", "keycloak", Kind::Secret,
       "Client secret",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_AUTHORIZATION_ENDPOINT", "sso", "keycloak", Kind::Url,
       "Authorization endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_TOKEN_ENDPOINT", "sso", "keycloak", Kind::Url,
       "Token endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_USERINFO_ENDPOINT", "sso", "keycloak", Kind::Url,
       "Userinfo endpoint",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_REDIRECT_URI", "sso", "keycloak", Kind::Url,
       "Redirect URI",
       "Must match the one registered with the provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_SCOPE", "sso", "keycloak", Kind::String,
       "Scope",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_ROLE_CLAIM", "sso", "keycloak", Kind::String,
       "Role claim",
       "Claim carrying the user's role.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_DEFAULT_ROLE", "sso", "keycloak", Kind::Enum,
       "Default role",
       "Overrides the shared OIDC value for this provider.",
       "", {"operator", "admin", "auditor"}, 0, 0},
      {"ENDORIUMFORT_SSO_OIDC_KEYCLOAK_SYNC_ROLE", "sso", "keycloak", Kind::Bool,
       "Sync role on login",
       "Overrides the shared OIDC value for this provider.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_RBI_ALLOW_UPLOAD", "rbi", "transfer", Kind::Bool,
       "Allow upload",
       "Files from the operator into the isolated browser.",
       "1", {}, 0, 0},
      {"ENDORIUMFORT_RBI_ALLOW_DOWNLOAD", "rbi", "transfer", Kind::Bool,
       "Allow download",
       "Files out of the isolated browser.",
       "1", {}, 0, 0},
      {"ENDORIUMFORT_RBI_ALLOW_PASTE", "rbi", "transfer", Kind::Bool,
       "Allow paste",
       "Clipboard into the isolated browser.",
       "1", {}, 0, 0},
      {"ENDORIUMFORT_RBI_MAX_TRANSFER_MB", "rbi", "transfer", Kind::Int,
       "Max transfer (MB)",
       "0 means no limit.",
       "0", {}, 0, 1048576},
      {"ENDORIUMFORT_RBI_BLOCKED_EXTENSIONS", "rbi", "transfer", Kind::Csv,
       "Blocked extensions",
       "Comma-separated list, e.g. exe,dll,scr.",
       "", {}, 0, 0},
      {"ENDORIUMFORT_SSH_TRANSFER_MAX_UPLOAD_MB", "ssh", "general", Kind::Int,
       "Max upload size (MB)",
       "Largest file an operator may send to an SSH target over SFTP/SCP.",
       "100", {}, 1, 10240},
      {"ENDORIUMFORT_INTEGRATIONS_DELIVERY_MODE", "general", "general", Kind::Enum,
       "Integration delivery mode",
       "Default verdict when an integration cannot be reached.",
       "fail-open", {"fail-open", "fail-closed"}, 0, 0},
  };
  return entries;
}

bool check(const std::string &key, const std::string &value, std::string &error) {
  const Descriptor *descriptor = find(key);
  if (!descriptor) {
    error = "unknown setting";
    return false;
  }
  if (value.empty()) return true;  // empty means "clear", always allowed
  if (descriptor->kind == Kind::Secret && crypto::aes256_encrypt("probe").empty()) {
    error = "no vault key configured: set ENDORIUMFORT_VAULT_KEY before storing a secret";
    return false;
  }
  return validate(*descriptor, value, error);
}

const Descriptor *find(const std::string &key) {
  const auto it = index().find(key);
  return it == index().end() ? nullptr : it->second;
}

bool is_secret(const std::string &key) {
  const Descriptor *descriptor = find(key);
  return descriptor && descriptor->kind == Kind::Secret;
}

std::optional<std::string> stored_value(const std::string &key) {
  Store &s = store();
  std::shared_lock<std::shared_mutex> lock(s.mutex);
  const auto it = s.values.find(key);
  if (it == s.values.end()) return std::nullopt;
  return it->second.value;
}

void init(AppContext &ctx) {
  refresh_from_db(ctx);
  Store &s = store();
  {
    std::lock_guard<std::mutex> lock(s.wake_mutex);
    if (s.started) return;
    s.started = true;
    s.worker = std::thread(refresher_loop, &ctx);
  }
  ctx.register_shutdown_hook([] {
    Store &inner = store();
    {
      std::lock_guard<std::mutex> lock(inner.wake_mutex);
      inner.stop = true;
    }
    inner.wake.notify_all();
    if (inner.worker.joinable()) inner.worker.join();
  });
}

bool set(AppContext &ctx, const std::string &key, const std::string &value,
         const std::string &actor, std::string &error) {
  const Descriptor *descriptor = find(key);
  if (!descriptor) {
    error = "unknown setting";
    return false;
  }
  // An empty value means "no value", which is what clearing expresses. Keeping
  // both would leave two ways to say the same thing and an ambiguous UI.
  if (value.empty()) return clear(ctx, key, actor, error);
  if (!validate(*descriptor, value, error)) return false;

  const std::string normalized = normalize(*descriptor, value);
  const bool secret = descriptor->kind == Kind::Secret;
  std::string persisted = normalized;
  if (secret) {
    persisted = crypto::aes256_encrypt(normalized);
    if (persisted.empty()) {
      // Storing a credential in the clear because the deployment forgot a key
      // is not a reasonable fallback.
      error =
          "no vault key configured: set ENDORIUMFORT_VAULT_KEY before storing a secret";
      return false;
    }
  }
  if (!ctx.sqlite.is_open()) {
    error = "database unavailable";
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
    auto stmt = ctx.sqlite.prepare(
        "INSERT INTO integration_settings (key, value, is_secret, updated_at, updated_by) "
        "VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(key) DO UPDATE SET "
        "value = ?2, is_secret = ?3, updated_at = ?4, updated_by = ?5");
    if (!stmt) {
      error = "database unavailable";
      return false;
    }
    const std::string now = now_utc();
    stmt.bind_text(1, key);
    stmt.bind_text(2, persisted);
    stmt.bind_int(3, secret ? 1 : 0);
    stmt.bind_text(4, now);
    stmt.bind_text(5, actor);
    if (!stmt.execute()) {
      error = "could not store the setting";
      return false;
    }
    CachedValue cached;
    cached.value = normalized;
    cached.isSecret = secret;
    cached.updatedAt = now;
    cached.updatedBy = actor;
    Store &s = store();
    std::unique_lock<std::shared_mutex> cache_lock(s.mutex);
    s.values[key] = std::move(cached);
  }
  // The audit trail records that a setting changed and to what, except for a
  // secret, where the fact of the change is the whole record.
  audit_change(ctx, "settings.integration.updated", key, actor,
               secret ? "***" : normalized);
  return true;
}

bool clear(AppContext &ctx, const std::string &key, const std::string &actor,
           std::string &error) {
  if (!find(key)) {
    error = "unknown setting";
    return false;
  }
  if (!ctx.sqlite.is_open()) {
    error = "database unavailable";
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
    auto stmt = ctx.sqlite.prepare("DELETE FROM integration_settings WHERE key = ?1");
    if (!stmt) {
      error = "database unavailable";
      return false;
    }
    stmt.bind_text(1, key);
    if (!stmt.execute()) {
      error = "could not clear the setting";
      return false;
    }
    Store &s = store();
    std::unique_lock<std::shared_mutex> cache_lock(s.mutex);
    s.values.erase(key);
  }
  audit_change(ctx, "settings.integration.cleared", key, actor, "");
  return true;
}

std::vector<Resolved> resolve_all() {
  std::vector<Resolved> out;
  out.reserve(catalog().size());
  Store &s = store();
  std::shared_lock<std::shared_mutex> lock(s.mutex);
  for (const auto &descriptor : catalog()) {
    Resolved resolved;
    resolved.descriptor = &descriptor;
    const char *from_env = std::getenv(descriptor.key.c_str());
    const bool env_set = from_env != nullptr && *from_env != '\0';
    const auto stored = s.values.find(descriptor.key);
    if (stored != s.values.end()) {
      resolved.source = "store";
      resolved.configured = true;
      // The store wins, and the UI says so rather than letting a Helm value
      // look applied when it is not.
      resolved.envShadowed = env_set;
      resolved.updatedAt = stored->second.updatedAt;
      resolved.updatedBy = stored->second.updatedBy;
      if (descriptor.kind != Kind::Secret) resolved.value = stored->second.value;
    } else if (env_set) {
      resolved.source = "env";
      resolved.configured = true;
      if (descriptor.kind != Kind::Secret) resolved.value = trim_copy(from_env);
    } else {
      resolved.source = "default";
      resolved.configured = !descriptor.defaultValue.empty();
      if (descriptor.kind != Kind::Secret) resolved.value = descriptor.defaultValue;
    }
    out.push_back(std::move(resolved));
  }
  return out;
}

}  // namespace settings
