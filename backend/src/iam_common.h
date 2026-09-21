#pragma once
// ─── EndoriumFort — LDAP/AD auth helpers (shared core + pro) ─────────────────
// LDAP authentication is woven into core login (/api/auth/login falls back to
// LDAP) AND used by the premium enterprise directory diagnostics in the pro/
// overlay. These helpers therefore live in a shared, core-linked TU so both
// editions can call them. Extracted from routes.cc.

#include "models.h"  // UserAccount

#include <optional>
#include <string>
#include <utility>
#include <vector>

struct AppContext;

struct LdapRuntimeConfig {
  bool enabled = false;
  std::string host;
  int port = 389;
  bool useTls = false;
  bool startTls = false;
  bool requireCert = true;
  std::string baseDn;
  std::string userAttribute = "sAMAccountName";
  std::string bindDnTemplate;
  std::string domain;
  std::string defaultRole = "operator";
  bool syncRole = false;
  std::string roleMap;
  std::string roleAdminMatchers;
  std::string roleAuditorMatchers;
};

struct LdapRoleResolution {
  std::string role = "operator";
  std::string strategy = "default";
  std::string matchedRule;
};

std::vector<std::pair<std::string, std::string>> parse_ldap_role_map(
    const std::string &raw_map);
LdapRuntimeConfig load_ldap_runtime_config();
LdapRoleResolution resolve_ldap_role(const LdapRuntimeConfig &cfg,
                                     const std::string &username,
                                     const std::string &directory_identity);
bool ldap_command_available();
std::string ldap_endpoint_uri(const LdapRuntimeConfig &cfg);
bool run_ldap_bind_command(const LdapRuntimeConfig &cfg,
                           const std::string &bind_identity,
                           const std::string &password,
                           std::string &directory_identity,
                           std::string &error_message);
bool ldap_authenticate_user(const LdapRuntimeConfig &cfg,
                            const std::string &username,
                            const std::string &password,
                            std::string &directory_identity,
                            std::string &error_message);
bool is_ldap_shadow_password(const std::string &password_hash);
std::optional<UserAccount> provision_ldap_shadow_user(
    AppContext &ctx, const std::string &username, const LdapRuntimeConfig &cfg,
    const std::string &resolved_role, bool &created, bool &updated,
    std::string &error_message);
