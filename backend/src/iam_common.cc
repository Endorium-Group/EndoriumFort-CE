// ─── EndoriumFort — LDAP/AD auth helpers (implementation) ────────────────────
// Shared by core login (routes.cc) and pro/ enterprise diagnostics. Extracted
// from routes.cc. Structs live in iam_common.h.
#include "iam_common.h"

#include "app_context.h"
#include "route_common.h"  // env_flag_enabled / env_string_value / env_int_value
#include "utils.h"         // trim_copy, to_lower, now_utc, split_csv_compact

#include <cstdlib>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

bool env_has_non_empty_value(const char *name) {
  if (!name || !*name) return false;
  const char *raw = std::getenv(name);
  if (!raw) return false;
  return !trim_copy(raw).empty();
}

void apply_ldap_host_overrides(LdapRuntimeConfig &cfg,
                               const std::string &host_value) {
  std::string host = trim_copy(host_value);
  if (host.empty()) {
    cfg.host = "";
    return;
  }

  const std::string lower = to_lower(host);
  if (lower.rfind("ldap://", 0) == 0) {
    cfg.useTls = false;
    host = trim_copy(host.substr(7));
  } else if (lower.rfind("ldaps://", 0) == 0) {
    cfg.useTls = true;
    host = trim_copy(host.substr(8));
  }

  const size_t slash_pos = host.find('/');
  if (slash_pos != std::string::npos) {
    host = trim_copy(host.substr(0, slash_pos));
  }

  std::string host_only = host;
  int parsed_port = 0;

  if (!host.empty() && host.front() == '[') {
    const size_t closing = host.find(']');
    if (closing != std::string::npos) {
      host_only = host.substr(1, closing - 1);
      if (closing + 1 < host.size() && host[closing + 1] == ':') {
        const std::string port_part = trim_copy(host.substr(closing + 2));
        if (!port_part.empty() &&
            std::all_of(port_part.begin(), port_part.end(),
                        [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
          parsed_port = std::stoi(port_part);
        }
      }
    }
  } else {
    const size_t first_colon = host.find(':');
    const size_t last_colon = host.rfind(':');
    if (first_colon != std::string::npos && first_colon == last_colon) {
      const std::string maybe_port = trim_copy(host.substr(last_colon + 1));
      if (!maybe_port.empty() &&
          std::all_of(maybe_port.begin(), maybe_port.end(),
                      [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
        host_only = trim_copy(host.substr(0, last_colon));
        parsed_port = std::stoi(maybe_port);
      }
    }
  }

  cfg.host = trim_copy(host_only);
  if (parsed_port > 0 &&
      !env_has_non_empty_value("ENDORIUMFORT_LDAP_PORT")) {
    cfg.port = std::clamp(parsed_port, 1, 65535);
  }
}

std::vector<std::pair<std::string, std::string>> parse_ldap_role_map(
    const std::string &raw_map) {
  auto split_ldap_rules = [](const std::string &raw_rules) {
    std::vector<std::string> rules;
    const std::string trimmed = trim_copy(raw_rules);
    if (trimmed.empty()) return rules;

    const bool explicit_separator =
        trimmed.find(';') != std::string::npos ||
        trimmed.find('\n') != std::string::npos;
    if (!explicit_separator) {
      const std::string lowered = to_lower(trimmed);
      const bool dn_like = lowered.find(",ou=") != std::string::npos ||
                           lowered.find(",dc=") != std::string::npos ||
                           lowered.find(",cn=") != std::string::npos;
      if (dn_like) {
        rules.push_back(trimmed);
      } else {
        rules = split_csv_compact(trimmed);
      }
      return rules;
    }

    std::string current;
    for (char ch : trimmed) {
      if (ch == ';' || ch == '\n') {
        const std::string token = trim_copy(current);
        if (!token.empty()) rules.push_back(token);
        current.clear();
        continue;
      }
      current.push_back(ch);
    }
    const std::string trailing = trim_copy(current);
    if (!trailing.empty()) rules.push_back(trailing);
    return rules;
  };

  std::vector<std::pair<std::string, std::string>> role_map;
  for (const auto &entry_raw : split_ldap_rules(raw_map)) {
    const std::string entry = trim_copy(entry_raw);
    if (entry.empty()) continue;
    size_t separator = entry.rfind('=');
    if (separator == std::string::npos) separator = entry.rfind(':');
    if (separator == std::string::npos) continue;

    std::string key = to_lower(trim_copy(entry.substr(0, separator)));
    std::string role = normalize_user_role(trim_copy(entry.substr(separator + 1)));
    if (key.empty() ||
        !is_allowed_user_role(role, {"operator", "admin", "auditor"})) {
      continue;
    }
    role_map.emplace_back(key, role);
  }
  return role_map;
}

std::optional<std::string> first_matching_csv_token(
    const std::string &raw_csv, const std::string &haystack) {
  if (haystack.empty()) return std::nullopt;
  std::vector<std::string> tokens;
  const std::string trimmed = trim_copy(raw_csv);
  if (trimmed.find(';') != std::string::npos ||
      trimmed.find('\n') != std::string::npos) {
    std::string current;
    for (char ch : trimmed) {
      if (ch == ';' || ch == '\n') {
        const std::string token = trim_copy(current);
        if (!token.empty()) tokens.push_back(token);
        current.clear();
        continue;
      }
      current.push_back(ch);
    }
    const std::string trailing = trim_copy(current);
    if (!trailing.empty()) tokens.push_back(trailing);
  } else {
    const std::string lowered = to_lower(trimmed);
    const bool dn_like = lowered.find(",ou=") != std::string::npos ||
                         lowered.find(",dc=") != std::string::npos ||
                         lowered.find(",cn=") != std::string::npos;
    if (dn_like) {
      if (!trimmed.empty()) tokens.push_back(trimmed);
    } else {
      tokens = split_csv_compact(trimmed);
    }
  }

  for (const auto &token_raw : tokens) {
    const std::string token = to_lower(trim_copy(token_raw));
    if (token.empty()) continue;
    if (haystack.find(token) != std::string::npos) {
      return token;
    }
  }
  return std::nullopt;
}

LdapRoleResolution resolve_ldap_role(const LdapRuntimeConfig &cfg,
                                     const std::string &username,
                                     const std::string &directory_identity) {
  LdapRoleResolution resolution;
  resolution.role =
      is_allowed_user_role(cfg.defaultRole, {"operator", "admin", "auditor"})
          ? normalize_user_role(cfg.defaultRole)
          : "operator";

  const std::string normalized_username = to_lower(trim_copy(username));
  const std::string normalized_identity = to_lower(trim_copy(directory_identity));

  const auto role_map = parse_ldap_role_map(cfg.roleMap);
  for (const auto &entry : role_map) {
    if (!normalized_username.empty() && entry.first == normalized_username) {
      resolution.role = entry.second;
      resolution.strategy = "role_map_user";
      resolution.matchedRule = entry.first;
      return resolution;
    }
    if (!normalized_identity.empty() && entry.first == normalized_identity) {
      resolution.role = entry.second;
      resolution.strategy = "role_map_identity";
      resolution.matchedRule = entry.first;
      return resolution;
    }
  }

  const std::string haystack = normalized_username + " " + normalized_identity;
  if (auto token = first_matching_csv_token(cfg.roleAdminMatchers, haystack)) {
    resolution.role = "admin";
    resolution.strategy = "matcher_admin";
    resolution.matchedRule = *token;
    return resolution;
  }
  if (auto token = first_matching_csv_token(cfg.roleAuditorMatchers, haystack)) {
    resolution.role = "auditor";
    resolution.strategy = "matcher_auditor";
    resolution.matchedRule = *token;
    return resolution;
  }

  return resolution;
}

bool ldap_command_available() {
#ifdef _WIN32
  return false;
#else
  return std::system("command -v ldapwhoami >/dev/null 2>&1") == 0;
#endif
}

std::string shell_quote(const std::string &value) {
  std::string quoted = "'";
  for (char ch : value) {
    if (ch == '\'') {
      quoted += "'\"'\"'";
    } else {
      quoted.push_back(ch);
    }
  }
  quoted.push_back('\'');
  return quoted;
}

std::string replace_all_copy(std::string input, const std::string &from,
                             const std::string &to) {
  if (from.empty()) return input;
  size_t start = 0;
  while (true) {
    const size_t pos = input.find(from, start);
    if (pos == std::string::npos) break;
    input.replace(pos, from.size(), to);
    start = pos + to.size();
  }
  return input;
}

LdapRuntimeConfig load_ldap_runtime_config() {
  LdapRuntimeConfig cfg;
  cfg.enabled = env_flag_enabled("ENDORIUMFORT_LDAP_ENABLED", false);
  cfg.useTls = env_flag_enabled("ENDORIUMFORT_LDAP_USE_TLS", false);
  cfg.startTls = env_flag_enabled("ENDORIUMFORT_LDAP_STARTTLS", false);
  cfg.requireCert = env_flag_enabled("ENDORIUMFORT_LDAP_REQUIRE_CERT", true);
  cfg.host = env_string_value("ENDORIUMFORT_LDAP_HOST", "");
  cfg.port = env_int_value("ENDORIUMFORT_LDAP_PORT", cfg.useTls ? 636 : 389,
                           1, 65535);
  apply_ldap_host_overrides(cfg, cfg.host);
  cfg.baseDn = env_string_value("ENDORIUMFORT_LDAP_BASE_DN", "");
  cfg.userAttribute = env_string_value("ENDORIUMFORT_LDAP_USER_ATTRIBUTE",
                                       "sAMAccountName");
  cfg.bindDnTemplate =
      env_string_value("ENDORIUMFORT_LDAP_BIND_DN_TEMPLATE", "");
  if (cfg.bindDnTemplate.empty()) {
    cfg.bindDnTemplate = env_string_value("ENDORIUMFORT_LDAP_USER_TEMPLATE", "");
  }
  cfg.domain = env_string_value("ENDORIUMFORT_LDAP_AD_DOMAIN", "");
  cfg.defaultRole = normalize_user_role(
      env_string_value("ENDORIUMFORT_LDAP_DEFAULT_ROLE", "operator"));
  if (!is_allowed_user_role(cfg.defaultRole,
                            {"operator", "admin", "auditor"})) {
    cfg.defaultRole = "operator";
  }
  cfg.syncRole = env_flag_enabled("ENDORIUMFORT_LDAP_SYNC_ROLE", false);
  cfg.roleMap = env_string_value("ENDORIUMFORT_LDAP_ROLE_MAP", "");
  cfg.roleAdminMatchers =
      env_string_value("ENDORIUMFORT_LDAP_ROLE_ADMIN_MATCHERS", "");
  cfg.roleAuditorMatchers =
      env_string_value("ENDORIUMFORT_LDAP_ROLE_AUDITOR_MATCHERS", "");
  return cfg;
}

std::string ldap_bind_identity_for_user(const LdapRuntimeConfig &cfg,
                                        const std::string &username) {
  const std::string normalized_user = trim_copy(username);
  if (normalized_user.empty()) return "";

  if (!cfg.bindDnTemplate.empty()) {
    std::string identity = replace_all_copy(cfg.bindDnTemplate, "{user}",
                                            normalized_user);
    identity = replace_all_copy(identity, "{username}", normalized_user);
    return identity;
  }

  if (!cfg.domain.empty() && normalized_user.find('@') == std::string::npos &&
      normalized_user.find('\\') == std::string::npos) {
    return normalized_user + "@" + cfg.domain;
  }

  if (!cfg.baseDn.empty() && !cfg.userAttribute.empty()) {
    return cfg.userAttribute + "=" + normalized_user + "," + cfg.baseDn;
  }

  return normalized_user;
}

std::string ldap_endpoint_uri(const LdapRuntimeConfig &cfg) {
  const std::string scheme = cfg.useTls ? "ldaps" : "ldap";
  return scheme + "://" + cfg.host + ":" + std::to_string(cfg.port);
}

bool run_ldap_bind_command(const LdapRuntimeConfig &cfg,
                           const std::string &bind_identity,
                           const std::string &password,
                           std::string &directory_identity,
                           std::string &error_message) {
  std::vector<std::string> command = {
      "ldapwhoami", "-x", "-o", "nettimeout=5", "-H",
      ldap_endpoint_uri(cfg)};
  if (cfg.startTls && !cfg.useTls) {
    command.push_back("-ZZ");
  }
  command.push_back("-D");
  command.push_back(bind_identity);
  command.push_back("-w");
  command.push_back(password);

  std::ostringstream shell_command;
  if (!cfg.requireCert) {
    shell_command << "LDAPTLS_REQCERT=never ";
  }
  for (size_t i = 0; i < command.size(); ++i) {
    if (i > 0) shell_command << ' ';
    shell_command << shell_quote(command[i]);
  }
  shell_command << " 2>&1";

  FILE *pipe = popen(shell_command.str().c_str(), "r");
  if (!pipe) {
    error_message = "Failed to execute ldapwhoami";
    return false;
  }

  std::string output;
  char buffer[256];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    output.append(buffer);
  }
  const int rc = pclose(pipe);

  directory_identity = trim_copy(output);
  if (rc != 0) {
    error_message = directory_identity.empty() ? "LDAP bind failed"
                                               : directory_identity;
    return false;
  }

  if (directory_identity.empty()) {
    directory_identity = bind_identity;
  }
  return true;
}

bool ldap_authenticate_user(const LdapRuntimeConfig &cfg,
                            const std::string &username,
                            const std::string &password,
                            std::string &directory_identity,
                            std::string &error_message) {
  if (!cfg.enabled) {
    error_message = "LDAP integration is disabled";
    return false;
  }
  if (trim_copy(cfg.host).empty()) {
    error_message = "LDAP host is not configured";
    return false;
  }
  if (trim_copy(username).empty() || password.empty()) {
    error_message = "Missing LDAP username or password";
    return false;
  }
  if (!ldap_command_available()) {
    error_message = "ldapwhoami command is not available on this host";
    return false;
  }

  const std::string bind_identity = ldap_bind_identity_for_user(cfg, username);
  if (bind_identity.empty()) {
    error_message = "Unable to build LDAP bind identity";
    return false;
  }

  return run_ldap_bind_command(cfg, bind_identity, password, directory_identity,
                               error_message);
}

bool is_ldap_shadow_password(const std::string &password_hash) {
  return password_hash.rfind("ldap_external:", 0) == 0;
}

std::optional<UserAccount> provision_ldap_shadow_user(
  AppContext &ctx, const std::string &username, const LdapRuntimeConfig &cfg,
  const std::string &resolved_role, bool &created, bool &updated,
  std::string &error_message) {
  created = false;
  updated = false;

  std::string normalized_username = trim_copy(username);
  if (normalized_username.empty()) {
    error_message = "LDAP username is empty";
    return std::nullopt;
  }
  if (normalized_username.size() > 128) normalized_username.resize(128);

  const std::string wanted = to_lower(normalized_username);
  const std::string default_role =
      is_allowed_user_role(cfg.defaultRole, {"operator", "admin", "auditor"})
          ? normalize_user_role(cfg.defaultRole)
          : "operator";
  std::string provision_role = normalize_user_role(trim_copy(resolved_role));
  if (!is_allowed_user_role(provision_role, {"operator", "admin", "auditor"})) {
    provision_role = default_role;
  }

  UserAccount user;
  bool found_existing = false;
  bool persist_update = false;
  bool persist_insert = false;

  {
    std::lock_guard<std::mutex> lock(ctx.user_mutex);
    for (auto &entry : ctx.users) {
      if (to_lower(entry.second.username) != wanted) continue;
      found_existing = true;
      user = entry.second;
      if (is_ldap_shadow_password(user.password) && cfg.syncRole &&
          normalize_user_role(user.role) != provision_role) {
        user.role = provision_role;
        user.updatedAt = now_utc();
        entry.second = user;
        updated = true;
        persist_update = true;
      }
      break;
    }

    if (!found_existing) {
      created = true;
      persist_insert = true;
      user.id = ctx.next_user_id.fetch_add(1);
      user.username = normalized_username;
      user.password = "ldap_external:" + ctx.generate_token();
      user.role = provision_role;
      user.createdAt = now_utc();
      user.updatedAt = user.createdAt;
      user.bootstrapPasswordChangeRequired = false;
      user.bootstrapMfaRequired = false;
      ctx.users[user.id] = user;
    }
  }

  if (persist_insert && !ctx.insert_user(user)) {
    error_message = "Failed to persist LDAP user";
    return std::nullopt;
  }
  if (persist_update && !ctx.update_user_db(user)) {
    error_message = "Failed to update LDAP user role";
    return std::nullopt;
  }

  return user;
}
