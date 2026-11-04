// Unit tests for personal API tokens: the pure policy in api_tokens.h and the
// storage / resolution in AppContext.
#include "api_tokens.h"
#include "app_context.h"
#include "utils.h"

#include <iostream>
#include <string>

namespace {
int failures = 0;
bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    ++failures;
  }
  return condition;
}

void test_policy() {
  using namespace api_tokens;
  expect(looks_like_api_token("efapi_abc"), "efapi_ prefix recognised");
  expect(!looks_like_api_token("eft_abc"), "session tokens are not API tokens");

  expect(is_grantable_scope("resources.manage"), "resources.manage grantable");
  expect(!is_grantable_scope("ssh.connect"), "ssh.connect not grantable");
  expect(!is_grantable_scope("sessions.create"), "sessions.create not grantable");
  expect(!is_grantable_scope("access_requests.review"), "review not grantable");
  expect(!is_grantable_scope("*"), "wildcard not grantable");

  expect(split_csv(join_csv({"a", "b"})).size() == 2, "csv round-trip");
  expect(split_csv("").empty(), "empty csv is empty");

  // Endpoint boundary.
  expect(path_allowed("GET", "/api/resources"), "list resources");
  expect(path_allowed("PUT", "/api/resources/4"), "update resource");
  expect(path_allowed("GET", "/api/health"), "health");
  expect(path_allowed("GET", "/api/sessions"), "list sessions");
  expect(!path_allowed("POST", "/api/sessions"), "cannot open a session");
  expect(path_allowed("POST", "/api/sessions/7/terminate"), "terminate session");
  expect(!path_allowed("GET", "/api/sessions/stream"), "no session stream");
  expect(!path_allowed("POST", "/api/sessions/7/files/upload"), "no file upload");
  expect(!path_allowed("POST", "/api/sessions/7/fileshare-ticket"), "no drive ticket");
  expect(!path_allowed("POST", "/api/resources/3/ephemeral-credentials"),
         "no ephemeral credentials");
  expect(path_allowed("GET", "/api/access-requests"), "list access requests");
  expect(!path_allowed("POST", "/api/access-requests/2/approve"), "cannot approve");
  expect(!path_allowed("POST", "/api/tokens"), "cannot mint tokens");
  expect(!path_allowed("POST", "/api/auth/change-password"), "cannot change password");
  expect(!path_allowed("POST", "/api/auth/setup-2fa"), "cannot touch MFA");
  expect(!path_allowed("GET", "/api/ws/ssh"), "no websocket");
  expect(!path_allowed("GET", "/proxy/3"), "no web proxy");
  expect(!path_allowed("GET", "/api/usersX"), "prefix needs a segment boundary");
  expect(path_allowed("GET", "/api/users/"), "trailing slash tolerated");
  expect(!path_allowed("GET", "/api/devices"), "unlisted endpoint refused");

  // Source addresses.
  expect(is_valid_cidr("10.0.0.0/8"), "valid CIDR");
  expect(is_valid_cidr("192.168.1.10"), "valid single address");
  expect(is_valid_cidr("2001:db8::1"), "valid IPv6 literal");
  expect(!is_valid_cidr("10.0.0.0/33"), "mask too long");
  expect(!is_valid_cidr("300.1.1.1"), "octet out of range");
  expect(!is_valid_cidr("example.com"), "hostnames refused");
  expect(ip_matches("10.2.3.4", "10.0.0.0/8"), "inside CIDR");
  expect(!ip_matches("11.2.3.4", "10.0.0.0/8"), "outside CIDR");
  expect(ip_matches("::ffff:10.2.3.4", "10.0.0.0/8"), "IPv4-mapped peer");
  expect(ip_matches("1.2.3.4", "0.0.0.0/0"), "/0 matches all");
  expect(ip_allowed("8.8.8.8", {}), "no restriction allows all");
  expect(!ip_allowed("8.8.8.8", {"10.0.0.0/8", "192.168.0.0/16"}), "restricted");
}

void test_storage() {
  AppContext ctx;
  std::string err;
  if (!expect(ctx.sqlite.open(":memory:", err), "open in-memory db")) return;
  ctx.sqlite.exec(
      "CREATE TABLE api_tokens (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,"
      "name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, token_prefix TEXT NOT NULL,"
      "scopes TEXT NOT NULL, allowed_cidrs TEXT, created_at TEXT NOT NULL,"
      "expires_at TEXT NOT NULL, last_used_at TEXT, last_used_ip TEXT, revoked_at TEXT);",
      err);
  ctx.audit_path = "";  // keep the test from writing a journal

  UserAccount admin;
  admin.id = 1;
  admin.username = "alice";
  admin.role = "admin";
  ctx.users[1] = admin;

  ApiToken t;
  t.userId = 1;
  t.name = "terraform";
  t.scopes = {"resources.read"};
  t.expiresAt = utc_from_epoch_seconds(now_epoch_seconds() + 3600);
  std::string clear;
  expect(ctx.create_api_token(t, clear), "create token");
  expect(t.id > 0, "token id assigned");
  expect(clear.rfind("efapi_", 0) == 0 && clear.size() == 6 + 64, "token format");
  expect(t.tokenPrefix == clear.substr(0, 14), "display prefix");

  auto auth = ctx.resolve_api_token(clear, "203.0.113.5");
  if (expect(auth.has_value(), "token resolves")) {
    expect(auth->user == "alice" && auth->apiTokenId == t.id, "identity of owner");
    expect(ctx.has_permission(*auth, "resources.read"), "scoped permission allowed");
    expect(!ctx.has_permission(*auth, "resources.manage"),
           "admin owner, but resources.manage outside scope");
  }
  int uses = 0;
  for (const auto &e : ctx.audit_events) uses += e.type == "apitoken.use";
  expect(uses == 1, "first use journaled once");
  ctx.resolve_api_token(clear, "203.0.113.5");
  uses = 0;
  for (const auto &e : ctx.audit_events) uses += e.type == "apitoken.use";
  expect(uses == 1, "repeated use within the hour not journaled again");
  expect(!ctx.resolve_api_token(clear + "0", "203.0.113.5"), "wrong token refused");
  expect(!ctx.resolve_api_token("efapi_", "203.0.113.5"), "empty token refused");

  // Scope never exceeds the owner's role.
  ctx.users[1].role = "auditor";
  auto demoted = ctx.resolve_api_token(clear, "203.0.113.5");
  expect(demoted && demoted->role == "auditor", "demotion applies at once");
  t.scopes = {"resources.manage"};
  ApiToken wide = t;
  std::string clear_wide;
  ctx.create_api_token(wide, clear_wide);
  auto wide_auth = ctx.resolve_api_token(clear_wide, "203.0.113.5");
  expect(wide_auth && !ctx.has_permission(*wide_auth, "resources.manage"),
         "scope cannot exceed the owner's role");
  ctx.users[1].role = "admin";

  // Source restriction.
  ApiToken pinned = t;
  pinned.allowedCidrs = {"10.0.0.0/8"};
  std::string clear_pinned;
  ctx.create_api_token(pinned, clear_pinned);
  expect(ctx.resolve_api_token(clear_pinned, "10.1.2.3").has_value(), "inside CIDR");
  expect(!ctx.resolve_api_token(clear_pinned, "203.0.113.5"), "outside CIDR refused");

  // Expiry.
  ApiToken old = t;
  old.expiresAt = utc_from_epoch_seconds(now_epoch_seconds() - 10);
  std::string clear_old;
  ctx.create_api_token(old, clear_old);
  expect(!ctx.resolve_api_token(clear_old, "203.0.113.5"), "expired token refused");

  // Listing and ownership.
  expect(ctx.list_api_tokens(1).size() == 4, "owner sees 4 tokens");
  expect(ctx.list_api_tokens(2).empty(), "other user sees none");
  expect(ctx.list_api_tokens(0).size() == 4, "admin listing sees all");
  expect(ctx.list_api_tokens(1)[0].owner == "alice", "owner name filled in");
  expect(ctx.count_active_api_tokens(1) == 3, "expired token not counted");

  // Revocation.
  expect(!ctx.revoke_api_token(t.id, 2), "another user cannot revoke");
  expect(ctx.revoke_api_token(t.id, 1), "owner revokes");
  expect(!ctx.revoke_api_token(t.id, 1), "second revoke is a no-op");
  expect(!ctx.resolve_api_token(clear, "203.0.113.5"), "revoked token refused");
  expect(ctx.revoke_api_token(wide.id, 0), "admin revokes any");

  // Owner gone, or still in first-login setup.
  ctx.users[1].bootstrapMfaRequired = true;
  expect(!ctx.resolve_api_token(clear_pinned, "10.1.2.3"), "setup pending refused");
  ctx.users.erase(1);
  expect(!ctx.resolve_api_token(clear_pinned, "10.1.2.3"), "deleted owner refused");

  // Session tokens keep their own path: an AuthSession without a token id
  // is not narrowed.
  AuthSession human;
  human.userId = 3;
  human.role = "admin";
  expect(ctx.has_permission(human, "resources.manage"), "human admin unaffected");
}
}  // namespace

int main() {
  test_policy();
  test_storage();
  if (failures == 0) std::cout << "api_tokens_test: all checks passed" << std::endl;
  return failures == 0 ? 0 : 1;
}
