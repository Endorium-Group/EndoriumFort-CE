// Agent tunnels obey the same access rules as sessions: a tunnel credential or
// ticket is only issued under a session opened through the access policy
// (reason, ticket, purpose, approval), and stops once that session ends.

#include "app_context.h"
#include "routes.h"
#include "tunnel.h"
#include "utils.h"

#include <iostream>
#include <string>
#include <unordered_map>

namespace {

int failures = 0;

void expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    ++failures;
  }
}

const char *kAgentUserAgent = "EndoriumFort-Agent/test";

crow::response dispatch(CrowApp &app, const std::string &url,
                        const std::string &body,
                        const std::string &token = "",
                        const std::string &tunnel_credential = "") {
  crow::request request;
  request.method = crow::HTTPMethod::Post;
  request.raw_url = url;
  request.url = url;
  request.body = body;
  request.http_ver_major = 1;
  request.http_ver_minor = 1;
  request.remote_ip_address = "127.0.0.1";
  request.add_header("Content-Type", "application/json");
  request.add_header("User-Agent", kAgentUserAgent);
  if (!token.empty()) request.add_header("Authorization", "Bearer " + token);
  if (!tunnel_credential.empty()) {
    request.add_header("X-EndoriumFort-Tunnel-Credential", tunnel_credential);
  }
  crow::response response;
  app.handle_full(request, response);
  if (!response.is_completed()) response.end();
  return response;
}

void seed_user(AppContext &ctx, int id, const std::string &name,
               const std::string &role, const std::string &token) {
  UserAccount user;
  user.id = id;
  user.username = name;
  user.password = "unused";
  user.role = role;
  user.createdAt = now_utc();
  user.updatedAt = user.createdAt;
  {
    std::lock_guard<std::mutex> lock(ctx.user_mutex);
    ctx.users[id] = user;
  }
  AuthSession auth;
  auth.userId = id;
  auth.user = name;
  auth.role = role;
  auth.token = token;
  auth.issuedAt = now_utc();
  auth.expiresAt = "9999-12-31T23:59:59Z";
  std::lock_guard<std::mutex> lock(ctx.auth_mutex);
  ctx.auth_sessions[token] = auth;
}

void seed_resource(AppContext &ctx, int id, const std::string &name,
                   const std::string &tags) {
  Resource resource;
  resource.id = id;
  resource.name = name;
  resource.target = "10.0.0." + std::to_string(id);
  resource.protocol = "agent";
  resource.agentProtocol = "rdp";
  resource.port = 3389;
  resource.tagsCsv = tags;
  resource.createdAt = now_utc();
  resource.updatedAt = resource.createdAt;
  std::lock_guard<std::mutex> lock(ctx.resource_mutex);
  ctx.resources[id] = resource;
}

std::string session_body(int resource_id,
                         const std::string &extra) {
  return "{\"resourceId\":" + std::to_string(resource_id) +
         ",\"target\":\"10.0.0." + std::to_string(resource_id) +
         "\",\"protocol\":\"agent\",\"port\":3389,\"user\":\"operator\"" +
         extra + "}";
}

int json_int(const crow::response &response, const char *key) {
  auto body = crow::json::load(response.body);
  if (!body || !body.has(key)) return 0;
  return static_cast<int>(body[key].i());
}

std::string json_string(const crow::response &response, const char *key) {
  auto body = crow::json::load(response.body);
  if (!body || !body.has(key)) return "";
  return body[key].s();
}

bool contains(const std::string &text, const std::string &fragment) {
  return text.find(fragment) != std::string::npos;
}

}  // namespace

int main() {
  AppContext ctx;
  ctx.init_database(":memory:");
  CrowApp app;
  register_auth_routes(app, ctx);
  register_session_routes(app, ctx);
  register_tunnel_routes(app, ctx);
  app.validate();

  std::string err;
  // zone:prod: JIT policy requiring a reason and an approval, 15 min max.
  ctx.sqlite.exec(
      "INSERT INTO access_policies (id, name, resource_tags_csv, "
      "require_justification, approval_mode, max_duration_seconds, enabled, "
      "created_at, updated_at) VALUES (1, 'prod-jit', 'zone:prod', 1, "
      "'required', 900, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
      err);
  ctx.sqlite.exec(
      "INSERT INTO user_resource_permissions (user_id, resource_id, created_at) "
      "VALUES (2, 2, 'x'), (2, 3, 'x'), (3, 2, 'x');",
      err);
  seed_user(ctx, 2, "operator", "operator", "operator-token");
  seed_user(ctx, 3, "other", "operator", "other-token");
  seed_resource(ctx, 2, "rdp-poste-01", "zone:prod");
  seed_resource(ctx, 3, "lab-box", "zone:lab");

  // ── Refusals: no session, or a session the policy would not open ──
  {
    auto r = dispatch(app, "/api/tunnel/ticket", "{\"resourceId\":2}",
                      "operator-token");
    expect(r.code == 403 && contains(r.body, "tied to a session"),
           "ticket without a session is refused (got " +
               std::to_string(r.code) + " " + r.body + ")");

    r = dispatch(app, "/api/tunnel/credential", "{\"resourceId\":2}",
                 "operator-token");
    expect(r.code == 400 && contains(r.body, "requires an access justification"),
           "credential without a reason is refused by the JIT policy (got " +
               std::to_string(r.code) + " " + r.body + ")");

    r = dispatch(app, "/api/tunnel/credential",
                 "{\"resourceId\":2,\"justification\":\"patching\"}",
                 "operator-token");
    expect(r.code == 400 && contains(r.body, "dual approval"),
           "credential without an approval is refused by the JIT policy (got " +
               std::to_string(r.code) + " " + r.body + ")");

    r = dispatch(app, "/api/sessions", session_body(2, ""),
                 "operator-token");
    expect(r.code == 400 && contains(r.body, "requires an access justification"),
           "POST /api/sessions applies the same rule");
  }

  // ── Accepted: session opened with reason + approved request ──
  AccessRequest approved;
  approved.id = 7;
  approved.resourceId = 2;
  approved.requester = "operator";
  approved.requesterRole = "operator";
  approved.status = "approved";
  approved.justification = "patching";
  approved.createdAt = now_utc();
  approved.reviewedAt = now_utc();
  approved.reviewedBy = "admin";
  {
    std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
    ctx.access_requests[approved.id] = approved;
  }

  auto created = dispatch(
      app, "/api/sessions",
      session_body(2,
                   ",\"justification\":\"patching\",\"accessRequestId\":7"),
      "operator-token");
  expect(created.code == 200, "session with reason + approval is opened (got " +
                                  std::to_string(created.code) + " " +
                                  created.body + ")");
  const int session_id = json_int(created, "id");

  // Someone else cannot bind that session to their agent token.
  auto foreign = dispatch(app, "/api/auth/agent-token",
                          "{\"sessionId\":" + std::to_string(session_id) + "}",
                          "other-token");
  expect(foreign.code == 403, "another user's session cannot be bound");

  auto minted = dispatch(app, "/api/auth/agent-token",
                         "{\"sessionId\":" + std::to_string(session_id) + "}",
                         "operator-token");
  expect(minted.code == 200, "agent token bound to the session is minted");
  const std::string agent_token = json_string(minted, "token");

  auto credential = dispatch(app, "/api/tunnel/credential",
                             "{\"resourceId\":2}", agent_token);
  expect(credential.code == 200, "credential under the session is issued (got " +
                                     std::to_string(credential.code) + " " +
                                     credential.body + ")");
  expect(json_int(credential, "sessionId") == session_id,
         "credential is tied to the session");
  const int ttl = json_int(credential, "ttlSeconds");
  expect(ttl > 0 && ttl <= 900, "credential stops at the JIT grant expiry");
  const std::string tunnel_credential = json_string(credential, "credential");

  auto ticket = dispatch(app, "/api/tunnel/ticket", "{\"resourceId\":2}", "",
                         tunnel_credential);
  expect(ticket.code == 200, "ticket through the credential is issued (got " +
                                 std::to_string(ticket.code) + " " +
                                 ticket.body + ")");
  ticket = dispatch(app, "/api/tunnel/ticket", "{\"resourceId\":2}", agent_token);
  expect(ticket.code == 200, "ticket through the bound agent token is issued");

  // The bound token and credential do not reach another resource.
  ticket = dispatch(app, "/api/tunnel/ticket", "{\"resourceId\":3}", agent_token);
  expect(ticket.code == 403, "bound token cannot mint tickets for another resource");

  // ── Ending the session stops the tunnel ──
  ctx.terminate_session(session_id, "operator", "operator", "session.terminate");
  ticket = dispatch(app, "/api/tunnel/ticket", "{\"resourceId\":2}", "",
                    tunnel_credential);
  expect(ticket.code == 403 && contains(ticket.body, "has ended"),
         "credential stops minting tickets once the session ended (got " +
             std::to_string(ticket.code) + " " + ticket.body + ")");

  // ── A resource without rules: the exchange opens an audited session ──
  auto lab = dispatch(app, "/api/tunnel/credential", "{\"resourceId\":3}",
                      "operator-token");
  expect(lab.code == 200, "credential for a rule-free resource is issued (got " +
                              std::to_string(lab.code) + " " + lab.body + ")");
  const int lab_session = json_int(lab, "sessionId");
  {
    std::lock_guard<std::mutex> lock(ctx.session_mutex);
    auto it = ctx.sessions.find(lab_session);
    expect(it != ctx.sessions.end() && it->second.status == "active" &&
               it->second.resourceId == 3,
           "the tunnel is recorded as an active session");
  }

  if (failures > 0) {
    std::cerr << failures << " agent tunnel JIT check(s) failed" << std::endl;
    return 1;
  }
  std::cout << "All agent tunnel JIT tests passed." << std::endl;
  return 0;
}
