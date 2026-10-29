// ─── EndoriumFort — File share resources (bastion side) ─────────────────────
// A "fileshare" resource opens a drive served by the separate file share
// service (fileshare/, its own container and volume). The bastion keeps what it
// already owns — who may open the resource, under which policy, for how long —
// and never touches a file: once POST /api/sessions has opened a session on
// the resource through the usual policy path, the owner of that session asks
// here for a short, single-use ticket signed with the key shared with the file
// service (ENDORIUMFORT_FILESHARE_SECRET). The browser trades it there for a
// session cookie scoped to that resource, and renews it here while the session
// stays active: ending the session cuts the drive within one renewal period.
//
// This is a CORE feature (shipped in Community Edition): no license gate.

#include "app_context.h"
#include "crypto.h"
#include "http_proxy.h"
#include "route_common.h"
#include "routes.h"
#include "utils.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

constexpr int kTicketTtlSeconds = 60;
// Without a policy duration, a drive session lasts a working day at most.
constexpr int64_t kDefaultSessionSeconds = 8 * 3600;
constexpr size_t kMinSecretLength = 32;

std::string trim_copy(std::string value) {
  const auto not_space = [](unsigned char c) { return !std::isspace(c); };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
  return value;
}

// The ticket key, from the environment or a mounted secret file (read per
// call: rotating the key needs no restart, and the file is tiny).
std::string fileshare_secret() {
  const char *file = std::getenv("ENDORIUMFORT_FILESHARE_SECRET_FILE");
  if (file && *file) {
    std::ifstream in(file);
    std::stringstream buf;
    buf << in.rdbuf();
    return trim_copy(buf.str());
  }
  const char *env = std::getenv("ENDORIUMFORT_FILESHARE_SECRET");
  return env ? trim_copy(env) : std::string();
}

std::string base64url(const std::string &raw) {
  std::string out = base64_encode(raw);
  for (char &c : out) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!out.empty() && out.back() == '=') out.pop_back();
  return out;
}

// "<base64url(claims)>.<hex hmac>", the format the file share service checks.
std::string sign_claims(const std::string &secret, const std::string &claims_json) {
  const std::string body = base64url(claims_json);
  return body + "." + crypto::hmac_sha256_hex(secret, body);
}

// ENDORIUMFORT_FILESHARE_UPSTREAM ("http://host:port") → host, port.
bool parse_upstream(std::string url, std::string &host, int &port) {
  const std::string scheme = "http://";
  if (url.rfind(scheme, 0) != 0) return false;
  url = url.substr(scheme.size());
  while (!url.empty() && url.back() == '/') url.pop_back();
  if (url.empty() || url.find('/') != std::string::npos) return false;
  port = 80;
  const auto colon = url.rfind(':');
  if (colon != std::string::npos) {
    try {
      port = std::stoi(url.substr(colon + 1));
    } catch (...) {
      return false;
    }
    url = url.substr(0, colon);
  }
  host = url;
  return !host.empty() && port > 0 && port <= 65535;
}

void audit_purge(AppContext &ctx, const std::string &actor, const std::string &role,
                 int resource_id, const std::string &outcome,
                 const std::string &detail) {
  AuditEvent event;
  event.id = ctx.next_audit_id.fetch_add(1);
  event.type = "fileshare.purge";
  event.actor = actor;
  event.role = role;
  event.createdAt = now_utc();
  event.payloadJson = "{\"resourceId\":" + std::to_string(resource_id) +
                      ",\"outcome\":\"" + json_escape(outcome) + "\"" +
                      ",\"detail\":\"" + json_escape(detail) + "\"}";
  event.payloadIsJson = true;
  ctx.append_audit(event);
}

bool may_open_resource(AppContext &ctx, int user_id, const std::string &role,
                       int resource_id) {
  if (ctx.has_permission(user_id, role, "resources.manage")) return true;
  const auto allowed = ctx.get_resource_permissions(user_id);
  return std::find(allowed.begin(), allowed.end(), resource_id) != allowed.end();
}

// Sessions that already received a ticket: renewals are not journaled again.
std::mutex g_ticketed_mutex;
std::unordered_set<int> g_ticketed_sessions;

}  // namespace

void fileshare_purge_space(AppContext &ctx, int resource_id,
                           const std::string &actor, const std::string &role) {
  const std::string secret = fileshare_secret();
  const char *upstream_env = std::getenv("ENDORIUMFORT_FILESHARE_UPSTREAM");
  std::string host;
  int port = 0;
  if (secret.size() < kMinSecretLength || !upstream_env ||
      !parse_upstream(upstream_env, host, port)) {
    audit_purge(ctx, actor, role, resource_id, "skipped",
                "file share service not configured; run `endoriumfort-files purge " +
                    std::to_string(resource_id) + "` on the file service");
    return;
  }
  // In the background: deleting the resource must not wait on another service.
  std::thread([&ctx, resource_id, actor, role, secret, host, port]() {
    std::string last_error;
    for (int attempt = 0; attempt < 3; ++attempt) {
      if (attempt > 0) std::this_thread::sleep_for(std::chrono::seconds(attempt * 5));
      const int64_t now = now_epoch_seconds();
      std::ostringstream claims;
      claims << "{\"v\":1,\"typ\":\"purge\""
             << ",\"sub\":\"" << json_escape(actor) << "\""
             << ",\"rid\":" << resource_id
             << ",\"iat\":" << now
             << ",\"exp\":" << (now + kTicketTtlSeconds)
             << ",\"jti\":\"" << ctx.generate_token() << "\"}";
      const std::string body =
          "{\"order\":\"" + sign_claims(secret, claims.str()) + "\"}";
      std::string error;
      const auto response = http_proxy_request(
          "POST", host, port,
          "/internal/spaces/" + std::to_string(resource_id) + "/purge", body,
          {{"Content-Type", "application/json"}}, error);
      if (error.empty() && response.status_code == 200) {
        audit_purge(ctx, actor, role, resource_id, "ok", "");
        return;
      }
      last_error = error.empty() ? "HTTP " + std::to_string(response.status_code)
                                 : error;
    }
    audit_purge(ctx, actor, role, resource_id, "failed",
                last_error + "; run `endoriumfort-files purge " +
                    std::to_string(resource_id) + "` on the file service");
  }).detach();
}

void register_fileshare_routes(CrowApp &app, AppContext &ctx) {
  // POST /api/sessions/<id>/fileshare-ticket — for the session's owner only,
  // while the session is active.
  CROW_ROUTE(app, "/api/sessions/<int>/fileshare-ticket")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int session_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            Session session;
            {
              std::lock_guard<std::mutex> lock(ctx.session_mutex);
              auto it = ctx.sessions.find(session_id);
              if (it == ctx.sessions.end())
                return crow::response(404, "Session not found");
              session = it->second;
            }
            // Driving the drive is for whoever opened the session, admins
            // included: the files are opened under that person's name.
            if (!ctx.may_drive_session(auth->user, ctx.session_owner(session)))
              return crow::response(404, "Session not found");
            if (to_lower(session.protocol) != "fileshare")
              return crow::response(400, "Not a file share session");
            if (session.status != "active")
              return crow::response(409, "Session is no longer active");
            if (!may_open_resource(ctx, auth->userId, auth->role, session.resourceId))
              return crow::response(403, "Forbidden");

            std::string resource_name;
            {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(session.resourceId);
              if (it == ctx.resources.end() ||
                  to_lower(it->second.protocol) != "fileshare")
                return crow::response(404, "Resource not found");
              resource_name = it->second.name;
            }

            const std::string secret = fileshare_secret();
            if (secret.size() < kMinSecretLength)
              return crow::response(503, "File share service is not configured");

            const int64_t now = now_epoch_seconds();
            int64_t session_end = now + kDefaultSessionSeconds;
            if (session.maxDurationSeconds > 0) {
              if (const auto started = parse_utc_epoch_seconds(session.createdAt))
                session_end = *started + session.maxDurationSeconds;
            }
            if (session_end <= now) {
              ctx.terminate_session(session_id, "system", "system",
                                    "session.expire");
              return crow::response(409, "Session is no longer active");
            }

            std::ostringstream claims;
            claims << "{\"v\":1"
                   << ",\"sub\":\"" << json_escape(auth->user) << "\""
                   << ",\"uid\":" << auth->userId
                   << ",\"rid\":" << session.resourceId
                   << ",\"sid\":" << session_id
                   << ",\"iat\":" << now
                   << ",\"exp\":" << (now + kTicketTtlSeconds)
                   << ",\"sexp\":" << session_end
                   << ",\"jti\":\"" << ctx.generate_token() << "\"}";
            const std::string ticket = sign_claims(secret, claims.str());

            bool first = false;
            {
              std::lock_guard<std::mutex> lock(g_ticketed_mutex);
              first = g_ticketed_sessions.insert(session_id).second;
            }
            if (first) {
              AuditEvent event;
              event.id = ctx.next_audit_id.fetch_add(1);
              event.type = "fileshare.open";
              event.actor = auth->user;
              event.role = auth->role;
              event.createdAt = now_utc();
              event.payloadJson =
                  "{\"sessionId\":" + std::to_string(session_id) +
                  ",\"resourceId\":" + std::to_string(session.resourceId) +
                  ",\"resource\":\"" + json_escape(resource_name) + "\"}";
              event.payloadIsJson = true;
              ctx.append_audit(event);
            }

            crow::json::wvalue payload;
            payload["ticket"] = ticket;
            payload["resourceId"] = session.resourceId;
            payload["resourceName"] = resource_name;
            payload["user"] = auth->user;
            payload["sessionId"] = session_id;
            payload["ticketTtlSeconds"] = kTicketTtlSeconds;
            return crow::response{payload};
          });

  // GET /api/resources/<id>/fileshare/directory — the people a drive item can
  // be shared with: those who may open the same resource. Usernames only.
  CROW_ROUTE(app, "/api/resources/<int>/fileshare/directory")(
      [&ctx](const crow::request &request, int resource_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          auto it = ctx.resources.find(resource_id);
          if (it == ctx.resources.end() ||
              to_lower(it->second.protocol) != "fileshare")
            return crow::response(404, "Resource not found");
        }
        if (!may_open_resource(ctx, auth->userId, auth->role, resource_id))
          return crow::response(403, "Forbidden");

        std::vector<UserAccount> accounts;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          accounts.reserve(ctx.users.size());
          for (const auto &entry : ctx.users) accounts.push_back(entry.second);
        }
        std::vector<std::string> names;
        for (const auto &account : accounts) {
          if (account.username == auth->user) continue;
          if (may_open_resource(ctx, account.id, account.role, resource_id))
            names.push_back(account.username);
        }
        std::sort(names.begin(), names.end());

        crow::json::wvalue payload;
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < names.size(); ++i)
          payload["items"][static_cast<int>(i)]["username"] = names[i];
        return crow::response{payload};
      });
}
