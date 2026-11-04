// ─── EndoriumFort — personal API token routes ───────────────────────────────
// Lets a signed-in person mint, list and revoke tokens for automation (CI,
// Terraform), and an administrator do the same for service accounts. Core. The rules a token is held to (scopes,
// reachable endpoints, source addresses) live in api_tokens.h; these routes
// themselves are never reachable with a token, so one cannot mint another.

#include "routes.h"

#include "api_tokens.h"
#include "app_context.h"
#include "route_common.h"
#include "utils.h"

#include <string>
#include <vector>

namespace {

crow::json::wvalue token_to_json(const ApiToken &t) {
  crow::json::wvalue out;
  out["id"] = t.id;
  out["userId"] = t.userId;
  out["owner"] = t.owner;
  out["name"] = t.name;
  out["tokenPrefix"] = t.tokenPrefix;
  out["scopes"] = t.scopes;
  out["allowedCidrs"] = t.allowedCidrs;
  out["createdAt"] = t.createdAt;
  out["expiresAt"] = t.expiresAt;
  out["lastUsedAt"] = t.lastUsedAt;
  out["lastUsedIp"] = t.lastUsedIp;
  out["revokedAt"] = t.revokedAt;
  const char *status = !t.revokedAt.empty()       ? "revoked"
                       : t.expiresAt <= now_utc() ? "expired"
                                                  : "active";
  out["status"] = status;
  return out;
}

void audit_token(AppContext &ctx, const AuthSession &auth, const char *type,
                 const ApiToken &token) {
  AuditEvent e;
  e.id = ctx.next_audit_id.fetch_add(1);
  e.type = type;
  e.actor = auth.user;
  e.role = auth.role;
  e.createdAt = now_utc();
  e.payloadJson = "{\"tokenId\":" + std::to_string(token.id) +
                  ",\"tokenPrefix\":\"" + json_escape(token.tokenPrefix) +
                  "\",\"name\":\"" + json_escape(token.name) +
                  "\",\"owner\":\"" + json_escape(token.owner) +
                  "\",\"scopes\":\"" + json_escape(api_tokens::join_csv(token.scopes)) +
                  "\",\"expiresAt\":\"" + json_escape(token.expiresAt) + "\"}";
  e.payloadIsJson = true;
  ctx.append_audit(e);
}

// Scopes this person could put on a token: grantable ones their role holds.
std::vector<std::string> grantable_for(AppContext &ctx, const AuthSession &auth) {
  std::vector<std::string> out;
  for (const auto &scope : api_tokens::grantable_scopes())
    if (ctx.has_permission(auth.userId, auth.role, scope)) out.push_back(scope);
  return out;
}

int max_lifetime_days() {
  return env_int_value("ENDORIUMFORT_API_TOKEN_MAX_DAYS",
                       api_tokens::kDefaultMaxLifetimeDays, 1, 3650);
}

}  // namespace

void register_api_token_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/tokens/scopes — what the caller may grant, and the lifetime cap.
  CROW_ROUTE(app, "/api/tokens/scopes")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth || auth->apiTokenId > 0)
          return crow::response(401, "Unauthorized");
        crow::json::wvalue payload;
        payload["scopes"] = grantable_for(ctx, *auth);
        payload["maxLifetimeDays"] = max_lifetime_days();
        return crow::response(payload);
      });

  // GET /api/tokens — the caller's tokens; ?all=1 lists everyone's for a
  // `users.manage` holder, so an administrator can find and revoke them.
  CROW_ROUTE(app, "/api/tokens")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth || auth->apiTokenId > 0)
          return crow::response(401, "Unauthorized");
        const char *all = request.url_params.get("all");
        const bool everyone = all && std::string(all) == "1";
        if (everyone && !has_permission(ctx, *auth, "users.manage"))
          return crow::response(403, "Forbidden");

        std::vector<crow::json::wvalue> items;
        for (const auto &t : ctx.list_api_tokens(everyone ? 0 : auth->userId))
          items.push_back(token_to_json(t));
        crow::json::wvalue payload;
        payload["items"] = std::move(items);
        return crow::response(payload);
      });

  // POST /api/tokens — mint a token. The clear value is in this response only.
  CROW_ROUTE(app, "/api/tokens")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth || auth->apiTokenId > 0)
          return crow::response(401, "Unauthorized");

        const auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON");

        // By default the token is the caller's. An administrator may instead
        // mint one for a service account, which cannot sign in to do it itself;
        // the scopes must then be held by both the administrator and the account.
        ApiToken token;
        token.userId = auth->userId;
        token.owner = auth->user;
        AuthSession holder = *auth;
        if (body.has("serviceAccountId")) {
          if (body["serviceAccountId"].t() != crow::json::type::Number)
            return crow::response(400, "serviceAccountId must be a number");
          if (!has_permission(ctx, *auth, "users.manage"))
            return crow::response(403, "Forbidden");
          const int account_id = static_cast<int>(body["serviceAccountId"].i());
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(account_id);
          if (it == ctx.users.end() || !it->second.serviceAccount)
            return crow::response(404, "Service account not found");
          token.userId = it->second.id;
          token.owner = it->second.username;
          holder.userId = it->second.id;
          holder.user = it->second.username;
          holder.role = it->second.role;
        }
        if (body.has("name") && body["name"].t() == crow::json::type::String)
          token.name = trim_copy(std::string(body["name"].s()));
        if (token.name.empty() || token.name.size() > api_tokens::kMaxNameLength)
          return crow::response(400, "name is required (max 64 characters)");

        if (!body.has("scopes") || body["scopes"].t() != crow::json::type::List)
          return crow::response(400, "scopes must be a list");
        std::vector<std::string> allowed;
        for (const auto &scope : grantable_for(ctx, *auth))
          if (ctx.has_permission(holder.userId, holder.role, scope)) allowed.push_back(scope);
        for (const auto &item : body["scopes"]) {
          if (item.t() != crow::json::type::String)
            return crow::response(400, "scopes must be strings");
          const std::string scope = item.s();
          if (!api_tokens::is_grantable_scope(scope))
            return crow::response(400, "Scope cannot be granted to a token: " + scope);
          if (!api_tokens::scope_allows(allowed, scope))
            return crow::response(403, "Permission not held: " + scope);
          if (!api_tokens::scope_allows(token.scopes, scope))
            token.scopes.push_back(scope);
        }
        if (token.scopes.empty())
          return crow::response(400, "At least one scope is required");

        if (body.has("allowedCidrs")) {
          if (body["allowedCidrs"].t() != crow::json::type::List)
            return crow::response(400, "allowedCidrs must be a list");
          for (const auto &item : body["allowedCidrs"]) {
            if (item.t() != crow::json::type::String)
              return crow::response(400, "allowedCidrs must be strings");
            const std::string cidr = trim_copy(std::string(item.s()));
            if (!api_tokens::is_valid_cidr(cidr))
              return crow::response(400, "Invalid address or CIDR: " + cidr);
            token.allowedCidrs.push_back(cidr);
          }
          if (token.allowedCidrs.size() > api_tokens::kMaxAllowedCidrs)
            return crow::response(400, "Too many allowedCidrs (max 16)");
        }

        const int max_days = max_lifetime_days();
        int days = 30;
        if (body.has("expiresInDays")) {
          if (body["expiresInDays"].t() != crow::json::type::Number)
            return crow::response(400, "expiresInDays must be a number");
          days = static_cast<int>(body["expiresInDays"].i());
        }
        if (days < 1 || days > max_days)
          return crow::response(
              400, "expiresInDays must be between 1 and " + std::to_string(max_days));
        token.expiresAt =
            utc_from_epoch_seconds(now_epoch_seconds() + int64_t{days} * 86400);

        if (ctx.count_active_api_tokens(token.userId) >= api_tokens::kMaxTokensPerUser)
          return crow::response(409, "Too many active tokens (max 25)");

        std::string plaintext;
        if (!ctx.create_api_token(token, plaintext))
          return crow::response(500, "Failed to create token");
        audit_token(ctx, *auth, "apitoken.create", token);

        crow::json::wvalue payload = token_to_json(token);
        payload["token"] = plaintext;
        return crow::response(201, payload);
      });

  // DELETE /api/tokens/<id> — revoke. Own tokens, or anyone's with users.manage.
  CROW_ROUTE(app, "/api/tokens/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int token_id) {
            auto auth = ctx.find_auth(request);
            if (!auth || auth->apiTokenId > 0)
              return crow::response(401, "Unauthorized");

            ApiToken target;
            for (const auto &t : ctx.list_api_tokens(0))
              if (t.id == token_id) target = t;
            if (target.id == 0) return crow::response(404, "Token not found");
            const bool own = target.userId == auth->userId;
            if (!own && !has_permission(ctx, *auth, "users.manage"))
              return crow::response(404, "Token not found");
            if (!ctx.revoke_api_token(token_id, own ? auth->userId : 0))
              return crow::response(409, "Token already revoked");

            audit_token(ctx, *auth, "apitoken.revoke", target);
            crow::json::wvalue payload;
            payload["status"] = "revoked";
            payload["id"] = token_id;
            return crow::response(payload);
          });
}
