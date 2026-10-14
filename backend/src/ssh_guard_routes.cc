// ─── EndoriumFort — SSH command guard routes ────────────────────────────────
// Reads and writes the blocklist behind ssh_guard.h. Core, not premium: the
// guard has no license feature, so an administrator must be able to configure
// it from the Community edition too. The Enterprise threat-detection page
// renders the same list through these endpoints.

#include "routes.h"

#include "app_context.h"
#include "route_common.h"
#include "ssh_guard.h"
#include "utils.h"

#include <string>

namespace {

crow::json::wvalue rule_to_json(const ssh_guard::Rule &rule) {
  crow::json::wvalue out;
  out["name"] = rule.name;
  out["command"] = rule.command;
  out["enabled"] = rule.enabled;
  out["builtin"] = rule.builtin;
  out["updatedAt"] = rule.updatedAt;
  return out;
}

void audit_rule(AppContext &ctx, const AuthSession &auth, const char *type,
                const std::string &name, const std::string &detail) {
  AuditEvent e;
  e.id = ctx.next_audit_id.fetch_add(1);
  e.type = type;
  e.actor = auth.user;
  e.role = auth.role;
  e.createdAt = now_utc();
  e.payloadJson = std::string("{\"rule\":\"") + json_escape(name) + "\"" +
                  detail + "}";
  e.payloadIsJson = true;
  ctx.append_audit(e);
}

}  // namespace

void register_ssh_guard_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/ssh-guard/rules — the whole blocklist, built-ins first.
  CROW_ROUTE(app, "/api/ssh-guard/rules")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage"))
          return crow::response(403, "Forbidden");

        std::vector<crow::json::wvalue> items;
        for (const auto &rule : ssh_guard::list(ctx))
          items.push_back(rule_to_json(rule));
        crow::json::wvalue payload;
        payload["items"] = std::move(items);
        return crow::response(payload);
      });

  // PUT /api/ssh-guard/rules/<name> — add or update a rule, or toggle one.
  CROW_ROUTE(app, "/api/ssh-guard/rules/<string>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, const std::string &name) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.manage"))
              return crow::response(403, "Forbidden");

            const auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON");
            const bool enabled =
                body.has("enabled") ? body["enabled"].b() : true;
            std::string command;
            if (body.has("command") &&
                body["command"].t() == crow::json::type::String)
              command = std::string(body["command"].s());

            std::string error;
            if (!ssh_guard::save(ctx, name, command, enabled, error))
              return crow::response(400, error);

            audit_rule(ctx, *auth, "ssh_guard.rule.configured", name,
                       std::string(",\"enabled\":") +
                           (enabled ? "true" : "false") + ",\"command\":\"" +
                           json_escape(command) + "\"");
            crow::json::wvalue payload;
            payload["status"] = "ok";
            return crow::response(payload);
          });

  // DELETE /api/ssh-guard/rules/<name> — custom rules only.
  CROW_ROUTE(app, "/api/ssh-guard/rules/<string>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, const std::string &name) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.manage"))
              return crow::response(403, "Forbidden");

            std::string error;
            if (!ssh_guard::remove(ctx, name, error))
              return crow::response(400, error);

            audit_rule(ctx, *auth, "ssh_guard.rule.removed", name, "");
            crow::json::wvalue payload;
            payload["status"] = "ok";
            return crow::response(payload);
          });
}
