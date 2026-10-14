// ─── EndoriumFort — integration settings routes ─────────────────────────────
// Reads and writes the store behind settings.h. Kept out of settings.cc so the
// store stays free of crow and cheap to link into the unit-test targets.
//
// A PUT is validated as a whole before anything is written: an operator who
// mistypes one field gets the form back, not half of it applied.

#include "routes.h"

#include "app_context.h"
#include "route_common.h"
#include "settings.h"
#include "utils.h"

#include <string>
#include <vector>

namespace {

const char *kind_name(settings::Kind kind) {
  switch (kind) {
    case settings::Kind::Bool: return "bool";
    case settings::Kind::Int: return "int";
    case settings::Kind::Secret: return "secret";
    case settings::Kind::Enum: return "enum";
    case settings::Kind::Url: return "url";
    case settings::Kind::Csv: return "csv";
    case settings::Kind::String: break;
  }
  return "string";
}

}  // namespace

void register_settings_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/settings/integrations
  CROW_ROUTE(app, "/api/settings/integrations")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "settings.manage")) {
          return crow::response(403, "Forbidden");
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        const auto resolved = settings::resolve_all();
        for (size_t i = 0; i < resolved.size(); ++i) {
          const auto &item = resolved[i];
          const auto &descriptor = *item.descriptor;
          const int index = static_cast<int>(i);
          auto &out = payload["items"][index];
          out["key"] = descriptor.key;
          out["group"] = descriptor.group;
          out["subgroup"] = descriptor.subgroup;
          out["kind"] = kind_name(descriptor.kind);
          out["label"] = descriptor.label;
          out["hint"] = descriptor.hint;
          out["default"] = descriptor.defaultValue;
          // A secret is never read back: the UI shows whether one is set, and
          // writing a new one is the only way to change it.
          out["secret"] = descriptor.kind == settings::Kind::Secret;
          out["value"] = item.value;
          out["source"] = item.source;
          out["configured"] = item.configured;
          out["envShadowed"] = item.envShadowed;
          out["updatedAt"] = item.updatedAt;
          out["updatedBy"] = item.updatedBy;
          if (descriptor.kind == settings::Kind::Int) {
            out["min"] = descriptor.minValue;
            out["max"] = descriptor.maxValue;
          }
          if (!descriptor.enumValues.empty()) {
            out["enumValues"] = crow::json::wvalue::list();
            for (size_t v = 0; v < descriptor.enumValues.size(); ++v) {
              out["enumValues"][static_cast<int>(v)] = descriptor.enumValues[v];
            }
          }
        }
        return crow::response{payload};
      });

  // PUT /api/settings/integrations
  CROW_ROUTE(app, "/api/settings/integrations")
      .methods(crow::HTTPMethod::Put)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "settings.manage")) {
          return crow::response(403, "Forbidden");
        }
        auto body = crow::json::load(request.body);
        if (!body || !body.has("values") ||
            body["values"].t() != crow::json::type::Object) {
          return crow::response(400, "Expected a \"values\" object");
        }
        const auto &values = body["values"];
        const auto keys = values.keys();
        if (keys.empty()) return crow::response(400, "No values submitted");
        if (keys.size() > 256) return crow::response(400, "Too many values");

        // ── Phase 1: resolve and validate everything ──
        struct Change {
          std::string key;
          std::string value;  // empty = clear
        };
        std::vector<Change> changes;
        crow::json::wvalue rejected = crow::json::wvalue::list();
        int rejected_count = 0;
        for (const auto &key : keys) {
          const auto &raw = values[key];
          Change change;
          change.key = key;
          switch (raw.t()) {
            case crow::json::type::Null: break;  // clear
            case crow::json::type::String: change.value = std::string(raw.s()); break;
            case crow::json::type::True: change.value = "1"; break;
            case crow::json::type::False: change.value = "0"; break;
            case crow::json::type::Number: change.value = std::to_string(raw.i()); break;
            default: {
              rejected[rejected_count]["key"] = key;
              rejected[rejected_count]["error"] = "unsupported value type";
              ++rejected_count;
              continue;
            }
          }
          std::string error;
          if (!settings::check(change.key, change.value, error)) {
            rejected[rejected_count]["key"] = key;
            rejected[rejected_count]["error"] = error;
            ++rejected_count;
            continue;
          }
          changes.push_back(std::move(change));
        }
        if (rejected_count > 0) {
          crow::json::wvalue payload;
          payload["status"] = "invalid";
          payload["applied"] = 0;
          payload["rejected"] = std::move(rejected);
          // 400, not 422: crow has no entry for 422 and silently rewrites an
          // unknown code to 500, which would report a client mistake as a
          // server fault.
          return crow::response(400, payload);
        }

        // ── Phase 2: apply ──
        crow::json::wvalue failures = crow::json::wvalue::list();
        int failure_count = 0;
        int applied = 0;
        for (const auto &change : changes) {
          std::string error;
          const bool ok = change.value.empty()
                              ? settings::clear(ctx, change.key, auth->user, error)
                              : settings::set(ctx, change.key, change.value,
                                              auth->user, error);
          if (ok) {
            ++applied;
          } else {
            failures[failure_count]["key"] = change.key;
            failures[failure_count]["error"] = error;
            ++failure_count;
          }
        }

        crow::json::wvalue payload;
        payload["status"] = failure_count == 0 ? "ok" : "partial";
        payload["applied"] = applied;
        if (failure_count > 0) payload["rejected"] = std::move(failures);
        // A stored value takes effect on the next read, which for most
        // integrations is the next request; the SIEM worker picks it up on its
        // next batch.
        return crow::response(failure_count == 0 ? 200 : 500, payload);
      });
}
