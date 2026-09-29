// ─── EndoriumFort — Remote Browser Isolation (RBI) ───────────────────────────
// A "real" RBI: for an http/https resource the bastion launches a throwaway
// headless Chromium *server-side*, navigates it to the resource URL, and streams
// the rendered pixels to the operator's browser as JPEG frames over a WebSocket
// (Chrome DevTools Protocol screencast). Keyboard/mouse are forwarded back as
// CDP Input events. The client's browser never touches the target site — only
// pixels cross the wire — so hostile web content stays isolated on the server.
//
// Transport to Chromium is CDP-over-pipe (`--remote-debugging-pipe`, fd 3/4,
// NUL-delimited JSON): no DevTools TCP port is ever opened and no WebSocket
// *client* library is needed. One ephemeral browser + user-data-dir per session,
// destroyed on close.
//
// This is a CORE feature (shipped in Community Edition too): no license gate. It
// reuses the same session/permission/audit seams as the web SSH terminal.
// Linux only (fork/exec + pipe wiring). On other platforms the WS reports that
// RBI is unavailable.

#include "app_context.h"
#include "routes.h"
#include "utils.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#define EF_RBI 1
#endif

namespace {

#ifdef EF_RBI

// Chromium reads CDP commands from fd 3 and writes responses/events to fd 4 when
// launched with --remote-debugging-pipe.
constexpr int kChromeReadFd = 3;
constexpr int kChromeWriteFd = 4;

// Resolve the Chromium binary: explicit env override, then common names.
std::string resolve_chromium() {
  const char *env = std::getenv("ENDORIUMFORT_RBI_CHROMIUM");
  if (env && *env) return env;
  for (const char *cand :
       {"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"}) {
    // execvp() searches PATH; we just pick the first plausible name. Existence is
    // checked at launch (exec failure → error to the client).
    return cand;
  }
  return "chromium";
}

bool has_resource_access(AppContext &ctx, int user_id, const std::string &role,
                         int resource_id) {
  if (resource_id <= 0) return false;
  if (ctx.has_permission(user_id, role, "resources.manage")) return true;
  const auto allowed = ctx.get_resource_permissions(user_id);
  return std::find(allowed.begin(), allowed.end(), resource_id) != allowed.end();
}

void audit(AppContext &ctx, const std::string &type, const std::string &actor,
           const std::string &role, const std::string &json_body) {
  AuditEvent e;
  e.id = ctx.next_audit_id.fetch_add(1);
  e.type = type;
  e.actor = actor;
  e.role = role;
  e.createdAt = now_utc();
  e.payloadJson = json_body;
  e.payloadIsJson = true;
  ctx.append_audit(e);
}

// One live RBI session: a headless Chromium spoken to over the CDP pipe.
struct RbiSession {
  pid_t pid = -1;
  int fd_in = -1;   // host → browser (browser's fd 3)
  int fd_out = -1;  // browser → host (browser's fd 4)
  std::thread reader;
  std::atomic<bool> running{false};
  std::atomic<long> cmd_id{1};
  std::mutex write_mutex;
  std::string cdp_session;  // flattened attach session id for the page target
  std::string rbuf;         // partial-message accumulator for fd_out
  int view_w = 1280;
  int view_h = 800;
  int session_id = 0;
  int resource_id = 0;
  int auth_user_id = 0;
  int64_t rec_handle = 0;  // premium recording handle (0 = not recording)
  std::string user;
  std::string role;
  std::string user_data_dir;
};

// Auth snapshot handed from onaccept to onopen via the connection userdata.
struct RbiAccept {
  int user_id = 0;
  std::string role;
};

std::mutex g_conns_mutex;
std::unordered_map<crow::websocket::connection *, std::shared_ptr<RbiSession>>
    g_conns;

// Write one NUL-terminated CDP message to the browser.
void cdp_raw(const std::shared_ptr<RbiSession> &s, const std::string &msg) {
  if (!s || s->fd_in < 0) return;
  std::lock_guard<std::mutex> lock(s->write_mutex);
  std::string framed = msg;
  framed.push_back('\0');
  const char *p = framed.data();
  size_t remaining = framed.size();
  while (remaining > 0) {
    ssize_t w = write(s->fd_in, p, remaining);
    if (w <= 0) break;
    p += w;
    remaining -= static_cast<size_t>(w);
  }
}

// Build and send a CDP command. `params_json` is a raw JSON object literal (or
// empty). Page/Input/Emulation commands ride the flattened page session.
void cdp(const std::shared_ptr<RbiSession> &s, const std::string &method,
         const std::string &params_json, bool with_session) {
  std::ostringstream o;
  o << "{\"id\":" << s->cmd_id.fetch_add(1) << ",\"method\":\"" << method << "\"";
  if (!params_json.empty()) o << ",\"params\":" << params_json;
  if (with_session && !s->cdp_session.empty())
    o << ",\"sessionId\":\"" << s->cdp_session << "\"";
  o << "}";
  cdp_raw(s, o.str());
}

// Read more bytes from the browser and split the accumulator into complete
// (NUL-delimited) messages. Returns false when the pipe is closed.
bool pump(const std::shared_ptr<RbiSession> &s, std::vector<std::string> &out) {
  char buf[65536];
  ssize_t n = read(s->fd_out, buf, sizeof(buf));
  if (n <= 0) return false;
  s->rbuf.append(buf, static_cast<size_t>(n));
  size_t start = 0, nul;
  while ((nul = s->rbuf.find('\0', start)) != std::string::npos) {
    out.emplace_back(s->rbuf.substr(start, nul - start));
    start = nul + 1;
  }
  if (start > 0) s->rbuf.erase(0, start);
  return true;
}

void send_device_metrics(const std::shared_ptr<RbiSession> &s) {
  std::ostringstream p;
  p << "{\"width\":" << s->view_w << ",\"height\":" << s->view_h
    << ",\"deviceScaleFactor\":1,\"mobile\":false}";
  cdp(s, "Emulation.setDeviceMetricsOverride", p.str(), true);
}

void start_screencast(const std::shared_ptr<RbiSession> &s) {
  std::ostringstream p;
  p << "{\"format\":\"jpeg\",\"quality\":60,\"maxWidth\":" << s->view_w
    << ",\"maxHeight\":" << s->view_h << ",\"everyNthFrame\":1}";
  cdp(s, "Page.startScreencast", p.str(), true);
}

// Fork+exec Chromium with the CDP pipe wired to fd 3/4. Returns false on failure.
bool launch_chromium(const std::shared_ptr<RbiSession> &s, std::string &error) {
  int in_pipe[2];   // host writes in_pipe[1] → browser reads in_pipe[0] (fd 3)
  int out_pipe[2];  // browser writes out_pipe[1] (fd 4) → host reads out_pipe[0]
  if (pipe(in_pipe) != 0) {
    error = "pipe() failed";
    return false;
  }
  if (pipe(out_pipe) != 0) {
    close(in_pipe[0]);
    close(in_pipe[1]);
    error = "pipe() failed";
    return false;
  }

  char tmpl[] = "/tmp/ef-rbi-XXXXXX";
  char *dir = mkdtemp(tmpl);
  if (!dir) {
    close(in_pipe[0]); close(in_pipe[1]);
    close(out_pipe[0]); close(out_pipe[1]);
    error = "mkdtemp() failed";
    return false;
  }
  s->user_data_dir = dir;

  const std::string chromium = resolve_chromium();
  const std::string udd = "--user-data-dir=" + s->user_data_dir;
  const std::string winsize =
      "--window-size=" + std::to_string(s->view_w) + "," +
      std::to_string(s->view_h);

  pid_t pid = fork();
  if (pid < 0) {
    close(in_pipe[0]); close(in_pipe[1]);
    close(out_pipe[0]); close(out_pipe[1]);
    std::filesystem::remove_all(s->user_data_dir);
    s->user_data_dir.clear();
    error = "fork() failed";
    return false;
  }

  if (pid == 0) {
    // Child: wire the CDP pipe onto fd 3 (read) and fd 4 (write).
    if (in_pipe[0] != kChromeReadFd) {
      dup2(in_pipe[0], kChromeReadFd);
    } else {
      fcntl(kChromeReadFd, F_SETFD, 0);  // clear CLOEXEC
    }
    if (out_pipe[1] != kChromeWriteFd) {
      dup2(out_pipe[1], kChromeWriteFd);
    } else {
      fcntl(kChromeWriteFd, F_SETFD, 0);
    }
    // Close every original pipe fd that isn't now 3/4.
    for (int fd : {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1]}) {
      if (fd != kChromeReadFd && fd != kChromeWriteFd) close(fd);
    }

    std::vector<std::string> args = {
        chromium,
        "--headless=new",
        "--remote-debugging-pipe",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
        "--hide-scrollbars",
        "--mute-audio",
        "--no-sandbox",  // container-friendly; RBI targets are internal resources
        udd,
        winsize,
        "about:blank",
    };
    // Optional extra flags (space-separated) for site-specific tuning.
    if (const char *extra = std::getenv("ENDORIUMFORT_RBI_FLAGS")) {
      std::istringstream iss(extra);
      std::string tok;
      while (iss >> tok) args.push_back(tok);
    }
    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (auto &a : args) argv.push_back(const_cast<char *>(a.c_str()));
    argv.push_back(nullptr);
    execvp(chromium.c_str(), argv.data());
    _exit(127);  // exec failed
  }

  // Parent.
  close(in_pipe[0]);
  close(out_pipe[1]);
  s->pid = pid;
  s->fd_in = in_pipe[1];
  s->fd_out = out_pipe[0];
  s->running = true;
  return true;
}

void teardown(AppContext &ctx, const std::shared_ptr<RbiSession> &s) {
  if (!s) return;
  bool was_running = s->running.exchange(false);
  if (s->pid > 0) kill(s->pid, SIGTERM);
  if (s->fd_in >= 0) { close(s->fd_in); s->fd_in = -1; }
  if (s->fd_out >= 0) { close(s->fd_out); s->fd_out = -1; }
  if (s->reader.joinable() &&
      std::this_thread::get_id() != s->reader.get_id())
    s->reader.join();
  if (s->pid > 0) {
    int status = 0;
    waitpid(s->pid, &status, 0);
    s->pid = -1;
  }
  if (!s->user_data_dir.empty()) {
    std::error_code ec;
    std::filesystem::remove_all(s->user_data_dir, ec);
    s->user_data_dir.clear();
  }
  if (s->rec_handle && ctx.rbi_recording_close) {
    ctx.rbi_recording_close(s->rec_handle);
    s->rec_handle = 0;
  }
  if (was_running && s->session_id > 0)
    ctx.terminate_session(s->session_id, "system", "system", "session.close");
}

// The reader thread owns all fd_out reads: it drives the CDP handshake, then
// streams screencast frames to the operator's WebSocket.
void run_reader(AppContext &ctx, crow::websocket::connection &conn,
                std::shared_ptr<RbiSession> s, std::string url) {
  // Auto-attach to the page target (flattened → events carry sessionId).
  cdp(s, "Target.setAutoAttach",
      "{\"autoAttach\":true,\"waitForDebuggerOnStart\":false,\"flatten\":true}",
      false);

  std::vector<std::string> msgs;
  while (s->running) {
    msgs.clear();
    if (!pump(s, msgs)) break;
    for (const auto &m : msgs) {
      const auto j = crow::json::load(m);
      if (!j) continue;
      const std::string method =
          j.has("method") ? std::string(j["method"].s()) : "";

      if (method == "Target.attachedToTarget") {
        if (!s->cdp_session.empty()) continue;
        if (!j.has("params")) continue;
        const auto &p = j["params"];
        std::string type;
        if (p.has("targetInfo") && p["targetInfo"].has("type"))
          type = std::string(p["targetInfo"]["type"].s());
        if (type != "page") continue;
        if (!p.has("sessionId")) continue;
        s->cdp_session = std::string(p["sessionId"].s());
        cdp(s, "Page.enable", "", true);
        send_device_metrics(s);
        cdp(s, "Page.navigate", std::string("{\"url\":\"") + json_escape(url) + "\"}",
            true);
        start_screencast(s);
        try {
          conn.send_text("{\"type\":\"status\",\"message\":\"connected\"}");
        } catch (...) {}
      } else if (method == "Page.screencastFrame") {
        if (!j.has("params")) continue;
        const auto &p = j["params"];
        if (!p.has("data")) continue;
        const std::string data = std::string(p["data"].s());
        long ack = 0;
        if (p.has("sessionId")) ack = p["sessionId"].i();
        std::string jpeg = base64_decode(data);
        if (s->rec_handle && ctx.rbi_recording_frame)
          ctx.rbi_recording_frame(s->rec_handle, jpeg);
        try {
          conn.send_binary(jpeg);
        } catch (...) {
          s->running = false;
          break;
        }
        cdp(s, "Page.screencastFrameAck",
            std::string("{\"sessionId\":") + std::to_string(ack) + "}", true);
      }
    }
  }

  // Reached only when the browser pipe closed while we were still streaming
  // (i.e. the client did not initiate the close). teardown() flips running via
  // its atomic exchange so the session is terminated exactly once.
  if (s->running.load()) {
    try { conn.send_text("{\"type\":\"status\",\"message\":\"browser closed\"}"); }
    catch (...) {}
    teardown(ctx, s);
    try { conn.close("rbi-closed"); } catch (...) {}
  }
}

int clamp_dim(int v, int lo, int hi) {
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

#endif  // EF_RBI

}  // namespace

void register_rbi_routes(CrowApp &app, AppContext &ctx) {
  // Capability probe so the frontend can show/hide the "isolated browser" action.
  CROW_ROUTE(app, "/api/rbi/capabilities")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        crow::json::wvalue payload;
        payload["status"] = "ok";
#ifdef EF_RBI
        payload["enabled"] = true;
        payload["wsPath"] = "/api/ws/rbi";
        payload["transport"] = "cdp-screencast";
#else
        payload["enabled"] = false;
        payload["message"] = "RBI is not supported on this platform build.";
#endif
        return crow::response(payload);
      });

#ifdef EF_RBI
  CROW_WEBSOCKET_ROUTE(app, "/api/ws/rbi")
      .onaccept([&ctx](const crow::request &request, void **userdata) {
        if (userdata) *userdata = nullptr;
        auto token = extract_auth_token_from_request(request);
        if (!token || token->empty()) return false;
        auto auth = ctx.find_auth_by_token(*token);
        if (!auth) return false;
        if (!ctx.has_permission(auth->userId, auth->role, "sessions.create"))
          return false;
        if (userdata) *userdata = new RbiAccept{auth->userId, auth->role};
        return true;
      })
      .onopen([&ctx](crow::websocket::connection &conn) {
        auto s = std::make_shared<RbiSession>();
        if (auto *acc = static_cast<RbiAccept *>(conn.userdata())) {
          s->auth_user_id = acc->user_id;
          s->role = acc->role;
          delete acc;
          conn.userdata(nullptr);
        }
        std::lock_guard<std::mutex> lock(g_conns_mutex);
        g_conns[&conn] = s;
      })
      .onclose([&ctx](crow::websocket::connection &conn, const std::string &) {
        std::shared_ptr<RbiSession> s;
        {
          std::lock_guard<std::mutex> lock(g_conns_mutex);
          auto it = g_conns.find(&conn);
          if (it != g_conns.end()) {
            s = it->second;
            g_conns.erase(it);
          }
        }
        if (s) {
          const int sid = s->session_id;
          const int rid = s->resource_id;
          const std::string user = s->user, role = s->role;
          teardown(ctx, s);
          if (sid > 0)
            audit(ctx, "rbi.close", user, role,
                  std::string("{\"sessionId\":") + std::to_string(sid) +
                      ",\"resourceId\":" + std::to_string(rid) + "}");
        }
      })
      .onmessage([&ctx](crow::websocket::connection &conn,
                        const std::string &data, bool is_binary) {
        if (is_binary) return;
        std::shared_ptr<RbiSession> s;
        {
          std::lock_guard<std::mutex> lock(g_conns_mutex);
          auto it = g_conns.find(&conn);
          if (it != g_conns.end()) s = it->second;
        }
        if (!s) return;
        const auto j = crow::json::load(data);
        if (!j) {
          conn.send_text("{\"type\":\"error\",\"message\":\"Invalid JSON\"}");
          return;
        }
        const std::string type =
            j.has("type") ? std::string(j["type"].s()) : "";

        if (type == "start") {
          if (s->running) return;
          if (!j.has("sessionId")) {
            conn.send_text("{\"type\":\"error\",\"message\":\"Missing sessionId\"}");
            return;
          }
          const int session_id = j["sessionId"].i();
          if (j.has("width")) s->view_w = clamp_dim(j["width"].i(), 320, 1920);
          if (j.has("height")) s->view_h = clamp_dim(j["height"].i(), 240, 1200);

          // Resolve session → resource → URL, and re-check access.
          int resource_id = 0;
          std::string sess_user, host, protocol;
          int port = 0;
          {
            std::lock_guard<std::mutex> lock(ctx.session_mutex);
            auto it = ctx.sessions.find(session_id);
            if (it == ctx.sessions.end() || it->second.status != "active") {
              conn.send_text("{\"type\":\"error\",\"message\":\"Session not found\"}");
              return;
            }
            resource_id = it->second.resourceId;
            sess_user = it->second.user;
            host = it->second.target;
            protocol = to_lower(it->second.protocol);
            port = it->second.port;
          }
          if (protocol != "http" && protocol != "https") {
            conn.send_text(
                "{\"type\":\"error\",\"message\":\"RBI only applies to http/https resources\"}");
            return;
          }
          // Defense in depth: the operator must be assigned to this resource
          // (mirrors the check in POST /api/sessions), not just hold
          // sessions.create globally.
          if (!has_resource_access(ctx, s->auth_user_id, s->role, resource_id)) {
            conn.send_text("{\"type\":\"error\",\"message\":\"Forbidden\"}");
            return;
          }

          // Build the target URL.
          std::string url = protocol + "://" + host;
          const bool default_port =
              (protocol == "http" && port == 80) ||
              (protocol == "https" && port == 443);
          if (port > 0 && !default_port) url += ":" + std::to_string(port);
          url += "/";

          s->session_id = session_id;
          s->resource_id = resource_id;
          s->user = sess_user;

          std::string error;
          if (!launch_chromium(s, error)) {
            conn.send_text(std::string("{\"type\":\"error\",\"message\":\"") +
                           json_escape(error) + "\"}");
            return;
          }

          // Premium: start graphical recording if the pro module is present and
          // the license entitles it (no-op / returns 0 otherwise).
          if (ctx.rbi_recording_open) {
            s->rec_handle = ctx.rbi_recording_open(
                session_id, s->view_w, s->view_h, "RBI " + url);
          }

          audit(ctx, "rbi.open", sess_user, s->role,
                std::string("{\"sessionId\":") + std::to_string(session_id) +
                    ",\"resourceId\":" + std::to_string(resource_id) +
                    ",\"url\":\"" + json_escape(url) +
                    "\",\"recording\":" + (s->rec_handle ? "true" : "false") + "}");

          s->reader = std::thread(run_reader, std::ref(ctx), std::ref(conn), s, url);
          return;
        }

        if (!s->running || s->cdp_session.empty()) return;

        if (type == "mouse") {
          // Client sends normalized coords in [0,1]; scale to the CDP viewport.
          double nx = j.has("x") ? j["x"].d() : 0.0;
          double ny = j.has("y") ? j["y"].d() : 0.0;
          const int x = static_cast<int>(nx * s->view_w);
          const int y = static_cast<int>(ny * s->view_h);
          const std::string ev = j.has("event") ? std::string(j["event"].s()) : "";
          std::string cdp_type;
          if (ev == "move") cdp_type = "mouseMoved";
          else if (ev == "down") cdp_type = "mousePressed";
          else if (ev == "up") cdp_type = "mouseReleased";
          else if (ev == "wheel") cdp_type = "mouseWheel";
          else return;
          std::string button = j.has("button") ? std::string(j["button"].s()) : "none";
          if (button != "left" && button != "right" && button != "middle" &&
              button != "none")
            button = "none";
          const int click_count = j.has("clickCount") ? j["clickCount"].i() : 0;
          std::ostringstream p;
          p << "{\"type\":\"" << cdp_type << "\",\"x\":" << x << ",\"y\":" << y
            << ",\"button\":\"" << button << "\",\"clickCount\":" << click_count;
          if (cdp_type == "mouseWheel") {
            const double dx = j.has("deltaX") ? j["deltaX"].d() : 0.0;
            const double dy = j.has("deltaY") ? j["deltaY"].d() : 0.0;
            p << ",\"deltaX\":" << dx << ",\"deltaY\":" << dy;
          }
          p << "}";
          cdp(s, "Input.dispatchMouseEvent", p.str(), true);
          return;
        }

        if (type == "key") {
          const std::string ev = j.has("event") ? std::string(j["event"].s()) : "";
          std::string cdp_type;
          if (ev == "down") cdp_type = "keyDown";
          else if (ev == "up") cdp_type = "keyUp";
          else if (ev == "char") cdp_type = "char";
          else return;
          const std::string key = j.has("key") ? std::string(j["key"].s()) : "";
          const std::string code = j.has("code") ? std::string(j["code"].s()) : "";
          const std::string text = j.has("text") ? std::string(j["text"].s()) : "";
          const int vk = j.has("keyCode") ? j["keyCode"].i() : 0;
          const int modifiers = j.has("modifiers") ? j["modifiers"].i() : 0;
          std::ostringstream p;
          p << "{\"type\":\"" << cdp_type << "\",\"modifiers\":" << modifiers;
          if (!key.empty()) p << ",\"key\":\"" << json_escape(key) << "\"";
          if (!code.empty()) p << ",\"code\":\"" << json_escape(code) << "\"";
          if (!text.empty()) p << ",\"text\":\"" << json_escape(text) << "\"";
          if (vk > 0) p << ",\"windowsVirtualKeyCode\":" << vk;
          p << "}";
          cdp(s, "Input.dispatchKeyEvent", p.str(), true);
          return;
        }

        if (type == "resize") {
          if (j.has("width")) s->view_w = clamp_dim(j["width"].i(), 320, 1920);
          if (j.has("height")) s->view_h = clamp_dim(j["height"].i(), 240, 1200);
          send_device_metrics(s);
          start_screencast(s);  // re-issue with the new max dimensions
          return;
        }
      });
#else
  CROW_ROUTE(app, "/api/ws/rbi")([] {
    crow::json::wvalue payload;
    payload["status"] = "error";
    payload["message"] = "RBI is unavailable on this platform build.";
    return crow::response{501, payload};
  });
#endif
}
