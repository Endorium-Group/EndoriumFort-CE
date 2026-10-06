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
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
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

// Tunables (env, read once). Defaults chosen to keep a single busy tab well under
// ~1 core and to bound bandwidth, while staying visually smooth for interaction.
int env_int(const char *name, int def, int lo, int hi) {
  const char *v = std::getenv(name);
  if (!v || !*v) return def;
  char *end = nullptr;
  long n = std::strtol(v, &end, 10);
  if (end == v) return def;
  if (n < lo) n = lo;
  if (n > hi) n = hi;
  return static_cast<int>(n);
}

std::string env_str(const char *name, const std::string &def) {
  const char *v = std::getenv(name);
  return (v && *v) ? std::string(v) : def;
}

struct RbiConfig {
  int max_fps;        // 0 = uncapped; else min interval between frame requests
  int jpeg_quality;   // 1..100
  int max_width;      // hard cap on the streamed viewport width
  int max_height;     // hard cap on the streamed viewport height
  int max_sessions;   // 0 = unlimited concurrent browsers
  int max_upload_mb;  // 0 = unlimited; hard cap on a single uploaded file (MiB)
  std::string engine; // "cdp" (Chromium screencast, default) | "tiles" (helper)
  std::string helper; // helper binary path for the "tiles" engine
};

const RbiConfig &rbi_config() {
  static const RbiConfig cfg = {
      env_int("ENDORIUMFORT_RBI_MAX_FPS", 20, 0, 60),
      env_int("ENDORIUMFORT_RBI_JPEG_QUALITY", 55, 1, 100),
      env_int("ENDORIUMFORT_RBI_MAX_WIDTH", 1600, 320, 1920),
      env_int("ENDORIUMFORT_RBI_MAX_HEIGHT", 900, 240, 1200),
      env_int("ENDORIUMFORT_RBI_MAX_SESSIONS", 12, 0, 1000),
      env_int("ENDORIUMFORT_RBI_MAX_UPLOAD_MB", 0, 0, 1048576),
      env_str("ENDORIUMFORT_RBI_ENGINE", "cdp"),
      env_str("ENDORIUMFORT_RBI_HELPER", "endoriumfort-rbi-cef"),
  };
  return cfg;
}

// Reduce an untrusted client filename to a safe basename (no path separators, no
// NUL, non-empty, bounded) for use under the session's own temp transfer dir.
std::string sanitize_upload_name(const std::string &in) {
  std::string base = in;
  const auto slash = base.find_last_of("/\\");
  if (slash != std::string::npos) base = base.substr(slash + 1);
  std::string out;
  for (char c : base) {
    if (c == '\0' || c == '/' || c == '\\') continue;
    out.push_back(c);
  }
  if (out.empty() || out == "." || out == "..") out = "upload.bin";
  if (out.size() > 200) out = out.substr(0, 200);
  return out;
}

// Number of live server-side browsers (for the concurrency cap + resource guard).
std::atomic<int> g_active_sessions{0};

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
  bool counted = false;    // whether this session is in g_active_sessions
  std::chrono::steady_clock::time_point last_frame{};  // for the FPS cap
  std::string user;
  std::string role;
  std::string user_data_dir;

  // ── File transfer state ──
  // Upload in progress (client → isolated browser). Bytes stream in as binary WS
  // frames into a temp file under transfer_dir; on completion we hand the path to
  // the helper as a drag-drop (U) or a file-dialog completion (F).
  std::string transfer_dir;
  std::ofstream upload_file;
  bool upload_active = false;
  uint32_t upload_id = 0;
  std::string upload_name;
  std::string upload_path;
  int64_t upload_size = 0;
  int64_t upload_written = 0;
  bool upload_drop = false;  // true=drag-drop at (x,y); false=file-dialog completion
  double upload_x = 0.0, upload_y = 0.0;
  uint32_t upload_dialog_seq = 0;
  // Downloads the EE policy blocked (reader thread only — no lock needed).
  std::unordered_set<uint32_t> blocked_downloads;
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
  p << "{\"format\":\"jpeg\",\"quality\":" << rbi_config().jpeg_quality
    << ",\"maxWidth\":" << s->view_w << ",\"maxHeight\":" << s->view_h
    << ",\"everyNthFrame\":1}";
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
        "--disable-software-rasterizer",
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
        "--hide-scrollbars",
        "--mute-audio",
        "--no-sandbox",  // container-friendly; RBI targets are internal resources
        // ── Resource footprint: fewer processes + capped heaps + no telemetry ──
        "--no-zygote",                     // drop the zygote helper process
        "--renderer-process-limit=1",      // one renderer for this single tab
        "--disable-features=IsolateOrigins,site-per-process,Translate,"
        "BackForwardCache,MediaRouter,OptimizationHints,InterestFeedContentSuggestions",
        "--js-flags=--max-old-space-size=256",  // cap V8 heap (~256 MB)
        "--disable-breakpad",
        "--disable-crash-reporter",
        "--disable-component-update",
        "--disable-background-timer-throttling",  // keep the visible tab responsive
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",
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
  if (s->upload_file.is_open()) s->upload_file.close();
  s->upload_active = false;
  if (!s->user_data_dir.empty()) {
    std::error_code ec;
    std::filesystem::remove_all(s->user_data_dir, ec);  // also clears transfer_dir
    s->user_data_dir.clear();
  }
  if (s->rec_handle && ctx.rbi_recording_close) {
    ctx.rbi_recording_close(s->rec_handle);
    s->rec_handle = 0;
  }
  if (s->counted) {
    g_active_sessions.fetch_sub(1);
    s->counted = false;
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
        // FPS cap: the screencast is ack-gated (Chromium won't render the next
        // frame until we ack), so throttling the ack throttles CPU + bandwidth.
        // The frame just displayed went out immediately (no added latency); we
        // only defer *requesting* the next one when frames arrive faster than the
        // cap — which is exactly when a page is repainting hard.
        const int fps = rbi_config().max_fps;
        if (fps > 0) {
          const auto min_interval = std::chrono::milliseconds(1000 / fps);
          const auto now = std::chrono::steady_clock::now();
          if (s->last_frame.time_since_epoch().count() != 0) {
            const auto elapsed = now - s->last_frame;
            if (elapsed < min_interval) std::this_thread::sleep_for(min_interval - elapsed);
          }
          s->last_frame = std::chrono::steady_clock::now();
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

// ─── "tiles" engine: a helper subprocess (CEF-OSR, or the synthetic stub) ─────
// Protocol, helper → us (its stdout), framed big-endian:
//   [u8 type][u32 len][payload]   type 1=tile, 2=surface-info, 3=log
//   tile payload:   [u16 x][u16 y][u16 w][u16 h][u8 format][image bytes]
//   surface payload:[u16 width][u16 height]
// Us → helper (its stdin): newline-delimited JSON input/resize events.
// We forward tile/surface frames to the browser as one binary WS message each,
// prefixed with the 1-byte type (WS framing carries the length).

// Launch the helper with argv [helper, url, width, height, user_data_dir] and
// wire its stdin/stdout to the session pipes. Mirrors launch_chromium() but on
// fd 0/1 instead of the CDP pipe fds.
bool launch_helper(const std::shared_ptr<RbiSession> &s, const std::string &url,
                   std::string &error) {
  int in_pipe[2], out_pipe[2];
  if (pipe(in_pipe) != 0) { error = "pipe() failed"; return false; }
  if (pipe(out_pipe) != 0) {
    close(in_pipe[0]); close(in_pipe[1]);
    error = "pipe() failed";
    return false;
  }
  char tmpl[] = "/tmp/ef-rbi-XXXXXX";
  char *dir = mkdtemp(tmpl);
  if (!dir) {
    close(in_pipe[0]); close(in_pipe[1]); close(out_pipe[0]); close(out_pipe[1]);
    error = "mkdtemp() failed";
    return false;
  }
  s->user_data_dir = dir;
  const std::string helper = rbi_config().helper;
  const std::string w = std::to_string(s->view_w), h = std::to_string(s->view_h);

  pid_t pid = fork();
  if (pid < 0) {
    close(in_pipe[0]); close(in_pipe[1]); close(out_pipe[0]); close(out_pipe[1]);
    std::filesystem::remove_all(s->user_data_dir);
    s->user_data_dir.clear();
    error = "fork() failed";
    return false;
  }
  if (pid == 0) {
    dup2(in_pipe[0], STDIN_FILENO);
    dup2(out_pipe[1], STDOUT_FILENO);
    for (int fd : {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1]})
      if (fd > STDERR_FILENO) close(fd);
    std::vector<std::string> args = {helper, url, w, h, s->user_data_dir};
    std::vector<char *> argv;
    for (auto &a : args) argv.push_back(const_cast<char *>(a.c_str()));
    argv.push_back(nullptr);
    execvp(helper.c_str(), argv.data());
    _exit(127);
  }
  close(in_pipe[0]);
  close(out_pipe[1]);
  s->pid = pid;
  s->fd_in = in_pipe[1];
  s->fd_out = out_pipe[0];
  s->running = true;
  return true;
}

void send_helper_input(const std::shared_ptr<RbiSession> &s, const std::string &json_line) {
  if (!s || s->fd_in < 0) return;
  std::lock_guard<std::mutex> lock(s->write_mutex);
  std::string line = json_line;
  line.push_back('\n');
  const char *p = line.data();
  size_t remaining = line.size();
  while (remaining > 0) {
    ssize_t w = write(s->fd_in, p, remaining);
    if (w <= 0) break;
    p += w;
    remaining -= static_cast<size_t>(w);
  }
}

// Reader thread for the "tiles" engine: parse framed messages and relay tile /
// surface frames to the WS as [u8 type][payload] binary messages.
void run_tile_reader(AppContext &ctx, crow::websocket::connection &conn,
                     std::shared_ptr<RbiSession> s) {
  try { conn.send_text("{\"type\":\"status\",\"message\":\"connected\"}"); } catch (...) {}
  char buf[65536];
  while (s->running) {
    ssize_t n = read(s->fd_out, buf, sizeof(buf));
    if (n <= 0) break;
    s->rbuf.append(buf, static_cast<size_t>(n));
    // Consume as many complete frames as are buffered.
    for (;;) {
      if (s->rbuf.size() < 5) break;
      const unsigned char *p = reinterpret_cast<const unsigned char *>(s->rbuf.data());
      const uint8_t type = p[0];
      const uint32_t len = (uint32_t(p[1]) << 24) | (uint32_t(p[2]) << 16) |
                           (uint32_t(p[3]) << 8) | uint32_t(p[4]);
      if (s->rbuf.size() < 5 + len) break;
      if (type == 3) {
        // log line — surface as a status message (best effort)
        try {
          conn.send_text(std::string("{\"type\":\"status\",\"message\":\"") +
                         json_escape(s->rbuf.substr(5, len)) + "\"}");
        } catch (...) {}
      } else {
        // Download frames (cible → hôte): 5=begin [u32 id][u64 size][u16 nameLen]
        // [name], 6=chunk [u32 id][bytes], 7=end [u32 id]. The EE transfer policy
        // (if present+licensed) gates the stream on the begin header; a blocked
        // download's 5/6/7 frames are suppressed rather than relayed.
        bool suppress = false;
        if (type == 5 || type == 6 || type == 7) {
          const unsigned char *dp =
              reinterpret_cast<const unsigned char *>(s->rbuf.data()) + 5;
          if (len >= 4) {
            const uint32_t did = (uint32_t(dp[0]) << 24) | (uint32_t(dp[1]) << 16) |
                                 (uint32_t(dp[2]) << 8) | uint32_t(dp[3]);
            if (type == 5) {
              std::string dname;
              int64_t dsize = 0;
              if (len >= 14) {
                for (int i = 0; i < 8; ++i)
                  dsize = (dsize << 8) | int64_t(dp[4 + i]);
                const uint16_t nl = (uint16_t(dp[12]) << 8) | uint16_t(dp[13]);
                if (len >= uint32_t(14) + nl)
                  dname.assign(reinterpret_cast<const char *>(dp) + 14, nl);
              }
              if (ctx.rbi_transfer_check &&
                  !ctx.rbi_transfer_check(s->session_id, "download", dname, dsize)) {
                s->blocked_downloads.insert(did);
                suppress = true;
                try {
                  conn.send_text(
                      "{\"type\":\"status\",\"message\":\"download blocked by policy\"}");
                } catch (...) {}
              }
            } else if (s->blocked_downloads.count(did)) {
              suppress = true;
              if (type == 7) s->blocked_downloads.erase(did);
            }
          }
        }
        if (!suppress) {
          std::string msg;
          msg.push_back(static_cast<char>(type));
          msg.append(s->rbuf, 5, len);
          // Record tile (1) and surface-info (2) frames so the EFR2 player can
          // reconstruct the canvas; the blob keeps its [type][payload] shape.
          if (s->rec_handle && ctx.rbi_recording_frame && (type == 1 || type == 2))
            ctx.rbi_recording_frame(s->rec_handle, msg);
          try { conn.send_binary(msg); }
          catch (...) { s->running = false; break; }
        }
      }
      s->rbuf.erase(0, 5 + len);
    }
  }
  if (s->running.load()) {
    try { conn.send_text("{\"type\":\"status\",\"message\":\"browser closed\"}"); } catch (...) {}
    teardown(ctx, s);
    try { conn.close("rbi-closed"); } catch (...) {}
  }
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
        payload["engine"] = rbi_config().engine;
        // File transfer (upload/download) is wired on the tiles engine; clipboard
        // paste works on both. The frontend enables its drag-drop / paste handlers
        // from these flags.
        payload["fileTransfer"] = (rbi_config().engine == "tiles");
        payload["clipboardPaste"] = true;
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
        std::shared_ptr<RbiSession> s;
        {
          std::lock_guard<std::mutex> lock(g_conns_mutex);
          auto it = g_conns.find(&conn);
          if (it != g_conns.end()) s = it->second;
        }
        if (!s) return;

        // Binary frames from the client are file-upload chunks (hôte → cible):
        //   [u8 0x10][u32 id][bytes]  — appended to the in-progress upload temp file.
        if (is_binary) {
          if (!s->running || !s->upload_active || !s->upload_file.is_open()) return;
          if (data.size() < 5) return;
          const unsigned char *p =
              reinterpret_cast<const unsigned char *>(data.data());
          if (p[0] != 0x10) return;
          const uint32_t id = (uint32_t(p[1]) << 24) | (uint32_t(p[2]) << 16) |
                              (uint32_t(p[3]) << 8) | uint32_t(p[4]);
          if (id != s->upload_id) return;
          const size_t n = data.size() - 5;
          const int64_t cap =
              int64_t(rbi_config().max_upload_mb) * 1024 * 1024;
          if (cap > 0 && s->upload_written + int64_t(n) > cap) {
            s->upload_file.close();
            s->upload_active = false;
            conn.send_text(
                "{\"type\":\"error\",\"message\":\"Upload exceeds size limit\"}");
            return;
          }
          s->upload_file.write(data.data() + 5, static_cast<std::streamsize>(n));
          s->upload_written += int64_t(n);
          return;
        }
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
          // Clamp the streamed viewport to the configured caps — a smaller frame
          // is cheaper to encode and transfer (lower CPU + latency).
          const auto &cfg = rbi_config();
          if (j.has("width")) s->view_w = clamp_dim(j["width"].i(), 320, cfg.max_width);
          if (j.has("height")) s->view_h = clamp_dim(j["height"].i(), 240, cfg.max_height);

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

          // Concurrency cap: bound the number of simultaneous server-side
          // browsers so a burst of RBI sessions can't exhaust host RAM/CPU.
          if (cfg.max_sessions > 0) {
            int prev = g_active_sessions.fetch_add(1);
            if (prev >= cfg.max_sessions) {
              g_active_sessions.fetch_sub(1);
              conn.send_text(
                  "{\"type\":\"error\",\"message\":\"Server at RBI capacity, retry shortly\"}");
              return;
            }
            s->counted = true;
          }

          const bool tiles = (cfg.engine == "tiles");
          std::string error;
          const bool launched =
              tiles ? launch_helper(s, url, error) : launch_chromium(s, error);
          if (!launched) {
            if (s->counted) { g_active_sessions.fetch_sub(1); s->counted = false; }
            conn.send_text(std::string("{\"type\":\"error\",\"message\":\"") +
                           json_escape(error) + "\"}");
            return;
          }

          // Premium: start graphical recording if the pro module is present and
          // the license entitles it (no-op / returns 0 otherwise).
          if (ctx.rbi_recording_open) {
            s->rec_handle = ctx.rbi_recording_open(
                session_id, s->view_w, s->view_h, "RBI " + url,
                tiles ? "tiles" : "mjpeg");
          }

          audit(ctx, "rbi.open", sess_user, s->role,
                std::string("{\"sessionId\":") + std::to_string(session_id) +
                    ",\"resourceId\":" + std::to_string(resource_id) +
                    ",\"url\":\"" + json_escape(url) + "\",\"engine\":\"" +
                    (tiles ? "tiles" : "cdp") + "\",\"recording\":" +
                    (s->rec_handle ? "true" : "false") + "}");

          if (tiles)
            s->reader = std::thread(run_tile_reader, std::ref(ctx), std::ref(conn), s);
          else
            s->reader = std::thread(run_reader, std::ref(ctx), std::ref(conn), s, url);
          return;
        }

        if (!s->running) return;
        const auto &cfg = rbi_config();
        const bool tiles = (cfg.engine == "tiles");

        // ── Clipboard paste (hôte → page isolée) — both engines ──
        if (type == "paste") {
          const std::string text = j.has("text") ? std::string(j["text"].s()) : "";
          if (text.empty()) return;
          if (ctx.rbi_transfer_check &&
              !ctx.rbi_transfer_check(s->session_id, "paste", "",
                                      static_cast<int64_t>(text.size()))) {
            conn.send_text("{\"type\":\"error\",\"message\":\"Paste blocked by policy\"}");
            return;
          }
          if (tiles) {
            send_helper_input(s, "P " + base64_encode(text));
          } else if (!s->cdp_session.empty()) {
            cdp(s, "Input.insertText",
                std::string("{\"text\":\"") + json_escape(text) + "\"}", true);
          }
          return;
        }

        // ── Typed text (robust keyboard: letters/AltGr/accents/IME come here as
        //    composed text, not keystrokes). Not DLP-gated — that's `paste`. ──
        if (type == "text") {
          const std::string text = j.has("text") ? std::string(j["text"].s()) : "";
          if (text.empty()) return;
          if (tiles) {
            send_helper_input(s, "T " + base64_encode(text));
          } else if (!s->cdp_session.empty()) {
            cdp(s, "Input.insertText",
                std::string("{\"text\":\"") + json_escape(text) + "\"}", true);
          }
          return;
        }

        // ── File upload (hôte → cible), tiles engine only ──
        if (type == "upload-begin") {
          if (!tiles) {
            conn.send_text(
                "{\"type\":\"error\",\"message\":\"File upload requires the tiles engine\"}");
            return;
          }
          if (s->upload_active && s->upload_file.is_open()) s->upload_file.close();
          const uint32_t id =
              j.has("id") ? static_cast<uint32_t>(j["id"].i()) : 0;
          const std::string name = sanitize_upload_name(
              j.has("name") ? std::string(j["name"].s()) : "upload.bin");
          const int64_t size = j.has("size") ? static_cast<int64_t>(j["size"].i()) : 0;
          if (ctx.rbi_transfer_check &&
              !ctx.rbi_transfer_check(s->session_id, "upload", name, size)) {
            conn.send_text("{\"type\":\"error\",\"message\":\"Upload blocked by policy\"}");
            return;
          }
          s->transfer_dir = s->user_data_dir + "/transfer";
          std::error_code ec;
          std::filesystem::create_directories(s->transfer_dir, ec);
          s->upload_path =
              s->transfer_dir + "/" + std::to_string(id) + "_" + name;
          s->upload_file.open(s->upload_path, std::ios::binary | std::ios::trunc);
          if (!s->upload_file) {
            conn.send_text("{\"type\":\"error\",\"message\":\"Cannot stage upload\"}");
            return;
          }
          s->upload_active = true;
          s->upload_id = id;
          s->upload_name = name;
          s->upload_size = size;
          s->upload_written = 0;
          s->upload_drop = j.has("drop") && j["drop"].b();
          s->upload_x = j.has("x") ? j["x"].d() : 0.0;
          s->upload_y = j.has("y") ? j["y"].d() : 0.0;
          s->upload_dialog_seq =
              j.has("dialogSeq") ? static_cast<uint32_t>(j["dialogSeq"].i()) : 0;
          return;
        }
        if (type == "upload-end") {
          if (!s->upload_active) return;
          const uint32_t id =
              j.has("id") ? static_cast<uint32_t>(j["id"].i()) : 0;
          if (id != s->upload_id) return;
          if (s->upload_file.is_open()) s->upload_file.close();
          s->upload_active = false;
          if (s->upload_drop) {
            const int x = static_cast<int>(s->upload_x * s->view_w);
            const int y = static_cast<int>(s->upload_y * s->view_h);
            std::ostringstream o;
            o << "U " << s->upload_id << ' ' << x << ' ' << y << ' '
              << base64_encode(s->upload_path) << ' '
              << base64_encode(s->upload_name);
            send_helper_input(s, o.str());
          } else {
            std::ostringstream o;
            o << "F " << s->upload_dialog_seq << ' '
              << base64_encode(s->upload_path);
            send_helper_input(s, o.str());
          }
          conn.send_text("{\"type\":\"status\",\"message\":\"upload complete\"}");
          return;
        }
        if (type == "upload-cancel") {
          if (s->upload_file.is_open()) s->upload_file.close();
          const bool was_dialog = s->upload_active && !s->upload_drop;
          const uint32_t seq = s->upload_dialog_seq;
          s->upload_active = false;
          if (was_dialog && seq)
            send_helper_input(s, "F " + std::to_string(seq) + " -");
          return;
        }
        if (type == "file-pick-cancel") {
          const uint32_t seq =
              j.has("dialogSeq") ? static_cast<uint32_t>(j["dialogSeq"].i()) : 0;
          send_helper_input(s, "F " + std::to_string(seq) + " -");
          return;
        }

        // "tiles" engine: forward input to the helper as simple space-delimited
        // lines (trivially parseable in the helper, no JSON dep). We pass pixel
        // coords scaled from the client's normalized ones (the helper owns the
        // surface). Formats:
        //   M <event> <x> <y> <button> <clickCount> <dx> <dy>   event=move|down|up|wheel
        //   K <event> <keyCode> <modifiers> <textB64>           event=down|up|char
        //   R <w> <h>
        if (cfg.engine == "tiles") {
          if (type == "mouse") {
            const double nx = j.has("x") ? j["x"].d() : 0.0;
            const double ny = j.has("y") ? j["y"].d() : 0.0;
            const int x = static_cast<int>(nx * s->view_w);
            const int y = static_cast<int>(ny * s->view_h);
            std::string ev = j.has("event") ? std::string(j["event"].s()) : "";
            std::string button = j.has("button") ? std::string(j["button"].s()) : "none";
            const int cc = j.has("clickCount") ? j["clickCount"].i() : 0;
            const int dx = j.has("deltaX") ? static_cast<int>(j["deltaX"].d()) : 0;
            const int dy = j.has("deltaY") ? static_cast<int>(j["deltaY"].d()) : 0;
            std::ostringstream o;
            o << "M " << ev << ' ' << x << ' ' << y << ' ' << button << ' ' << cc
              << ' ' << dx << ' ' << dy;
            send_helper_input(s, o.str());
          } else if (type == "key") {
            std::string ev = j.has("event") ? std::string(j["event"].s()) : "";
            const std::string text = j.has("text") ? std::string(j["text"].s()) : "";
            const int vk = j.has("keyCode") ? j["keyCode"].i() : 0;
            const int mods = j.has("modifiers") ? j["modifiers"].i() : 0;
            std::ostringstream o;
            o << "K " << ev << ' ' << vk << ' ' << mods << ' '
              << (text.empty() ? std::string("-") : base64_encode(text));
            send_helper_input(s, o.str());
          } else if (type == "resize") {
            if (j.has("width")) s->view_w = clamp_dim(j["width"].i(), 320, cfg.max_width);
            if (j.has("height")) s->view_h = clamp_dim(j["height"].i(), 240, cfg.max_height);
            std::ostringstream o;
            o << "R " << s->view_w << ' ' << s->view_h;
            send_helper_input(s, o.str());
          }
          return;
        }

        if (s->cdp_session.empty()) return;

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
