// ─── EndoriumFort — RBI "tiles" engine: real CEF offscreen-rendering helper ───
// Renders a URL with Chromium Embedded Framework in windowless (offscreen) mode,
// encodes only the dirty rectangles CEF reports as JPEG tiles, and speaks the
// EndoriumFort tile protocol on stdout. Input events arrive as simple lines on
// stdin. This is a drop-in replacement for the synthetic stub helper — same
// protocol — so the backend relay and the frontend canvas need no changes.
//
// Build: linked against CEF + libjpeg. See CMakeLists.txt in this directory and
// the Dockerfile "rbi-cef" build stage. It CANNOT run without the CEF runtime
// files (libcef.so, *.pak, icudtl.dat, locales/…) beside the binary.
//
// stdout protocol (framed big-endian):  [u8 type][u32 len][payload]
//   type 1 tile:        [u16 x][u16 y][u16 w][u16 h][u8 format=0(jpeg)][jpeg bytes]
//   type 2 surface:     [u16 width][u16 height]
//   type 3 log:         utf8
//   type 4 file-dialog: [u32 seq][u8 mode][u8 multiple][u16 acceptLen][accept]
//   type 5 dl-begin:    [u32 id][u64 size][u16 nameLen][name]
//   type 6 dl-chunk:    [u32 id][bytes]
//   type 7 dl-end:      [u32 id]
// stdin (newline-delimited):
//   M <event> <x> <y> <button> <clickCount> <dx> <dy>   event=move|down|up|wheel
//   K <event> <keyCode> <modifiers> <textB64|->         event=down|up|char
//   R <w> <h>
//   P <textB64>                                         paste (inject char events)
//   U <id> <x> <y> <pathB64> <nameB64>                  drop a local file at (x,y)
//   F <seq> <pathsB64CSV|->                             complete/cancel a file dialog
//
// argv: [prog, url, width, height, user_data_dir]

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>
#ifdef EF_RBI_JPEG
#include <jpeglib.h>
#endif

#include "include/cef_app.h"
#include "include/cef_browser.h"
#include "include/cef_client.h"
#include "include/cef_command_line.h"
#include "include/cef_dialog_handler.h"
#include "include/cef_download_handler.h"
#include "include/cef_drag_data.h"
#include "include/cef_render_handler.h"
#include "include/cef_task.h"
#include "include/wrapper/cef_helpers.h"

namespace {

std::atomic<int> g_width{1280};
std::atomic<int> g_height{800};
std::atomic<int> g_fps{20};
CefRefPtr<CefBrowser> g_browser;  // UI-thread owned
std::mutex g_out_mutex;
int g_last_surface_w = 0, g_last_surface_h = 0;

// Where downloads (cible → hôte) are staged before being streamed back over
// stdout. Set from the cache dir (argv[4]) in main(); cleaned with the session.
std::string g_download_dir;

// Pending file-dialog callbacks (page opened a file picker): the backend relays a
// request to the client, which answers with a `F <seq> <paths>` line.
std::mutex g_dialog_mutex;
std::unordered_map<uint32_t, CefRefPtr<CefFileDialogCallback>> g_dialogs;
std::atomic<uint32_t> g_dialog_seq{1};

// ── stdout framing ────────────────────────────────────────────────────────────
bool write_all(const char* p, size_t n) {
  while (n > 0) {
    ssize_t w = write(STDOUT_FILENO, p, n);
    if (w <= 0) return false;
    p += w;
    n -= static_cast<size_t>(w);
  }
  return true;
}
void emit_frame(uint8_t type, const std::string& payload) {
  std::lock_guard<std::mutex> lock(g_out_mutex);
  char hdr[5];
  const uint32_t len = static_cast<uint32_t>(payload.size());
  hdr[0] = static_cast<char>(type);
  hdr[1] = static_cast<char>((len >> 24) & 0xff);
  hdr[2] = static_cast<char>((len >> 16) & 0xff);
  hdr[3] = static_cast<char>((len >> 8) & 0xff);
  hdr[4] = static_cast<char>(len & 0xff);
  if (write_all(hdr, 5)) write_all(payload.data(), payload.size());
}
void put_u16(std::string& s, uint16_t v) {
  s.push_back(static_cast<char>((v >> 8) & 0xff));
  s.push_back(static_cast<char>(v & 0xff));
}
void put_u32(std::string& s, uint32_t v) {
  s.push_back(static_cast<char>((v >> 24) & 0xff));
  s.push_back(static_cast<char>((v >> 16) & 0xff));
  s.push_back(static_cast<char>((v >> 8) & 0xff));
  s.push_back(static_cast<char>(v & 0xff));
}
void put_u64(std::string& s, uint64_t v) {
  for (int i = 7; i >= 0; --i) s.push_back(static_cast<char>((v >> (i * 8)) & 0xff));
}
void emit_surface(int w, int h) {
  std::string p;
  put_u16(p, static_cast<uint16_t>(w));
  put_u16(p, static_cast<uint16_t>(h));
  emit_frame(2, p);
}
void emit_log(const std::string& m) { emit_frame(3, m); }

// Stream a completed download back over stdout: frame 5 (begin), 6 (chunks),
// 7 (end), then delete the staged file. Runs on a detached thread so a large
// file never blocks the CEF UI thread.
void stream_download(uint32_t id, std::string path, std::string name) {
  struct stat st {};
  uint64_t size = (stat(path.c_str(), &st) == 0) ? static_cast<uint64_t>(st.st_size) : 0;
  {
    std::string p;
    put_u32(p, id);
    put_u64(p, size);
    put_u16(p, static_cast<uint16_t>(name.size() > 0xffff ? 0xffff : name.size()));
    p.append(name, 0, name.size() > 0xffff ? 0xffff : name.size());
    emit_frame(5, p);
  }
  std::ifstream in(path, std::ios::binary);
  if (in) {
    std::vector<char> buf(256 * 1024);
    while (in) {
      in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
      std::streamsize got = in.gcount();
      if (got <= 0) break;
      std::string p;
      put_u32(p, id);
      p.append(buf.data(), static_cast<size_t>(got));
      emit_frame(6, p);
    }
  }
  {
    std::string p;
    put_u32(p, id);
    emit_frame(7, p);
  }
  in.close();
  ::remove(path.c_str());
}

// Minimal UTF-8 → UTF-16 for paste: decode code points, emit one char event per
// UTF-16 code unit (surrogate pair for astral code points).
std::vector<char16_t> utf8_to_utf16(const std::string& in) {
  std::vector<char16_t> out;
  size_t i = 0, n = in.size();
  while (i < n) {
    unsigned char c = static_cast<unsigned char>(in[i]);
    uint32_t cp = 0;
    int extra = 0;
    if (c < 0x80) { cp = c; }
    else if ((c >> 5) == 0x6) { cp = c & 0x1f; extra = 1; }
    else if ((c >> 4) == 0xe) { cp = c & 0x0f; extra = 2; }
    else if ((c >> 3) == 0x1e) { cp = c & 0x07; extra = 3; }
    else { ++i; continue; }  // invalid lead byte
    if (i + extra >= n) break;
    for (int k = 0; k < extra; ++k) {
      unsigned char cc = static_cast<unsigned char>(in[i + 1 + k]);
      if ((cc & 0xc0) != 0x80) { cp = 0; break; }
      cp = (cp << 6) | (cc & 0x3f);
    }
    i += 1 + extra;
    if (cp == 0) continue;
    if (cp <= 0xffff) {
      out.push_back(static_cast<char16_t>(cp));
    } else {
      cp -= 0x10000;
      out.push_back(static_cast<char16_t>(0xd800 + (cp >> 10)));
      out.push_back(static_cast<char16_t>(0xdc00 + (cp & 0x3ff)));
    }
  }
  return out;
}

#ifdef EF_RBI_JPEG
// JPEG encode of one dirty rect (BGRA source → RGB → jpeg). Compiled only when
// libjpeg is available; otherwise the helper emits raw-RGBA tiles (format 2).
bool encode_tile_jpeg(const uint8_t* view, int view_w, int rx, int ry, int rw, int rh,
                      int quality, std::string& jpeg_out) {
  std::vector<uint8_t> rgb(static_cast<size_t>(rw) * rh * 3);
  for (int y = 0; y < rh; ++y) {
    const uint8_t* src = view + (static_cast<size_t>(ry + y) * view_w + rx) * 4;
    uint8_t* dst = rgb.data() + static_cast<size_t>(y) * rw * 3;
    for (int x = 0; x < rw; ++x) {
      dst[0] = src[2];  // R (BGRA → RGB)
      dst[1] = src[1];  // G
      dst[2] = src[0];  // B
      dst += 3;
      src += 4;
    }
  }
  jpeg_compress_struct cinfo;
  jpeg_error_mgr jerr;
  cinfo.err = jpeg_std_error(&jerr);
  jpeg_create_compress(&cinfo);
  unsigned char* mem = nullptr;
  unsigned long memsize = 0;
  jpeg_mem_dest(&cinfo, &mem, &memsize);
  cinfo.image_width = rw;
  cinfo.image_height = rh;
  cinfo.input_components = 3;
  cinfo.in_color_space = JCS_RGB;
  jpeg_set_defaults(&cinfo);
  jpeg_set_quality(&cinfo, quality, TRUE);
  jpeg_start_compress(&cinfo, TRUE);
  while (cinfo.next_scanline < cinfo.image_height) {
    JSAMPROW row = rgb.data() + static_cast<size_t>(cinfo.next_scanline) * rw * 3;
    jpeg_write_scanlines(&cinfo, &row, 1);
  }
  jpeg_finish_compress(&cinfo);
  bool ok = mem && memsize > 0;
  if (ok) jpeg_out.assign(reinterpret_cast<char*>(mem), memsize);
  if (mem) free(mem);
  jpeg_destroy_compress(&cinfo);
  return ok;
}
#endif

#ifndef EF_RBI_JPEG
// Extract one dirty rect as raw RGBA (BGRA → RGBA). Dependency-free fallback,
// compiled only when libjpeg is absent (otherwise it would be an unused function
// under CEF's -Werror).
void extract_tile_rgba(const uint8_t* view, int view_w, int rx, int ry, int rw, int rh,
                       std::string& rgba_out) {
  rgba_out.resize(static_cast<size_t>(rw) * rh * 4);
  char* dst = &rgba_out[0];
  for (int y = 0; y < rh; ++y) {
    const uint8_t* src = view + (static_cast<size_t>(ry + y) * view_w + rx) * 4;
    for (int x = 0; x < rw; ++x) {
      dst[0] = static_cast<char>(src[2]);  // R
      dst[1] = static_cast<char>(src[1]);  // G
      dst[2] = static_cast<char>(src[0]);  // B
      dst[3] = static_cast<char>(src[3]);  // A
      dst += 4;
      src += 4;
    }
  }
}
#endif  // !EF_RBI_JPEG

// ── base64 decode (for K char text) ───────────────────────────────────────────
std::string b64decode(const std::string& in) {
  auto val = [](unsigned char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  std::string out;
  int bits = 0, acc = 0;
  for (unsigned char c : in) {
    if (c == '=') break;
    int v = val(c);
    if (v < 0) continue;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) { bits -= 8; out += static_cast<char>((acc >> bits) & 0xff); }
  }
  return out;
}

// Post a functor onto the CEF UI thread.
class FnTask : public CefTask {
 public:
  explicit FnTask(std::function<void()> fn) : fn_(std::move(fn)) {}
  void Execute() override { fn_(); }
 private:
  std::function<void()> fn_;
  IMPLEMENT_REFCOUNTING(FnTask);
};
void post_ui(std::function<void()> fn) { CefPostTask(TID_UI, new FnTask(std::move(fn))); }

// ── CEF client + render handler ───────────────────────────────────────────────
class RbiClient : public CefClient,
                  public CefRenderHandler,
                  public CefLifeSpanHandler,
                  public CefDialogHandler,
                  public CefDownloadHandler {
 public:
  CefRefPtr<CefRenderHandler> GetRenderHandler() override { return this; }
  CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override { return this; }
  CefRefPtr<CefDialogHandler> GetDialogHandler() override { return this; }
  CefRefPtr<CefDownloadHandler> GetDownloadHandler() override { return this; }

  // ── CefDialogHandler: the page opened a file picker ──
  // Headless has no native dialog, so we MUST intercept (return true) and later
  // complete the callback with a client-supplied path, or the upload silently
  // hangs. Only OPEN/OPEN_MULTIPLE are serviceable from the operator's machine;
  // other modes are cancelled. NOTE: this override's signature drifts across CEF
  // releases (accept_extensions/accept_descriptions were added, the selected
  // filter index removed) — verify against the pinned CEF headers when bumping.
  bool OnFileDialog(CefRefPtr<CefBrowser> /*browser*/, FileDialogMode mode,
                    const CefString& /*title*/, const CefString& /*default_file_path*/,
                    const std::vector<CefString>& accept_filters,
                    const std::vector<CefString>& accept_extensions,
                    const std::vector<CefString>& /*accept_descriptions*/,
                    CefRefPtr<CefFileDialogCallback> callback) override {
    if (mode != FILE_DIALOG_OPEN && mode != FILE_DIALOG_OPEN_MULTIPLE) {
      callback->Cancel();
      return true;
    }
    const uint32_t seq = g_dialog_seq.fetch_add(1);
    {
      std::lock_guard<std::mutex> lock(g_dialog_mutex);
      g_dialogs[seq] = callback;
    }
    std::string accept;
    const auto& src = !accept_extensions.empty() ? accept_extensions : accept_filters;
    for (const auto& e : src) {
      if (!accept.empty()) accept.push_back(',');
      accept += e.ToString();
    }
    std::string p;
    put_u32(p, seq);
    p.push_back(static_cast<char>(mode == FILE_DIALOG_OPEN_MULTIPLE ? 1 : 0));
    p.push_back(static_cast<char>(mode == FILE_DIALOG_OPEN_MULTIPLE ? 1 : 0));
    put_u16(p, static_cast<uint16_t>(accept.size() > 0xffff ? 0xffff : accept.size()));
    p.append(accept, 0, accept.size() > 0xffff ? 0xffff : accept.size());
    emit_frame(4, p);
    return true;
  }

  // ── CefDownloadHandler: a file was downloaded in the isolated page ──
  // Stage it under g_download_dir, then stream it back when complete. NOTE:
  // OnBeforeDownload's return type (void vs bool) drifts across CEF releases —
  // verify against the pinned headers when bumping.
  bool OnBeforeDownload(CefRefPtr<CefBrowser> /*browser*/,
                        CefRefPtr<CefDownloadItem> item,
                        const CefString& suggested_name,
                        CefRefPtr<CefBeforeDownloadCallback> callback) override {
    const uint32_t id = static_cast<uint32_t>(item->GetId());
    std::string name = suggested_name.ToString();
    std::string safe;
    for (char c : name) {
      if (c == '/' || c == '\\' || c == '\0') continue;
      safe.push_back(c);
    }
    if (safe.empty()) safe = "download.bin";
    if (safe.size() > 200) safe = safe.substr(0, 200);
    const std::string path = g_download_dir + "/" + std::to_string(id) + "_" + safe;
    {
      std::lock_guard<std::mutex> lock(dl_mutex_);
      dl_paths_[id] = path;
      dl_names_[id] = safe;
    }
    callback->Continue(path, false);
    return true;
  }

  void OnDownloadUpdated(CefRefPtr<CefBrowser> /*browser*/,
                         CefRefPtr<CefDownloadItem> item,
                         CefRefPtr<CefDownloadItemCallback> /*callback*/) override {
    const uint32_t id = static_cast<uint32_t>(item->GetId());
    if (!item->IsComplete() && !item->IsCanceled()) return;
    std::string path, name;
    {
      std::lock_guard<std::mutex> lock(dl_mutex_);
      if (dl_done_.count(id)) return;
      auto itp = dl_paths_.find(id);
      if (itp == dl_paths_.end()) return;
      dl_done_.insert(id);
      path = itp->second;
      name = dl_names_[id];
      dl_paths_.erase(id);
      dl_names_.erase(id);
    }
    if (item->IsCanceled()) { ::remove(path.c_str()); return; }
    std::thread(stream_download, id, path, name).detach();
  }

  void OnAfterCreated(CefRefPtr<CefBrowser> browser) override {
    CEF_REQUIRE_UI_THREAD();
    g_browser = browser;
  }
  void OnBeforeClose(CefRefPtr<CefBrowser>) override {
    CEF_REQUIRE_UI_THREAD();
    g_browser = nullptr;
    CefQuitMessageLoop();
  }

  void GetViewRect(CefRefPtr<CefBrowser>, CefRect& rect) override {
    rect.Set(0, 0, g_width.load(), g_height.load());
  }

  void OnPaint(CefRefPtr<CefBrowser>, PaintElementType type,
               const RectList& dirtyRects, const void* buffer,
               int width, int height) override {
    if (type != PET_VIEW) return;
    if (width != g_last_surface_w || height != g_last_surface_h) {
      g_last_surface_w = width;
      g_last_surface_h = height;
      emit_surface(width, height);
    }
    const uint8_t* view = static_cast<const uint8_t*>(buffer);
    const int quality = [] {
      const char* q = std::getenv("ENDORIUMFORT_RBI_JPEG_QUALITY");
      int v = q ? atoi(q) : 55;
      return v < 1 ? 1 : (v > 100 ? 100 : v);
    }();
    (void)quality;
    for (const CefRect& r : dirtyRects) {
      int rx = r.x, ry = r.y, rw = r.width, rh = r.height;
      if (rw <= 0 || rh <= 0) continue;
      if (rx + rw > width) rw = width - rx;
      if (ry + rh > height) rh = height - ry;
      if (rw <= 0 || rh <= 0) continue;
      std::string img;
      uint8_t format;
#ifdef EF_RBI_JPEG
      if (!encode_tile_jpeg(view, width, rx, ry, rw, rh, quality, img)) continue;
      format = 0;  // jpeg
#else
      extract_tile_rgba(view, width, rx, ry, rw, rh, img);
      format = 2;  // raw RGBA
#endif
      std::string payload;
      put_u16(payload, static_cast<uint16_t>(rx));
      put_u16(payload, static_cast<uint16_t>(ry));
      put_u16(payload, static_cast<uint16_t>(rw));
      put_u16(payload, static_cast<uint16_t>(rh));
      payload.push_back(static_cast<char>(format));
      payload.append(img);
      emit_frame(1, payload);
    }
  }

 private:
  std::mutex dl_mutex_;
  std::unordered_map<uint32_t, std::string> dl_paths_;
  std::unordered_map<uint32_t, std::string> dl_names_;
  std::unordered_set<uint32_t> dl_done_;
  IMPLEMENT_REFCOUNTING(RbiClient);
};

// ── CEF app: create the windowless browser once the context is ready ──────────
class RbiApp : public CefApp, public CefBrowserProcessHandler {
 public:
  explicit RbiApp(std::string url) : url_(std::move(url)) {}
  CefRefPtr<CefBrowserProcessHandler> GetBrowserProcessHandler() override { return this; }

  // Headless/OSR command-line tuning: no GPU (software compositing), SwiftShader
  // GL so the page still rasterizes without a real GPU, small-shm safe.
  void OnBeforeCommandLineProcessing(const CefString& process_type,
                                     CefRefPtr<CefCommandLine> cmd) override {
    if (!process_type.empty()) return;  // browser process only
    // Headless Ozone: render with no X server / $DISPLAY (required in containers;
    // without it CEF aborts with "Missing X server"). Override via
    // ENDORIUMFORT_RBI_OZONE (e.g. "x11" when a display is available, "off" to skip).
    const char* ozone = std::getenv("ENDORIUMFORT_RBI_OZONE");
    std::string ozone_platform = (ozone && *ozone) ? ozone : "headless";
    if (ozone_platform != "off") cmd->AppendSwitchWithValue("ozone-platform", ozone_platform);
    cmd->AppendSwitch("disable-gpu");
    cmd->AppendSwitch("disable-gpu-compositing");
    cmd->AppendSwitch("disable-dev-shm-usage");
    cmd->AppendSwitch("no-sandbox");
    cmd->AppendSwitch("enable-begin-frame-scheduling");
    // Software GL backend for GPU-less hosts. Configurable so a host with a real
    // GPU (or a different software stack) can override: ENDORIUMFORT_RBI_ANGLE.
    const char* angle = std::getenv("ENDORIUMFORT_RBI_ANGLE");
    std::string angle_backend = (angle && *angle) ? angle : "swiftshader";
    if (angle_backend != "off") cmd->AppendSwitchWithValue("use-angle", angle_backend);
    // Extra space-separated switches (without leading --), e.g. "ozone-platform=headless".
    if (const char* extra = std::getenv("ENDORIUMFORT_RBI_CEF_FLAGS")) {
      std::istringstream iss(extra);
      std::string tok;
      while (iss >> tok) {
        auto eq = tok.find('=');
        if (eq == std::string::npos) cmd->AppendSwitch(tok);
        else cmd->AppendSwitchWithValue(tok.substr(0, eq), tok.substr(eq + 1));
      }
    }
  }

  void OnContextInitialized() override {
    CEF_REQUIRE_UI_THREAD();
    CefWindowInfo window_info;
    window_info.SetAsWindowless(kNullWindowHandle);
    CefBrowserSettings settings;
    settings.windowless_frame_rate = g_fps.load();
    settings.background_color = CefColorSetARGB(255, 24, 26, 33);
    CefRefPtr<RbiClient> client(new RbiClient());
    CefBrowserHost::CreateBrowser(window_info, client, url_, settings, nullptr, nullptr);
  }

 private:
  std::string url_;
  IMPLEMENT_REFCOUNTING(RbiApp);
};

// ── input: apply parsed events on the UI thread ───────────────────────────────
uint32_t mouse_button_flag(const std::string& b) {
  if (b == "left") return EVENTFLAG_LEFT_MOUSE_BUTTON;
  if (b == "right") return EVENTFLAG_RIGHT_MOUSE_BUTTON;
  if (b == "middle") return EVENTFLAG_MIDDLE_MOUSE_BUTTON;
  return 0;
}
cef_mouse_button_type_t mouse_button_type(const std::string& b) {
  if (b == "right") return MBT_RIGHT;
  if (b == "middle") return MBT_MIDDLE;
  return MBT_LEFT;
}

void handle_line(const std::string& line) {
  if (line.empty()) return;
  const char kind = line[0];
  if (kind == 'R') {
    int w = 0, h = 0;
    if (sscanf(line.c_str() + 1, "%d %d", &w, &h) == 2 && w > 0 && h > 0) {
      g_width = w;
      g_height = h;
      post_ui([] { if (g_browser) g_browser->GetHost()->WasResized(); });
    }
    return;
  }
  if (kind == 'M') {
    char ev[16] = {0}, button[16] = {0};
    int x = 0, y = 0, cc = 0, dx = 0, dy = 0;
    if (sscanf(line.c_str() + 1, "%15s %d %d %15s %d %d %d", ev, &x, &y, button, &cc, &dx, &dy) < 3)
      return;
    std::string e(ev), b(button);
    post_ui([e, b, x, y, cc, dx, dy] {
      if (!g_browser) return;
      auto host = g_browser->GetHost();
      CefMouseEvent me;
      me.x = x;
      me.y = y;
      me.modifiers = mouse_button_flag(b);
      if (e == "move") host->SendMouseMoveEvent(me, false);
      else if (e == "down") host->SendMouseClickEvent(me, mouse_button_type(b), false, cc <= 0 ? 1 : cc);
      else if (e == "up") host->SendMouseClickEvent(me, mouse_button_type(b), true, cc <= 0 ? 1 : cc);
      else if (e == "wheel") host->SendMouseWheelEvent(me, dx, dy);
    });
    return;
  }
  if (kind == 'K') {
    char ev[16] = {0}, textb64[2048] = {0};
    int keyCode = 0, mods = 0;
    if (sscanf(line.c_str() + 1, "%15s %d %d %2047s", ev, &keyCode, &mods, textb64) < 3)
      return;
    std::string e(ev);
    std::string text = (textb64[0] && strcmp(textb64, "-") != 0) ? b64decode(textb64) : "";
    post_ui([e, keyCode, mods, text] {
      if (!g_browser) return;
      auto host = g_browser->GetHost();
      CefKeyEvent ke;
      ke.modifiers = static_cast<uint32_t>(mods);
      ke.windows_key_code = keyCode;
      ke.native_key_code = keyCode;
      if (e == "char") {
        ke.type = KEYEVENT_CHAR;
        // First UTF-16 unit of the text (BMP fast path).
        char16_t ch = 0;
        if (!text.empty()) ch = static_cast<unsigned char>(text[0]);
        ke.windows_key_code = ch;
        ke.character = ch;
        ke.unmodified_character = ch;
      } else if (e == "down") {
        ke.type = KEYEVENT_RAWKEYDOWN;
      } else {
        ke.type = KEYEVENT_KEYUP;
      }
      host->SendKeyEvent(ke);
    });
    return;
  }
  if (kind == 'P') {
    // P <textB64> — paste: inject each UTF-16 unit as a CHAR key event.
    if (line.size() < 3) return;
    std::string text = b64decode(line.substr(2));
    std::vector<char16_t> units = utf8_to_utf16(text);
    post_ui([units] {
      if (!g_browser) return;
      auto host = g_browser->GetHost();
      for (char16_t ch : units) {
        CefKeyEvent ke;
        ke.type = KEYEVENT_CHAR;
        ke.modifiers = 0;
        ke.windows_key_code = ch;
        ke.character = ch;
        ke.unmodified_character = ch;
        host->SendKeyEvent(ke);
      }
    });
    return;
  }
  if (kind == 'U') {
    // U <id> <x> <y> <pathB64> <nameB64> — drop a local file at (x,y).
    char pathb64[4096] = {0}, nameb64[4096] = {0};
    unsigned id = 0;
    int x = 0, y = 0;
    if (sscanf(line.c_str() + 1, "%u %d %d %4095s %4095s", &id, &x, &y, pathb64, nameb64) < 5)
      return;
    std::string path = b64decode(pathb64);
    std::string name = b64decode(nameb64);
    if (path.empty()) return;
    post_ui([x, y, path, name] {
      if (!g_browser) return;
      auto host = g_browser->GetHost();
      CefRefPtr<CefDragData> data = CefDragData::Create();
      data->AddFile(path, name.empty() ? CefString() : CefString(name));
      CefMouseEvent me;
      me.x = x;
      me.y = y;
      me.modifiers = 0;
      host->DragTargetDragEnter(data, me, DRAG_OPERATION_COPY);
      host->DragTargetDragOver(me, DRAG_OPERATION_COPY);
      host->DragTargetDrop(me);
    });
    return;
  }
  if (kind == 'F') {
    // F <seq> <pathsB64CSV|-> — complete (or cancel with "-") a file dialog.
    char paths[4096] = {0};
    unsigned seq = 0;
    if (sscanf(line.c_str() + 1, "%u %4095s", &seq, paths) < 2) return;
    CefRefPtr<CefFileDialogCallback> cb;
    {
      std::lock_guard<std::mutex> lock(g_dialog_mutex);
      auto it = g_dialogs.find(seq);
      if (it != g_dialogs.end()) { cb = it->second; g_dialogs.erase(it); }
    }
    if (!cb) return;
    if (strcmp(paths, "-") == 0) {
      post_ui([cb] { cb->Cancel(); });
      return;
    }
    std::vector<CefString> files;
    std::stringstream ss(paths);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
      std::string p = b64decode(tok);
      if (!p.empty()) files.push_back(p);
    }
    if (files.empty()) { post_ui([cb] { cb->Cancel(); }); return; }
    post_ui([cb, files] { cb->Continue(files); });
    return;
  }
}

void stdin_reader() {
  std::string line;
  char c;
  while (true) {
    ssize_t n = read(STDIN_FILENO, &c, 1);
    if (n <= 0) break;  // EOF: parent closed → quit
    if (c == '\n') {
      handle_line(line);
      line.clear();
    } else if (line.size() < (1u << 20)) {  // 1 MiB: room for a base64 paste line
      line.push_back(c);
    }
  }
  post_ui([] { if (g_browser) g_browser->GetHost()->CloseBrowser(true); });
  CefPostTask(TID_UI, new FnTask([] { CefQuitMessageLoop(); }));
}

}  // namespace

int main(int argc, char** argv) {
  CefMainArgs main_args(argc, argv);

  std::string url = argc > 1 ? argv[1] : "about:blank";
  if (argc > 2) { int w = atoi(argv[2]); if (w > 0) g_width = w; }
  if (argc > 3) { int h = atoi(argv[3]); if (h > 0) g_height = h; }
  const std::string cache = argc > 4 ? argv[4] : "";
  // Downloads (cible → hôte) are staged here before streaming back; cleaned with
  // the session's cache dir by the backend.
  g_download_dir = (cache.empty() ? std::string("/tmp") : cache) + "/downloads";
  mkdir(g_download_dir.c_str(), 0700);
  if (const char* f = std::getenv("ENDORIUMFORT_RBI_MAX_FPS")) {
    int v = atoi(f);
    if (v > 0 && v <= 60) g_fps = v;
  }

  CefRefPtr<RbiApp> app(new RbiApp(url));

  // Sub-processes (renderer/gpu/utility) re-enter here and must return early.
  int exit_code = CefExecuteProcess(main_args, app.get(), nullptr);
  if (exit_code >= 0) return exit_code;

  CefSettings settings;
  settings.windowless_rendering_enabled = true;
  settings.no_sandbox = true;  // container/headless; the whole helper is isolated
  settings.command_line_args_disabled = false;
  if (!cache.empty()) CefString(&settings.root_cache_path) = cache;

  if (!CefInitialize(main_args, settings, app.get(), nullptr)) {
    emit_log("CefInitialize failed");
    return 1;
  }

  std::thread reader(stdin_reader);
  reader.detach();

  CefRunMessageLoop();
  CefShutdown();
  return 0;
}
