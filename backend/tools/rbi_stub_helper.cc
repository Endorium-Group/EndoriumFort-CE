// ─── EndoriumFort — RBI "tiles" engine: synthetic stub helper ────────────────
// A dependency-free stand-in for the real CEF-OSR helper, used to validate the
// homemade dirty-rect tile transport (protocol, backend relay, frontend canvas)
// without building CEF. It renders nothing real — it emits a moving colored
// square as raw-RGBA tiles and consumes input events from stdin.
//
// Protocol (this program's stdout, framed big-endian):
//   [u8 type][u32 len][payload]   type 1=tile, 2=surface-info, 3=log
//   tile:    [u16 x][u16 y][u16 w][u16 h][u8 format][image bytes]  (format 2 = RGBA)
//   surface: [u16 width][u16 height]
// stdin: newline-delimited JSON input/resize events (consumed; a resize updates
// the surface size and re-emits a surface-info frame).
//
// argv: [prog, url, width, height, user_data_dir]

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <unistd.h>
#include <signal.h>

namespace {

std::atomic<bool> g_running{true};
std::atomic<int> g_width{1280};
std::atomic<int> g_height{800};

bool write_all(const char *p, size_t n) {
  while (n > 0) {
    ssize_t w = write(STDOUT_FILENO, p, n);
    if (w <= 0) return false;
    p += w;
    n -= static_cast<size_t>(w);
  }
  return true;
}

void put_u16(std::string &s, uint16_t v) {
  s.push_back(static_cast<char>((v >> 8) & 0xff));
  s.push_back(static_cast<char>(v & 0xff));
}

bool emit_frame(uint8_t type, const std::string &payload) {
  std::string hdr;
  hdr.push_back(static_cast<char>(type));
  const uint32_t len = static_cast<uint32_t>(payload.size());
  hdr.push_back(static_cast<char>((len >> 24) & 0xff));
  hdr.push_back(static_cast<char>((len >> 16) & 0xff));
  hdr.push_back(static_cast<char>((len >> 8) & 0xff));
  hdr.push_back(static_cast<char>(len & 0xff));
  return write_all(hdr.data(), hdr.size()) && write_all(payload.data(), payload.size());
}

void emit_surface() {
  std::string p;
  put_u16(p, static_cast<uint16_t>(g_width.load()));
  put_u16(p, static_cast<uint16_t>(g_height.load()));
  emit_frame(2, p);
}

// A raw-RGBA tile filled with one color.
void emit_square(int x, int y, int w, int h, uint8_t r, uint8_t gc, uint8_t b) {
  std::string p;
  put_u16(p, static_cast<uint16_t>(x));
  put_u16(p, static_cast<uint16_t>(y));
  put_u16(p, static_cast<uint16_t>(w));
  put_u16(p, static_cast<uint16_t>(h));
  p.push_back(static_cast<char>(2));  // format 2 = RGBA
  p.reserve(p.size() + static_cast<size_t>(w) * h * 4);
  for (int i = 0; i < w * h; ++i) {
    p.push_back(static_cast<char>(r));
    p.push_back(static_cast<char>(gc));
    p.push_back(static_cast<char>(b));
    p.push_back(static_cast<char>(0xff));
  }
  emit_frame(1, p);
}

void stdin_reader() {
  std::string line;
  char c;
  while (g_running) {
    ssize_t n = read(STDIN_FILENO, &c, 1);
    if (n <= 0) break;  // EOF → parent closed the pipe
    if (c == '\n') {
      // Line protocol: "R <w> <h>" resizes the surface; M/K (input) are ignored.
      if (line.size() >= 2 && line[0] == 'R' && line[1] == ' ') {
        int w = 0, h = 0;
        if (sscanf(line.c_str() + 2, "%d %d", &w, &h) == 2 && w > 0 && h > 0) {
          g_width = w;
          g_height = h;
          emit_surface();
        }
      }
      line.clear();
    } else if (line.size() < 4096) {
      line.push_back(c);
    }
  }
  g_running = false;
}

}  // namespace

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  if (argc >= 4) {
    int w = atoi(argv[2]);
    int h = atoi(argv[3]);
    if (w > 0) g_width = w;
    if (h > 0) g_height = h;
  }
  std::thread reader(stdin_reader);
  reader.detach();

  emit_surface();
  // Paint a static background once (one big tile), then animate a moving square.
  emit_square(0, 0, g_width.load(), g_height.load(), 24, 26, 33);

  int step = 0;
  const int sq = 96;
  while (g_running) {
    const int W = g_width.load(), H = g_height.load();
    const int range_x = W > sq ? W - sq : 1;
    const int range_y = H > sq ? H - sq : 1;
    const int x = (step * 13) % range_x;
    const int y = (step * 7) % range_y;
    // Repaint the background strip we may have dirtied, then the square.
    emit_square(0, 0, W, H, 24, 26, 33);
    emit_square(x, y, sq, sq,
                static_cast<uint8_t>(80 + (step * 3) % 175),
                static_cast<uint8_t>(120),
                static_cast<uint8_t>(200 - (step * 2) % 150));
    if (!g_running) break;
    ++step;
    std::this_thread::sleep_for(std::chrono::milliseconds(66));  // ~15 fps
    // Exit if stdout is gone.
    if (write_all("", 0) == false) break;
  }
  return 0;
}
