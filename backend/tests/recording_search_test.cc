// Unit tests for full-text search in recordings: the text extraction of a
// cast (cast_text.h) and the SQLite FTS5 index (recording_search.cc).
#include "app_context.h"
#include "pro/cast_text.h"
#include "pro/fold_text.h"
#include "pro/recording_search.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <sstream>
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

std::vector<cast_text::Line> screen_of(const std::vector<std::pair<double, std::string>> &events) {
  cast_text::Screen screen;
  for (const auto &[ts, data] : events) screen.feed(ts, data);
  screen.finish();
  return screen.take();
}

void test_json_and_events() {
  size_t at = 0;
  auto s = cast_text::json_string("\"a\\u001b[0m\\r\\n\\u00e9\\ud83d\\ude00\\\"\"", at);
  expect(s && *s == "a\x1b[0m\r\n\xc3\xa9\xf0\x9f\x98\x80\"", "JSON string: escapes, BMP and surrogate pair");
  at = 0;
  expect(!cast_text::json_string("\"unterminated", at), "unterminated string refused");

  auto e = cast_text::parse_event("[1.250000,\"o\",\"ls\\r\\n\"]");
  expect(e && e->ts == 1.25 && e->stream == 'o' && e->data == "ls\r\n", "event parsed");
  expect(!cast_text::parse_event("garbage"), "garbage refused");
}

void test_screen() {
  auto lines = screen_of({{0.5, "\x1b[01;32muser@prod\x1b[00m:~$ "}, {1.0, "rm -rf /tmp/x\r\n"}});
  expect(lines.size() == 1 && lines[0].text == "user@prod:~$ rm -rf /tmp/x", "colours removed, prompt + command");
  expect(lines.size() == 1 && lines[0].ts == 1.0, "line stamped when it was complete (Enter)");

  lines = screen_of({{0, "progress 10%\rprogress 99%\rdone        \x1b[K\n"}});
  expect(lines.size() == 1 && lines[0].text == "done", "carriage return overwrites, erase to end of line");

  lines = screen_of({{0, "sudo rmm\b \bdir\r\n"}});
  expect(lines.size() == 1 && lines[0].text == "sudo rmdir", "backspace edits the line");

  lines = screen_of({{0, "a\tb\r\n"}});
  expect(lines.size() == 1 && lines[0].text == "a       b", "tab to the next stop");

  lines = screen_of({{0, "\x1b]0;user@host: ~\x07" "caf\xc3\xa9\b\b\xc3\xa8\r\n"}});
  expect(lines.size() == 1 && lines[0].text == "ca\xc3\xa8\xc3\xa9", "OSC title removed, UTF-8 cells kept whole (backspace moves, does not erase)");

  lines = screen_of({{0, "abcdef\x1b[3D\x1b[1PX\r\n"}});
  expect(lines.size() == 1 && lines[0].text == "abcXf", "cursor back, delete character, overwrite");

  lines = screen_of({{0, "\r\n   \r\nlast"}});
  expect(lines.size() == 1 && lines[0].text == "last", "blank lines dropped, last line kept at the end");
}

void test_fold() {
  expect(fold_text::fold("D\xc3\xa9ploiement TERMIN\xc3\x89 \xc5\x93uvre stra\xc3\x9f") == "deploiement termine oeuvre strass",
         "accents, case, ligatures folded");
  expect(fold_text::fold("\xe6\x97\xa5\xe6\x9c\xac 1\xc3\x97" "2") == "\xe6\x97\xa5\xe6\x9c\xac 1\xc3\x97" "2",
         "other scripts and symbols kept");
  expect(fold_text::mark("Le D\xc3\xa9ploiement est fini", "deploiement") == "Le \x02" "D\xc3\xa9ploiement\x03 est fini",
         "the original word is marked");
  expect(fold_text::mark("rmdir x; rm -rf y", "rm -rf") == "rmdir x; \x02rm\x03 -\x02rf\x03 y", "whole words only");
}

void test_read_cast() {
  std::istringstream cast(
      "{\"version\":2,\"width\":80,\"height\":24}\n"
      "[0.1,\"o\",\"$ \"]\n"
      "[0.2,\"i\",\"sudo -k\\r\"]\n"
      "[0.3,\"o\",\"sudo -k\\r\\n[sudo] password: \"]\n"
      "[0.9,\"i\",\"S3cretPw\\r\"]\n"
      "[1.0,\"o\",\"\\r\\n$ \"]\n");
  const auto lines = cast_text::read_cast(cast);
  std::string all;
  for (const auto &l : lines) all += l.text + "\n";
  expect(all.find("sudo -k") != std::string::npos, "echoed command indexed");
  expect(all.find("S3cretPw") == std::string::npos, "keystrokes that were never shown stay out");
}

std::string write_cast(const std::filesystem::path &path, const std::string &body) {
  std::ofstream(path) << "{\"version\":2,\"width\":80,\"height\":24}\n" << body;
  return path.string();
}

void test_index_and_search(const std::string &dsn, const std::string &label) {
  std::cout << "index on " << label << std::endl;
  AppContext ctx;
  ctx.audit_path = "";
  ctx.init_database(dsn);
  expect(recording_search::init(ctx), label + ": index created");
  expect(recording_search::fts_phrase("say \"hi\"") == "\"say \"\"hi\"\"\"", "phrase quoting");

  const auto dir = std::filesystem::temp_directory_path() / ("ef-recsearch-" + std::to_string(::getpid()));
  std::filesystem::create_directories(dir);
  const auto path1 = write_cast(dir / "s5.cast",
                                "[0.5,\"o\",\"root@prod:~# \"]\n"
                                "[2.0,\"o\",\"rm -rf /var/lib/app\\r\\n\"]\n"
                                "[3.0,\"o\",\"Déploiement terminé\\r\\n\"]\n");
  const auto path2 = write_cast(dir / "s6.cast", "[1.0,\"o\",\"ls -la\\r\\n\"]\n");

  std::string err;
  if (!ctx.sqlite.exec("INSERT INTO access_grants(id, resource_id, subject, resource_scope, granted_at, expires_at) VALUES "
                       "(40, 2, 'alice', 'resource:2', '2026-11-05T09:00:00Z', '2026-11-05T10:00:00Z'), "
                       "(41, 2, 'bob', 'resource:2', '2026-11-04T09:00:00Z', '2026-11-04T10:00:00Z');", err))
    std::cerr << "grant insert: " << err << std::endl;
  Session s5;
  s5.id = 5;
  s5.resourceId = 2;
  s5.accessGrantId = 40;
  ctx.sessions[5] = s5;
  Session s6 = s5;
  s6.id = 6;
  s6.accessGrantId = 41;
  ctx.sessions[6] = s6;
  ctx.recordings[1] = SessionRecording{1, 5, path1, "2026-11-05T09:00:00Z", "2026-11-05T09:10:00Z", 0, 0};
  ctx.recordings[2] = SessionRecording{2, 6, path2, "2026-11-04T09:00:00Z", "2026-11-04T09:10:00Z", 0, 0};
  SessionRecording open_rec{3, 7, (dir / "live.cast").string(), "2026-11-05T10:00:00Z", "", 0, 0};
  write_cast(dir / "live.cast", "[0.1,\"o\",\"rm -rf live\\r\\n\"]\n");
  ctx.recordings[3] = open_rec;

  const std::string first = recording_search::sync(ctx);
  expect(first.find("indexed=2") != std::string::npos, "closed recordings indexed, the open one left: " + first);
  expect(recording_search::sync(ctx).find("indexed=0") != std::string::npos, "unchanged files are not re-indexed");

  recording_search::Query q;
  q.text = "rm -rf";
  auto r = recording_search::search(ctx, q);
  expect(r.error.empty() && r.sessions.size() == 1, "phrase found once: " + r.error);
  if (!r.sessions.empty()) {
    const auto &hit = r.sessions[0];
    expect(hit.sessionId == 5 && hit.operatorName == "alice" && hit.resourceId == 2, "labelled with its session");
    expect(!hit.hits.empty() && hit.hits[0].ts == 2.0, "offset of the line for the player");
    expect(!hit.hits.empty() && (hit.hits[0].snippet.find("\x02rm -rf\x03") != std::string::npos ||
                                hit.hits[0].snippet.find("\x02rm\x03 -\x02rf\x03") != std::string::npos),
           "match marked: " + (hit.hits.empty() ? std::string() : hit.hits[0].snippet));
  }
  q.text = "deploiement";
  expect(recording_search::search(ctx, q).sessions.size() == 1, "accents and case folded");
  q.text = "rf rm";
  expect(recording_search::search(ctx, q).sessions.empty(), "a phrase keeps word order");
  q.text = "ls";
  q.user = "alice";
  expect(recording_search::search(ctx, q).sessions.empty(), "user filter");
  q.user = "bob";
  expect(recording_search::search(ctx, q).sessions.size() == 1, "user filter keeps that user's sessions");
  q.user.clear();
  q.from = "2026-11-05";
  expect(recording_search::search(ctx, q).sessions.empty(), "date filter on the recording start");
  q.from.clear();
  q.resourceId = 9;
  expect(recording_search::search(ctx, q).sessions.empty(), "resource filter");
  q = {};
  q.text = "\"";
  expect(recording_search::search(ctx, q).error.empty(), "a stray quote is not a syntax error");
  q.text = "";
  expect(!recording_search::search(ctx, q).error.empty(), "empty query refused");

  // The file is gone: its lines leave the index.
  std::filesystem::remove(path1);
  recording_search::sync(ctx);
  q = {};
  q.text = "rm -rf";
  expect(recording_search::search(ctx, q).sessions.empty(), "purged recording no longer found");
  // The recording itself is forgotten: its index rows go too.
  ctx.recordings.erase(2);
  const std::string dropped = recording_search::sync(ctx);
  expect(dropped.find("dropped=1") != std::string::npos, "unknown recording dropped: " + dropped);

  std::filesystem::remove_all(dir);
}

// A throw-away PostgreSQL for the tsvector variant; "" when unavailable.
std::string find_pg_bin() {
  if (const char *env = std::getenv("ENDORIUMFORT_PG_BIN"); env && *env) return env;
  std::string best;
  if (std::filesystem::exists("/usr/lib/postgresql"))
    for (const auto &entry : std::filesystem::directory_iterator("/usr/lib/postgresql"))
      if (std::filesystem::exists(entry.path() / "bin" / "initdb") && entry.path().string() > best)
        best = entry.path().string();
  return best.empty() ? "" : best + "/bin";
}
// Regression (v1.0.60): the end-of-recording seam ran under the database
// lock and the scheduler it wakes takes that lock too — the bastion froze on
// the first closed recording. The seam here takes the lock the same way.
void test_close_seam_outside_the_lock() {
  static AppContext ctx;  // static: on failure the stuck thread still uses it
  ctx.audit_path = "";
  ctx.init_database(":memory:");
  std::atomic<int> called{0};
  ctx.on_recording_closed = [&](int id) {
    std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
    called = id;
  };
  SessionRecording rec{42, 1, "/nonexistent.cast", "2026-11-05T09:00:00Z", "2026-11-05T09:01:00Z", 1000, 10};
  ctx.insert_recording(rec);
  auto done = std::async(std::launch::async, [&] { return ctx.update_recording_close(rec); });
  if (!expect(done.wait_for(std::chrono::seconds(5)) == std::future_status::ready,
              "closing a recording does not deadlock on the seam")) {
    std::cerr << failures << " recording search test(s) failed" << std::endl;
    std::_Exit(1);  // the update thread is stuck holding the lock
  }
  expect(done.get() && called == 42, "the seam runs once the recording is closed");
}
}  // namespace

int main() {
  test_close_seam_outside_the_lock();
  test_json_and_events();
  test_screen();
  test_fold();
  test_read_cast();
  test_index_and_search(":memory:", "SQLite FTS5");

#ifdef ENDORIUMFORT_POSTGRES
  const std::string bin = find_pg_bin();
#else
  const std::string bin;  // this build has no PostgreSQL backend
#endif
  if (bin.empty() || geteuid() == 0) {
    std::cout << "PostgreSQL variant skipped (no binaries, or root)" << std::endl;
  } else {
    char tmpl[] = "/tmp/ef-recsearch-pg-XXXXXX";
    const std::string dir = mkdtemp(tmpl);
    const std::string port = std::to_string(20000 + (::getpid() % 20000));
    const bool up = std::system((bin + "/initdb -D " + dir + "/data -U postgres --auth=trust >/dev/null 2>&1 && " +
                                 bin + "/pg_ctl -D " + dir + "/data -w -l " + dir + "/log -o \"-c listen_addresses='' -k " +
                                 dir + " -p " + port + "\" start >/dev/null 2>&1").c_str()) == 0;
    if (expect(up, "throw-away PostgreSQL started")) {
      test_index_and_search("postgresql://postgres@/postgres?host=" + dir + "&port=" + port, "PostgreSQL tsvector");
      std::system((bin + "/pg_ctl -D " + dir + "/data -m immediate stop >/dev/null 2>&1").c_str());
    }
    std::filesystem::remove_all(dir);
  }
  if (failures) {
    std::cerr << failures << " recording search test(s) failed" << std::endl;
    return 1;
  }
  std::cout << "recording search tests passed" << std::endl;
  return 0;
}
