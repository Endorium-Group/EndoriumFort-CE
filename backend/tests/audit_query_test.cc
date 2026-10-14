#include "audit_query.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

// A log line as the server writes it; `chained` adds prevHash/hash like the
// current format, otherwise it is an older, pre-chain line.
std::string line(int id, const std::string &type, const std::string &actor,
                 const std::string &at, const std::string &payload, bool chained = true) {
  std::string out = "{\"id\":" + std::to_string(id) + ",\"type\":\"" + type +
                    "\",\"actor\":\"" + actor + "\",\"role\":\"admin\",\"createdAt\":\"" +
                    at + "\",\"payload\":" + payload;
  if (chained) out += ",\"prevHash\":\"GENESIS\",\"hash\":\"" + std::string(64, 'a') + "\"";
  return out + "}\n";
}

void write(const std::string &path, const std::vector<std::string> &lines, const std::string &tail = "") {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  for (const auto &l : lines) out << l;
  out << tail;
}

std::vector<std::string> types_of(const AuditPage &page) {
  std::vector<std::string> out;
  for (const auto &row : page.items) out.push_back(row.type);
  return out;
}

AuditQuery parsed(const char *limit = nullptr, const char *cursor = nullptr,
                  const char *actor = nullptr, const char *family = nullptr,
                  const char *category = nullptr, const char *from = nullptr,
                  const char *to = nullptr, const char *text = nullptr,
                  const char *session = nullptr, const char *facets = nullptr) {
  AuditQuery q;
  std::string error;
  parse_audit_query(limit, cursor, actor, family, category, from, to, text, session, facets, q, error);
  return q;
}

}  // namespace

int main() {
  bool ok = true;
  namespace fs = std::filesystem;
  const fs::path dir = fs::temp_directory_path() / "ef-audit-query-test";
  fs::remove_all(dir);
  fs::create_directories(dir);
  const std::string active = (dir / "audit-log.jsonl").string();

  // Archive (older): two pre-chain lines from a previous version.
  write(active + ".1000", {
      line(1, "auth.login.success", "alice", "2026-10-01T08:00:00Z", "{\"ip\":\"10.0.0.1\"}", false),
      line(2, "session.create", "alice", "2026-10-01T08:01:00Z", "{\"sessionId\":7,\"resourceId\":1}", false),
  });
  // Active file: ids restart at 1 (new boot), a string payload, and a line
  // still being written (no newline) that must be ignored.
  write(active, {
      line(1, "user.update", "admin", "2026-10-12T09:00:00Z", "{\"username\":\"bob\"}"),
      line(2, "auth.login.failure", "bob", "2026-10-12T09:05:00Z", "{\"reason\":\"Bad password\"}"),
      line(3, "session.create", "bob", "2026-10-13T10:00:00Z", "{\"sessionId\":9}"),
      line(4, "session.terminate", "admin", "2026-10-13T11:00:00Z", "{\"sessionId\":\"9\"}"),
      line(5, "note", "system", "2026-10-13T12:00:00Z", "\"plain \\\"text\\\" payload\""),
  }, "{\"id\":6,\"type\":\"half");
  const auto files = audit_log_files(active);
  ok &= expect(files.size() == 2 && files[0] == active, "active file first, then the archive");

  {
    const AuditPage page = query_audit_files(files, std::nullopt, parsed());
    ok &= expect(page.items.size() == 7, "default query returns every complete line");
    ok &= expect(page.items.front().type == "note", "newest first");
    ok &= expect(page.items.back().type == "auth.login.success", "archive lines come last");
    ok &= expect(page.next.empty(), "no next page when everything fits");
    ok &= expect(!page.items.front().payloadIsJson && page.items.front().payloadRaw == "plain \"text\" payload",
                 "string payloads are unescaped");
    ok &= expect(page.items[1].payloadIsJson && page.items[1].payloadRaw == "{\"sessionId\":\"9\"}",
                 "JSON payloads are returned verbatim");
    ok &= expect(page.items.front().key != page.items[4].key, "keys are unique even when ids repeat");
  }

  {
    // Paging two at a time walks the whole log, across the archive, once.
    std::vector<std::string> seen;
    std::string cursor;
    int pages = 0;
    do {
      const AuditPage page = query_audit_files(files, std::nullopt, parsed("2", cursor.c_str()));
      for (const auto &row : page.items) seen.push_back(row.key);
      cursor = page.next;
      ++pages;
    } while (!cursor.empty() && pages < 10);
    ok &= expect(pages == 4 && seen.size() == 7, "4 pages of 2 cover the 7 events");
    std::vector<std::string> unique(seen);
    std::sort(unique.begin(), unique.end());
    ok &= expect(std::unique(unique.begin(), unique.end()) == unique.end(), "no event repeated across pages");
  }

  {
    // A cursor survives the active file being rotated into an archive.
    const AuditPage first = query_audit_files(files, std::nullopt, parsed("3"));
    fs::rename(active, active + ".2000");
    write(active, {line(1, "license.reloaded", "system", "2026-10-13T13:00:00Z", "{}")});
    const auto rotated = audit_log_files(active);
    const AuditPage second = query_audit_files(rotated, std::nullopt, parsed("3", first.next.c_str()));
    ok &= expect(types_of(second) == std::vector<std::string>({"auth.login.failure", "user.update", "session.create"}),
                 "after rotation the next page continues where it stopped");
    const AuditPage expired = query_audit_files(rotated, std::nullopt, parsed("3", "0123456789abcdef:4"));
    ok &= expect(expired.cursorExpired, "an unknown cursor is reported as expired");
    fs::remove(active);
    fs::rename(active + ".2000", active);
  }

  {
    auto only = [&](AuditQuery q) { return types_of(query_audit_files(files, std::nullopt, q)); };
    ok &= expect(only(parsed(nullptr, nullptr, "bob")) == std::vector<std::string>({"session.create", "auth.login.failure"}),
                 "actor filter");
    ok &= expect(only(parsed(nullptr, nullptr, nullptr, "session")).size() == 3, "family filter matches session.*");
    ok &= expect(only(parsed(nullptr, nullptr, nullptr, nullptr, "failure")) == std::vector<std::string>({"auth.login.failure"}),
                 "failure category");
    ok &= expect(only(parsed(nullptr, nullptr, nullptr, nullptr, "admin")) == std::vector<std::string>({"user.update"}),
                 "admin category");
    ok &= expect(only(parsed(nullptr, nullptr, nullptr, nullptr, nullptr, "2026-10-12", "2026-10-12")).size() == 2,
                 "a from/to day includes the whole day");
    ok &= expect(only(parsed(nullptr, nullptr, nullptr, nullptr, nullptr, "2026-10-13T10:30:00Z")).size() == 2,
                 "from with a time");
    ok &= expect(only(parsed(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, "BAD PASS")) == std::vector<std::string>({"auth.login.failure"}),
                 "text search ignores case");
    ok &= expect(only(parsed(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, "9")) == std::vector<std::string>({"session.terminate", "session.create"}),
                 "session filter accepts numeric and string ids");
  }

  {
    const AuditPage page = query_audit_files(files, std::nullopt, parsed("1", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, "1"));
    ok &= expect(page.items.size() == 1 && !page.next.empty(), "facets do not change paging");
    ok &= expect(page.actors == std::set<std::string>({"admin", "alice", "bob", "system"}), "facets list every actor, archives included");
    ok &= expect(page.families.count("auth") && page.families.count("session") && page.families.count("note"), "facets list families");
  }

  {
    // The active size cap leaves out a line appended after the snapshot. End
    // the half-written line first: it stays unreadable and must be skipped.
    {
      std::ofstream out(active, std::ios::binary | std::ios::app);
      out << "\n";
    }
    const auto snapshot = static_cast<uint64_t>(fs::file_size(active));
    {
      std::ofstream out(active, std::ios::binary | std::ios::app);
      out << line(7, "late.event", "admin", "2026-10-13T14:00:00Z", "{}");
    }
    const AuditPage capped = query_audit_files(files, snapshot, parsed());
    ok &= expect(capped.items.front().type == "note", "lines past the snapshot size are not read");
    const AuditPage full = query_audit_files(files, std::nullopt, parsed());
    ok &= expect(full.items.front().type == "late.event", "without a cap the new line is read");
  }

  {
    AuditQuery q;
    std::string error;
    ok &= expect(!parse_audit_query("0", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, q, error), "limit 0 refused");
    ok &= expect(!parse_audit_query("501", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, q, error), "limit over 500 refused");
    ok &= expect(!parse_audit_query(nullptr, "../etc", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, q, error), "malformed cursor refused");
    ok &= expect(!parse_audit_query(nullptr, nullptr, nullptr, nullptr, "all", nullptr, nullptr, nullptr, nullptr, nullptr, q, error), "unknown category refused");
    ok &= expect(!parse_audit_query(nullptr, nullptr, nullptr, nullptr, nullptr, "yesterday", nullptr, nullptr, nullptr, nullptr, q, error), "bad date refused");
  }

  fs::remove_all(dir);
  if (ok) std::cout << "audit query tests passed" << std::endl;
  return ok ? 0 : 1;
}
