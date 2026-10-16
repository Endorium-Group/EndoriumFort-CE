#include "ssh_guard.h"

#include "app_context.h"
#include "utils.h"

#include <algorithm>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <sstream>

namespace ssh_guard {
namespace {

constexpr size_t kMaxNameChars = 48;
constexpr size_t kMaxCommandChars = 200;

struct Builtin {
  const char *name;
  std::string pattern;
};

// The set that shipped hard-coded in ssh.cc. The sources are unchanged, so a
// guard left at its defaults behaves exactly as before.
// Start of the line or just after a shell separator, an optional sudo, and an
// optional directory so /bin/rm reads as rm. One optional run, not a nested
// quantifier: this is matched against every submitted line.
constexpr const char *kCommandPrefix = R"((^|[;&|]\s*)(sudo\s+)?(?:[A-Za-z0-9_./-]*/)?)";

const std::vector<Builtin> &builtins() {
  static const std::vector<Builtin> all = {
      {"wipe_root", std::string(kCommandPrefix) + R"(rm\s+-rf\s+/($|\s))"},
      {"fork_bomb", R"(:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:)"},
      {"disk_format", std::string(kCommandPrefix) + R"(mkfs(\.[a-z0-9]+)?\b)"},
      {"raw_disk_dd", std::string(kCommandPrefix) + R"(dd\s+if=.*\s+of=/dev/)"},
      {"power_command",
       std::string(kCommandPrefix) + R"((shutdown|poweroff|reboot)\b)"}};
  return all;
}

bool is_builtin(const std::string &name) {
  const auto &all = builtins();
  return std::any_of(all.begin(), all.end(),
                     [&](const Builtin &b) { return name == b.name; });
}

// The compiled set lives here rather than in AppContext: it is read on every
// keystroke of every guarded session, and keeping <regex> out of the shared
// header saves rebuilding most of the backend whenever this file changes.
std::shared_mutex g_mutex;
std::vector<std::pair<std::string, std::regex>> g_compiled;

std::string regex_escape(const std::string &s) {
  static const std::string specials = R"(\^$.|?*+()[]{}/)";
  std::string out;
  out.reserve(s.size() * 2);
  for (char c : s) {
    if (specials.find(c) != std::string::npos) out.push_back('\\');
    out.push_back(c);
  }
  return out;
}

std::string trim(const std::string &s) {
  const auto begin = s.find_first_not_of(" \t\r\n");
  if (begin == std::string::npos) return "";
  const auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(begin, end - begin + 1);
}

}  // namespace

std::string command_to_pattern(const std::string &command) {
  // Tokens are joined with \s+ so "rm  -rf  /" and "rm -rf /" are one rule.
  std::istringstream iss(command);
  std::string token;
  std::string body;
  while (iss >> token) {
    if (!body.empty()) body += R"(\s+)";
    body += regex_escape(token);
  }
  if (body.empty()) return "";
  // Same shape as the built-ins, and nothing word-like straight after — so
  // "shutdown" does not fire on "shutdownctl", nor "rm -rf /" on "rm -rf /srv".
  return std::string(kCommandPrefix) + body + R"((?![A-Za-z0-9_.\-/]))";
}

namespace {

// Rebuilds the compiled set from the store. Caller must not hold g_mutex.
void recompile(AppContext &ctx) {
  std::vector<std::pair<std::string, std::regex>> next;
  for (const auto &rule : list(ctx)) {
    if (!rule.enabled) continue;
    std::string source;
    if (rule.builtin) {
      for (const auto &b : builtins())
        if (rule.name == b.name) source = b.pattern;
    } else {
      source = command_to_pattern(rule.command);
    }
    if (source.empty()) continue;
    try {
      next.emplace_back(rule.name, std::regex(source, std::regex::icase));
    } catch (const std::regex_error &) {
      // Unreachable for escaped input, but a rule that will not compile must
      // never take the guard down with it.
      continue;
    }
  }
  std::unique_lock<std::shared_mutex> lock(g_mutex);
  g_compiled = std::move(next);
}

}  // namespace

void init(AppContext &ctx) {
  {
    std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
    if (!ctx.sqlite.is_open()) return;
    std::string err;
    ctx.sqlite.exec(
        "CREATE TABLE IF NOT EXISTS ssh_guard_rules ("
        "name TEXT PRIMARY KEY,"
        "command TEXT NOT NULL DEFAULT '',"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "builtin INTEGER NOT NULL DEFAULT 0,"
        "updated_at INTEGER NOT NULL DEFAULT 0);",
        err);
    // Seed, never overwrite: an operator who disabled a built-in keeps it off
    // across restarts.
    for (const auto &b : builtins()) {
      auto stmt = ctx.sqlite.prepare(
          "INSERT INTO ssh_guard_rules(name,command,enabled,builtin,updated_at)"
          " VALUES(?1,'',1,1,?2) ON CONFLICT(name) DO NOTHING;");
      if (!stmt) continue;
      stmt.bind_text(1, b.name);
      stmt.bind_int64(2, now_epoch_seconds());
      stmt.execute();
    }
  }
  recompile(ctx);
}

std::vector<Rule> list(AppContext &ctx) {
  std::vector<Rule> out;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  if (!ctx.sqlite.is_open()) return out;
  auto stmt = ctx.sqlite.prepare(
      "SELECT name,command,enabled,builtin,updated_at FROM ssh_guard_rules "
      "ORDER BY builtin DESC, name ASC;");
  if (!stmt) return out;
  while (stmt.step()) {
    Rule r;
    r.name = stmt.column_text(0);
    r.command = stmt.column_text(1);
    r.enabled = stmt.column_int(2) != 0;
    r.builtin = stmt.column_int(3) != 0;
    r.updatedAt = stmt.column_int64(4);
    out.push_back(std::move(r));
  }
  return out;
}

bool save(AppContext &ctx, const std::string &name, const std::string &command,
          bool enabled, std::string &error) {
  const std::string clean_name = trim(name);
  if (clean_name.empty() || clean_name.size() > kMaxNameChars) {
    error = "name must be 1 to 48 characters";
    return false;
  }
  // The name reaches the audit trail and the UI; keep it boring.
  for (char c : clean_name) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
      error = "name may only contain letters, digits, '_' and '-'";
      return false;
    }
  }

  const bool builtin = is_builtin(clean_name);
  std::string clean_command = trim(command);
  if (builtin) {
    // Only the toggle is editable: the built-in sources are the product's.
    clean_command.clear();
  } else {
    if (clean_command.empty()) {
      error = "command must not be empty";
      return false;
    }
    if (clean_command.size() > kMaxCommandChars) {
      error = "command must be at most 200 characters";
      return false;
    }
    if (command_to_pattern(clean_command).empty()) {
      error = "command must contain at least one word";
      return false;
    }
  }

  {
    std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
    if (!ctx.sqlite.is_open()) {
      error = "database unavailable";
      return false;
    }
    auto stmt = ctx.sqlite.prepare(
        "INSERT INTO ssh_guard_rules(name,command,enabled,builtin,updated_at) "
        "VALUES(?1,?2,?3,?4,?5) ON CONFLICT(name) DO UPDATE SET "
        "command=excluded.command,enabled=excluded.enabled,"
        "updated_at=excluded.updated_at;");
    if (!stmt) {
      error = "database unavailable";
      return false;
    }
    stmt.bind_text(1, clean_name);
    stmt.bind_text(2, clean_command);
    stmt.bind_int(3, enabled ? 1 : 0);
    stmt.bind_int(4, builtin ? 1 : 0);
    stmt.bind_int64(5, now_epoch_seconds());
    if (!stmt.execute()) {
      error = "could not save the rule";
      return false;
    }
  }
  recompile(ctx);
  return true;
}

bool remove(AppContext &ctx, const std::string &name, std::string &error) {
  if (is_builtin(name)) {
    error = "built-in rules can be disabled but not removed";
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
    if (!ctx.sqlite.is_open()) {
      error = "database unavailable";
      return false;
    }
    auto stmt =
        ctx.sqlite.prepare("DELETE FROM ssh_guard_rules WHERE name=?1;");
    if (!stmt) {
      error = "database unavailable";
      return false;
    }
    stmt.bind_text(1, name);
    stmt.execute();
    if (ctx.sqlite.changes() == 0) {
      error = "no such rule";
      return false;
    }
  }
  recompile(ctx);
  return true;
}

bool track_line(const std::string &input, std::string &line) {
  constexpr size_t kMaxTrackedLine = 4096;
  for (char c : input) {
    if (c == '\r' || c == '\n') return true;
    switch (c) {
      case '\b':
      case '\x7f':  // backspace / delete
        if (!line.empty()) line.pop_back();
        break;
      case '\x03':  // Ctrl-C: the line is abandoned
      case '\x15':  // Ctrl-U: kill the whole line
        line.clear();
        break;
      case '\x1b':
        // An escape sequence — an arrow key, history recall, a full-screen
        // program. Whatever the remote now holds, we no longer know it.
        // Drop the rest of the event too, or its bytes ("[A" for Up) would be
        // mistaken for typing and poison the next command.
        line.clear();
        return false;
      case '\x17':  // Ctrl-W: kill the word before the cursor
        while (!line.empty() && line.back() == ' ') line.pop_back();
        while (!line.empty() && line.back() != ' ') line.pop_back();
        break;
      default:
        // Printable only, and bounded: a paste of a megabyte must not grow
        // the mirror without limit.
        if (static_cast<unsigned char>(c) >= 0x20 && line.size() < kMaxTrackedLine)
          line.push_back(c);
    }
  }
  return false;
}

std::string unquote(const std::string &line) {
  // Shell quoting is the cheapest way to walk past a literal blocklist:
  // r''m, "rm" and r\m all run rm. Removing the quoting characters gives the
  // reading the shell would get. Variables and command substitution are out of
  // reach — see the limits in ssh_guard.h.
  std::string out;
  out.reserve(line.size());
  bool in_single = false, in_double = false;
  for (size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (c == '\\' && !in_single && i + 1 < line.size()) {
      out.push_back(line[++i]);  // drop the backslash, keep what it escaped
      continue;
    }
    if (c == '\'' && !in_double) { in_single = !in_single; continue; }
    if (c == '"' && !in_single) { in_double = !in_double; continue; }
    out.push_back(c);
  }
  return out;
}

std::string first_match(const std::string &input) {
  // Both readings are tried, and the raw one first: stripping quotes can only
  // add detections, never hide one that the literal text would have caught.
  const std::string stripped = unquote(input);
  std::shared_lock<std::shared_mutex> lock(g_mutex);
  for (const auto &rule : g_compiled) {
    if (std::regex_search(input, rule.second)) return rule.first;
    if (stripped != input && std::regex_search(stripped, rule.second))
      return rule.first;
  }
  return "";
}

}  // namespace ssh_guard
