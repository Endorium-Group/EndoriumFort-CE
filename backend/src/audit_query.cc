#include "audit_query.h"

#include "crow.h"
#include "crypto.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <regex>
#include <sstream>

namespace {

constexpr int kMaxLimit = 500;
constexpr char kPrevMarker[] = ",\"prevHash\":\"";
constexpr char kPayloadKey[] = "\"payload\":";

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

bool valid_date(const std::string &s) {
  static const std::regex re(R"(^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z?)?$)");
  return std::regex_match(s, re);
}

// Identity of a log file: survives the rename of the active file into an archive.
std::string file_id(const std::string &first_line) {
  return crypto::sha256_hex(first_line).substr(0, 16);
}

// Whole file (or its first `cap` bytes) split into lines; a trailing partial
// line (no newline yet) is dropped.
std::vector<std::string> read_lines(const std::string &path, std::optional<uint64_t> cap) {
  std::vector<std::string> lines;
  std::ifstream in(path, std::ios::binary);
  if (!in) return lines;
  std::string data;
  if (cap) {
    data.resize(static_cast<size_t>(*cap));
    in.read(&data[0], static_cast<std::streamsize>(*cap));
    data.resize(static_cast<size_t>(in.gcount()));
  } else {
    data.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  }
  size_t start = 0;
  while (start < data.size()) {
    const size_t nl = data.find('\n', start);
    if (nl == std::string::npos) break;  // incomplete last line
    std::string line = data.substr(start, nl - start);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    lines.push_back(std::move(line));
    start = nl + 1;
  }
  return lines;
}

std::string first_line_of(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  std::string line;
  if (in) std::getline(in, line);
  if (!line.empty() && line.back() == '\r') line.pop_back();
  return line;
}

// One log line → row; false for blank or unreadable lines.
bool parse_line(const std::string &line, AuditRow &row, crow::json::rvalue &json) {
  if (line.empty() || line.front() != '{') return false;
  const size_t pp = line.rfind(kPrevMarker);
  // Chained lines carry prevHash/hash after the canonical entry; older lines
  // are the canonical entry alone.
  const std::string canonical = pp == std::string::npos ? line : line.substr(0, pp) + "}";
  json = crow::json::load(canonical);
  if (!json || json.t() != crow::json::type::Object) return false;
  auto str = [&json](const char *key) {
    return json.has(key) && json[key].t() == crow::json::type::String ? std::string(json[key].s())
                                                                      : std::string();
  };
  row.type = str("type");
  row.actor = str("actor");
  row.role = str("role");
  row.createdAt = str("createdAt");
  row.id = json.has("id") && json["id"].t() == crow::json::type::Number ? static_cast<int>(json["id"].i()) : 0;
  row.payloadRaw.clear();
  row.payloadIsJson = false;
  if (json.has("payload")) {
    const auto &payload = json["payload"];
    if (payload.t() == crow::json::type::String) {
      row.payloadRaw = payload.s();
    } else {
      const size_t at = canonical.find(kPayloadKey);
      if (at != std::string::npos) {
        const size_t begin = at + sizeof(kPayloadKey) - 1;
        row.payloadRaw = canonical.substr(begin, canonical.size() - 1 - begin);
        row.payloadIsJson = true;
      }
    }
  }
  return true;
}

std::string family_of(const std::string &type) { return type.substr(0, type.find('.')); }

bool matches(const AuditQuery &q, const AuditRow &row, const crow::json::rvalue &json,
             const std::string &line_lower, const std::string &from, const std::string &to) {
  if (!q.actor.empty() && row.actor != q.actor) return false;
  if (!q.family.empty() && family_of(row.type) != q.family && row.type != q.family) return false;
  if (q.category == "failure" && !audit_type_is_failure(row.type)) return false;
  if (q.category == "admin" && !audit_type_is_admin(row.type)) return false;
  if (!from.empty() && row.createdAt < from) return false;
  if (!to.empty() && row.createdAt > to) return false;
  if (q.sessionId > 0) {
    if (!json.has("payload") || json["payload"].t() != crow::json::type::Object) return false;
    const auto &payload = json["payload"];
    if (!payload.has("sessionId")) return false;
    const auto &sid = payload["sessionId"];
    const long long value = sid.t() == crow::json::type::Number ? sid.i()
                            : sid.t() == crow::json::type::String ? std::atoll(std::string(sid.s()).c_str())
                                                                  : 0;
    if (value != q.sessionId) return false;
  }
  if (!q.text.empty() && line_lower.find(q.text) == std::string::npos) return false;
  return true;
}

}  // namespace

bool audit_type_is_failure(const std::string &type) {
  static const std::regex re(
      "fail|denied|deny|block|reject|rate_limited|error|unjustified|anomaly|incident|detection|containment");
  return std::regex_search(type, re);
}

bool audit_type_is_admin(const std::string &type) {
  static const std::regex re(
      R"(^(resource|user|access_policy|access_profile|relay|license|integration|cluster|itdr\.rule|automation)\.|^access_request\.(approve|deny)$|^credential\.rotat)");
  return std::regex_search(type, re);
}

bool parse_audit_query(const char *limit, const char *cursor, const char *actor,
                       const char *family, const char *category,
                       const char *from, const char *to, const char *text,
                       const char *session, const char *facets,
                       AuditQuery &out, std::string &error) {
  out = AuditQuery{};
  if (limit && *limit) {
    char *end = nullptr;
    const long value = std::strtol(limit, &end, 10);
    if (*end || value < 1 || value > kMaxLimit) {
      error = "limit must be between 1 and 500";
      return false;
    }
    out.limit = static_cast<int>(value);
  }
  if (cursor) {
    out.cursor = cursor;
    static const std::regex re(R"(^[0-9a-f]{16}:[0-9]+$)");
    if (!out.cursor.empty() && !std::regex_match(out.cursor, re)) {
      error = "invalid cursor";
      return false;
    }
  }
  if (actor) out.actor = actor;
  if (family) out.family = family;
  if (category) {
    out.category = category;
    if (!out.category.empty() && out.category != "failure" && out.category != "admin") {
      error = "category must be failure or admin";
      return false;
    }
  }
  for (auto [raw, field] : {std::pair{from, &out.from}, std::pair{to, &out.to}}) {
    if (!raw || !*raw) continue;
    *field = raw;
    if (!valid_date(*field)) {
      error = "dates must look like 2026-10-13 or 2026-10-13T08:30:00Z";
      return false;
    }
  }
  if (text) out.text = lower(text);
  if (session && *session) {
    out.sessionId = std::atoi(session);
    if (out.sessionId <= 0) {
      error = "invalid session";
      return false;
    }
  }
  out.facets = facets && std::string(facets) == "1";
  return true;
}

std::vector<std::string> audit_log_files(const std::string &active_path) {
  namespace fs = std::filesystem;
  std::vector<std::string> files;
  std::error_code ec;
  if (fs::exists(active_path, ec)) files.push_back(active_path);
  const fs::path logp(active_path);
  const fs::path dir = logp.has_parent_path() ? logp.parent_path() : fs::path(".");
  const std::string prefix = logp.filename().string() + ".";
  std::vector<std::pair<long long, std::string>> archives;
  for (fs::directory_iterator it(dir, ec), end; it != end && !ec; it.increment(ec)) {
    const std::string name = it->path().filename().string();
    if (name.rfind(prefix, 0) != 0) continue;
    const std::string suffix = name.substr(prefix.size());
    if (suffix.empty() || !std::all_of(suffix.begin(), suffix.end(), ::isdigit)) continue;
    archives.emplace_back(std::atoll(suffix.c_str()), it->path().string());
  }
  std::sort(archives.begin(), archives.end(), [](auto &a, auto &b) { return a.first > b.first; });
  for (auto &archive : archives) files.push_back(archive.second);
  return files;
}

AuditPage query_audit_files(const std::vector<std::string> &files,
                            std::optional<uint64_t> active_size,
                            const AuditQuery &query) {
  AuditPage page;
  const std::string from = query.from.size() == 10 ? query.from + "T00:00:00Z" : query.from;
  const std::string to = query.to.size() == 10 ? query.to + "T23:59:59Z" : query.to;

  // Where to start: the file named by the cursor, just above its line.
  size_t first_file = 0;
  long long start_line = -1;  // -1 = from the end of the file
  if (!query.cursor.empty()) {
    const size_t colon = query.cursor.find(':');
    const std::string fid = query.cursor.substr(0, colon);
    const long long line_no = std::atoll(query.cursor.c_str() + colon + 1);
    bool found = false;
    for (size_t i = 0; i < files.size(); ++i) {
      if (file_id(first_line_of(files[i])) == fid) {
        first_file = i;
        start_line = line_no - 1;  // lines are 1-based; continue with the older one
        found = true;
        break;
      }
    }
    if (!found) {
      page.cursorExpired = true;
      return page;
    }
  }

  bool page_full = false;
  AuditRow row;
  crow::json::rvalue json;
  for (size_t i = query.facets ? 0 : first_file; i < files.size(); ++i) {
    const auto lines = read_lines(files[i], i == 0 ? active_size : std::nullopt);
    if (lines.empty()) continue;
    const std::string fid = file_id(lines.front());
    const bool in_page_range = i >= first_file;
    for (long long n = static_cast<long long>(lines.size()); n >= 1; --n) {
      const std::string &line = lines[static_cast<size_t>(n - 1)];
      const bool candidate = in_page_range && !page_full && (i > first_file || start_line < 0 || n <= start_line);
      if (!candidate && !query.facets) continue;
      if (!parse_line(line, row, json)) continue;
      if (query.facets) {
        if (!row.actor.empty()) page.actors.insert(row.actor);
        if (!row.type.empty()) page.families.insert(family_of(row.type));
      }
      if (!candidate || !matches(query, row, json, query.text.empty() ? std::string() : lower(line), from, to))
        continue;
      if (static_cast<int>(page.items.size()) == query.limit) {
        // One more match exists: the page has a successor.
        page.next = page.items.back().key;
        page_full = true;
        if (!query.facets) return page;
        continue;
      }
      row.key = fid + ":" + std::to_string(n);
      page.items.push_back(row);
    }
  }
  return page;
}
