#include "reporting.h"

#include "audit_query.h"
#include "crow.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <functional>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace {

// A report never reads more than this many lines. A log that large means the
// retention policy is not rotating; answering a partial report (flagged as
// truncated) beats holding a worker for minutes.
constexpr int kMaxScanLines = 2000000;
constexpr int kMaxTop = 50;

struct Civil {
  int y = 0, m = 0, d = 0;
};

bool leap_year(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

int days_in_month(int y, int m) {
  static const int table[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (m < 1 || m > 12) return 0;
  if (m == 2 && leap_year(y)) return 29;
  return table[m - 1];
}

std::string pad2(int value) {
  return (value < 10 ? "0" : "") + std::to_string(value);
}

std::string iso_date(const Civil &c) {
  return std::to_string(c.y) + "-" + pad2(c.m) + "-" + pad2(c.d);
}

Civil previous_day(Civil c) {
  if (c.d > 1) {
    --c.d;
    return c;
  }
  if (c.m > 1) --c.m;
  else {
    c.m = 12;
    --c.y;
  }
  c.d = days_in_month(c.y, c.m);
  return c;
}

Civil next_day(Civil c) {
  if (c.d < days_in_month(c.y, c.m)) {
    ++c.d;
    return c;
  }
  c.d = 1;
  if (c.m < 12) ++c.m;
  else {
    c.m = 1;
    ++c.y;
  }
  return c;
}

std::string today_utc() {
  const std::time_t now = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &now);
#else
  gmtime_r(&now, &utc);
#endif
  return std::to_string(utc.tm_year + 1900) + "-" + pad2(utc.tm_mon + 1) + "-" +
         pad2(utc.tm_mday);
}

// "2026-10-30", "2026-10" (→ day 1) or "2026" (→ January 1st).
bool parse_anchor(const std::string &text, Civil &out) {
  static const std::regex re(R"(^(\d{4})(?:-(\d{2})(?:-(\d{2}))?)?$)");
  std::smatch match;
  if (!std::regex_match(text, match, re)) return false;
  out.y = std::atoi(match[1].str().c_str());
  out.m = match[2].matched ? std::atoi(match[2].str().c_str()) : 1;
  out.d = match[3].matched ? std::atoi(match[3].str().c_str()) : 1;
  if (out.y < 1970 || out.y > 9999) return false;
  if (out.m < 1 || out.m > 12) return false;
  if (out.d < 1 || out.d > days_in_month(out.y, out.m)) return false;
  return true;
}

ReportWindow window_of(const std::string &period, const Civil &anchor) {
  ReportWindow w;
  Civil first = anchor, last = anchor;
  if (period == "day") {
    w.label = iso_date(anchor);
  } else if (period == "month") {
    first.d = 1;
    last.d = days_in_month(last.y, last.m);
    w.label = std::to_string(anchor.y) + "-" + pad2(anchor.m);
  } else if (period == "quarter") {
    const int quarter = (anchor.m - 1) / 3;  // 0..3
    first.m = quarter * 3 + 1;
    first.d = 1;
    last.m = quarter * 3 + 3;
    last.d = days_in_month(last.y, last.m);
    w.label = std::to_string(anchor.y) + "-Q" + std::to_string(quarter + 1);
  } else {  // year
    first.m = 1;
    first.d = 1;
    last.m = 12;
    last.d = 31;
    w.label = std::to_string(anchor.y);
  }
  w.from = iso_date(first) + "T00:00:00Z";
  w.to = iso_date(last) + "T23:59:59Z";
  w.anchor = iso_date(first);
  return w;
}

// The day just before a window starts, which always falls in the period before.
Civil day_before(const ReportWindow &w) {
  Civil start{};
  parse_anchor(w.anchor, start);
  return previous_day(start);
}

std::string bucket_unit_of(const std::string &period) {
  if (period == "day") return "hour";
  if (period == "year") return "month";
  return "day";  // month and quarter
}

// Every bucket of the window, in order, so the chart shows the quiet slots too.
std::vector<std::string> bucket_labels(const std::string &period,
                                       const ReportWindow &w) {
  std::vector<std::string> labels;
  if (period == "day") {
    for (int hour = 0; hour < 24; ++hour) labels.push_back(pad2(hour) + ":00");
    return labels;
  }
  if (period == "year") {
    const std::string year = w.from.substr(0, 4);
    for (int month = 1; month <= 12; ++month) labels.push_back(year + "-" + pad2(month));
    return labels;
  }
  Civil day{};
  parse_anchor(w.anchor, day);
  const std::string last = w.to.substr(0, 10);
  for (std::string date = iso_date(day); date <= last; date = iso_date(day)) {
    labels.push_back(date);
    day = next_day(day);
  }
  return labels;
}

// Which bucket an event belongs to, from its createdAt.
std::string bucket_key(const std::string &period, const std::string &created_at) {
  if (created_at.size() < 13) return std::string();
  if (period == "day") return created_at.substr(11, 2) + ":00";
  if (period == "year") return created_at.substr(0, 7);
  return created_at.substr(0, 10);
}

bool is_sign_in(const std::string &type) {
  return type == "auth.login.success" || type == "auth.login.ldap.success" ||
         type == "auth.login.sso.success";
}

bool is_sign_in_failure(const std::string &type) {
  return type == "auth.login.failure" || type == "auth.login.2fa_failure" ||
         type == "auth.login.ldap.failure" || type == "auth.login.sso.failure" ||
         type == "auth.login.rate_limited";
}

bool is_session_close(const std::string &type) {
  return type == "session.close" || type == "session.terminate" ||
         type == "session.expire";
}

bool is_session_blocked(const std::string &type) {
  return type == "session.create.blocked.containment" ||
         type == "session.create.unjustified" ||
         type.rfind("access.denied.", 0) == 0;
}

std::string family_of(const std::string &type) {
  return type.substr(0, type.find('.'));
}

// What the event was about, in the payload's own words. Resource names are not
// resolved here: reporting reads the log, not the live resource table.
std::string target_of(const std::string &payload_raw) {
  auto json = crow::json::load(payload_raw);
  if (!json || json.t() != crow::json::type::Object) return std::string();
  for (const char *key : {"resourceName", "target", "subject", "username", "requester"}) {
    if (json.has(key) && json[key].t() == crow::json::type::String) {
      std::string value = json[key].s();
      if (!value.empty()) return value;
    }
  }
  if (json.has("resourceId")) {
    const auto &id = json["resourceId"];
    if (id.t() == crow::json::type::Number)
      return "resource #" + std::to_string(id.i());
  }
  return std::string();
}

void count_event(ReportTotals &totals, const std::string &type) {
  ++totals.events;
  if (audit_type_is_failure(type)) ++totals.failures;
  if (audit_type_is_admin(type)) ++totals.adminActions;
  if (is_sign_in(type)) ++totals.signIns;
  if (is_sign_in_failure(type)) ++totals.signInFailures;
  if (type == "session.create") ++totals.sessionsOpened;
  if (is_session_close(type)) ++totals.sessionsClosed;
  if (is_session_blocked(type)) ++totals.sessionsBlocked;
  if (type == "access_request.create") ++totals.accessRequests;
  if (type == "access_request.approve") ++totals.accessApproved;
  if (type == "access_request.deny") ++totals.accessDenied;
  if (type == "command_guard.block") ++totals.commandBlocks;
  if (type == "security.incident.opened") ++totals.incidents;
}

// The `top` busiest entries, ties broken by name so the output is stable.
std::vector<ReportCount> top_of(const std::unordered_map<std::string, int> &tally,
                                int top) {
  std::vector<ReportCount> items;
  items.reserve(tally.size());
  for (const auto &entry : tally) items.push_back({entry.first, entry.second});
  std::sort(items.begin(), items.end(), [](const ReportCount &a, const ReportCount &b) {
    if (a.count != b.count) return a.count > b.count;
    return a.name < b.name;
  });
  if (top > 0 && static_cast<int>(items.size()) > top) items.resize(static_cast<size_t>(top));
  return items;
}

// Each complete line of `path`, oldest first. `cap` bounds how many bytes are
// read; `visit` returning false stops the walk.
void for_each_line(const std::string &path, std::optional<uint64_t> cap,
                   const std::function<bool(const std::string &)> &visit) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return;
  uint64_t read = 0;
  std::string line;
  while (std::getline(in, line)) {
    read += line.size() + 1;  // the newline std::getline consumed
    if (cap && read > *cap) return;  // a line being appended: leave it out
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (!visit(line)) return;
  }
}

std::string first_line_of(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  std::string line;
  if (in) std::getline(in, line);
  if (!line.empty() && line.back() == '\r') line.pop_back();
  return line;
}

// Excel and Sheets read a leading = + - @ as a formula, even inside quotes.
std::string csv_cell(const std::string &value) {
  std::string raw = value;
  if (!raw.empty() && std::string("=+-@\t\r").find(raw.front()) != std::string::npos)
    raw.insert(raw.begin(), '\'');
  std::string out = "\"";
  for (const char c : raw) {
    if (c == '"') out += "\"\"";
    else out += c;
  }
  return out + "\"";
}

void csv_row(std::ostringstream &out, const std::string &section,
             const std::string &label, const std::string &value) {
  out << csv_cell(section) << ',' << csv_cell(label) << ',' << csv_cell(value) << "\r\n";
}

void csv_totals(std::ostringstream &out, const std::string &section,
                const ReportTotals &t) {
  const std::pair<const char *, int> rows[] = {
      {"events", t.events},
      {"failures", t.failures},
      {"adminActions", t.adminActions},
      {"signIns", t.signIns},
      {"signInFailures", t.signInFailures},
      {"sessionsOpened", t.sessionsOpened},
      {"sessionsClosed", t.sessionsClosed},
      {"sessionsBlocked", t.sessionsBlocked},
      {"accessRequests", t.accessRequests},
      {"accessApproved", t.accessApproved},
      {"accessDenied", t.accessDenied},
      {"commandBlocks", t.commandBlocks},
      {"incidents", t.incidents},
      {"uniqueActors", t.uniqueActors},
      {"uniqueTargets", t.uniqueTargets}};
  for (const auto &row : rows) csv_row(out, section, row.first, std::to_string(row.second));
}

}  // namespace

bool parse_report_query(const char *period, const char *date, const char *top,
                        ReportQuery &out, std::string &error) {
  out = ReportQuery{};
  std::string wanted = period && *period ? period : "day";
  // The UI speaks of daily/monthly/quarterly/annual reports; accept both forms.
  static const std::unordered_map<std::string, std::string> aliases = {
      {"day", "day"},         {"daily", "day"},
      {"month", "month"},     {"monthly", "month"},
      {"quarter", "quarter"}, {"quarterly", "quarter"},
      {"year", "year"},       {"yearly", "year"},
      {"annual", "year"},     {"annually", "year"}};
  const auto found = aliases.find(wanted);
  if (found == aliases.end()) {
    error = "period must be day, month, quarter or year";
    return false;
  }
  out.period = found->second;

  Civil anchor{};
  const std::string text = date && *date ? date : today_utc();
  if (!parse_anchor(text, anchor)) {
    error = "date must look like 2026-10-13, 2026-10 or 2026";
    return false;
  }
  out.anchor = iso_date(anchor);

  if (top && *top) {
    char *end = nullptr;
    const long value = std::strtol(top, &end, 10);
    if (*end || value < 1 || value > kMaxTop) {
      error = "top must be between 1 and 50";
      return false;
    }
    out.top = static_cast<int>(value);
  }
  return true;
}

ReportWindow report_window(const ReportQuery &query) {
  Civil anchor{};
  if (!parse_anchor(query.anchor.empty() ? today_utc() : query.anchor, anchor))
    parse_anchor(today_utc(), anchor);
  return window_of(query.period, anchor);
}

ReportWindow report_previous_window(const ReportQuery &query) {
  return window_of(query.period, day_before(report_window(query)));
}

Report build_report(const std::vector<std::string> &files,
                    std::optional<uint64_t> active_size,
                    const ReportQuery &query) {
  Report report;
  report.window = report_window(query);
  report.previous = report_previous_window(query);
  report.bucketUnit = bucket_unit_of(query.period);

  std::unordered_map<std::string, size_t> bucket_index;
  for (const auto &label : bucket_labels(query.period, report.window)) {
    bucket_index.emplace(label, report.buckets.size());
    ReportBucket bucket;
    bucket.label = label;
    report.buckets.push_back(bucket);
  }

  // Everything from the previous period's start to this one's end is read; the
  // previous period only feeds the comparison totals.
  const std::string scan_from = report.previous.from;
  const std::string scan_to = report.window.to;

  std::unordered_map<std::string, int> actors, targets, types, families;
  std::unordered_set<std::string> previous_actors, previous_targets;
  AuditRow row;

  for (size_t i = 0; i < files.size(); ++i) {
    const std::string oldest = first_line_of(files[i]);
    AuditRow head;
    const bool head_ok = parse_audit_line(oldest, head);
    // Lines inside one file run oldest to newest, and audit_log_files() hands
    // them over newest file first.
    if (head_ok && head.createdAt > scan_to) continue;  // wholly after the window
    ++report.scannedFiles;
    for_each_line(files[i], i == 0 ? active_size : std::nullopt,
                  [&](const std::string &line) {
      if (report.scannedLines >= kMaxScanLines) {
        report.truncated = true;
        return false;
      }
      ++report.scannedLines;
      if (!parse_audit_line(line, row)) return true;
      if (row.createdAt < scan_from || row.createdAt > scan_to) return true;

      const bool current = row.createdAt >= report.window.from;
      if (!current) {
        count_event(report.previousTotals, row.type);
        if (!row.actor.empty()) previous_actors.insert(row.actor);
        const std::string target = row.payloadIsJson ? target_of(row.payloadRaw) : std::string();
        if (!target.empty()) previous_targets.insert(target);
        return true;
      }

      count_event(report.totals, row.type);
      if (report.firstEventAt.empty() || row.createdAt < report.firstEventAt)
        report.firstEventAt = row.createdAt;
      if (row.createdAt > report.lastEventAt) report.lastEventAt = row.createdAt;
      if (!row.actor.empty()) ++actors[row.actor];
      if (!row.type.empty()) {
        ++types[row.type];
        ++families[family_of(row.type)];
      }
      const std::string target = row.payloadIsJson ? target_of(row.payloadRaw) : std::string();
      if (!target.empty()) ++targets[target];

      const auto bucket = bucket_index.find(bucket_key(query.period, row.createdAt));
      if (bucket != bucket_index.end()) {
        auto &slot = report.buckets[bucket->second];
        ++slot.events;
        if (row.type == "session.create") ++slot.sessions;
        if (audit_type_is_failure(row.type)) ++slot.failures;
      }
      return true;
    });
    if (report.truncated) break;
    // This file reaches back before the window: every older archive is too.
    if (head_ok && head.createdAt < scan_from) break;
  }

  report.totals.uniqueActors = static_cast<int>(actors.size());
  report.totals.uniqueTargets = static_cast<int>(targets.size());
  report.previousTotals.uniqueActors = static_cast<int>(previous_actors.size());
  report.previousTotals.uniqueTargets = static_cast<int>(previous_targets.size());
  report.topActors = top_of(actors, query.top);
  report.topTargets = top_of(targets, query.top);
  report.topEvents = top_of(types, query.top);
  report.families = top_of(families, 0);
  return report;
}

std::string report_to_csv(const Report &report) {
  std::ostringstream out;
  out << "\xEF\xBB\xBF";  // BOM: Excel reads the UTF-8 accents right
  out << "section,label,value\r\n";
  csv_row(out, "period", "label", report.window.label);
  csv_row(out, "period", "from", report.window.from);
  csv_row(out, "period", "to", report.window.to);
  csv_row(out, "period", "previous", report.previous.label);
  csv_row(out, "period", "firstEventAt", report.firstEventAt);
  csv_row(out, "period", "lastEventAt", report.lastEventAt);
  csv_row(out, "period", "truncated", report.truncated ? "true" : "false");
  csv_totals(out, "total", report.totals);
  csv_totals(out, "previousTotal", report.previousTotals);
  for (const auto &bucket : report.buckets) {
    csv_row(out, report.bucketUnit, bucket.label, std::to_string(bucket.events));
    csv_row(out, report.bucketUnit + ".sessions", bucket.label, std::to_string(bucket.sessions));
    csv_row(out, report.bucketUnit + ".failures", bucket.label, std::to_string(bucket.failures));
  }
  for (const auto &item : report.topActors) csv_row(out, "topActor", item.name, std::to_string(item.count));
  for (const auto &item : report.topTargets) csv_row(out, "topTarget", item.name, std::to_string(item.count));
  for (const auto &item : report.topEvents) csv_row(out, "topEvent", item.name, std::to_string(item.count));
  for (const auto &item : report.families) csv_row(out, "family", item.name, std::to_string(item.count));
  return out.str();
}
