#include "reporting.h"

#include "audit_query.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
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

// A log line as the server writes it, tamper-evidence fields included.
std::string line(int id, const std::string &type, const std::string &actor,
                 const std::string &at, const std::string &payload = "{}") {
  return "{\"id\":" + std::to_string(id) + ",\"type\":\"" + type +
         "\",\"actor\":\"" + actor + "\",\"role\":\"admin\",\"createdAt\":\"" + at +
         "\",\"payload\":" + payload + ",\"prevHash\":\"GENESIS\",\"hash\":\"" +
         std::string(64, 'a') + "\"}\n";
}

void write(const std::string &path, const std::vector<std::string> &lines) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  for (const auto &l : lines) out << l;
}

ReportQuery parsed(const char *period, const char *date = nullptr,
                   const char *top = nullptr) {
  ReportQuery q;
  std::string error;
  parse_report_query(period, date, top, q, error);
  return q;
}

const ReportBucket *bucket(const Report &report, const std::string &label) {
  for (const auto &item : report.buckets)
    if (item.label == label) return &item;
  return nullptr;
}

int count_of(const std::vector<ReportCount> &items, const std::string &name) {
  for (const auto &item : items)
    if (item.name == name) return item.count;
  return 0;
}

}  // namespace

int main() {
  bool ok = true;
  namespace fs = std::filesystem;
  const auto dir = fs::temp_directory_path() / "endoriumfort-reporting-test";
  fs::remove_all(dir);
  fs::create_directories(dir);
  const std::string active = (dir / "audit.jsonl").string();

  // ── The calendar windows ──────────────────────────────────────────────
  {
    const ReportWindow day = report_window(parsed("day", "2026-10-30"));
    ok &= expect(day.label == "2026-10-30", "a day is labelled by its date");
    ok &= expect(day.from == "2026-10-30T00:00:00Z" && day.to == "2026-10-30T23:59:59Z",
                 "a day spans midnight to midnight");

    const ReportWindow month = report_window(parsed("month", "2026-02-17"));
    ok &= expect(month.label == "2026-02", "a month is labelled YYYY-MM");
    ok &= expect(month.from == "2026-02-01T00:00:00Z" && month.to == "2026-02-28T23:59:59Z",
                 "February 2026 ends on the 28th");
    ok &= expect(report_window(parsed("month", "2024-02-17")).to == "2024-02-29T23:59:59Z",
                 "February 2024 ends on the 29th");

    const ReportWindow quarter = report_window(parsed("quarter", "2026-10-30"));
    ok &= expect(quarter.label == "2026-Q4", "October falls in Q4");
    ok &= expect(quarter.from == "2026-10-01T00:00:00Z" && quarter.to == "2026-12-31T23:59:59Z",
                 "Q4 runs October to December");
    ok &= expect(report_window(parsed("quarter", "2026-01-01")).label == "2026-Q1",
                 "January falls in Q1");
    ok &= expect(report_window(parsed("quarter", "2026-09-30")).label == "2026-Q3",
                 "September falls in Q3");

    const ReportWindow year = report_window(parsed("year", "2026-10-30"));
    ok &= expect(year.label == "2026", "a year is labelled by its number");
    ok &= expect(year.from == "2026-01-01T00:00:00Z" && year.to == "2026-12-31T23:59:59Z",
                 "a year spans January to December");
  }

  // ── The period just before, across every boundary ─────────────────────
  {
    ok &= expect(report_previous_window(parsed("day", "2026-01-01")).label == "2025-12-31",
                 "the day before January 1st is in the previous year");
    ok &= expect(report_previous_window(parsed("day", "2026-03-01")).label == "2026-02-28",
                 "the day before March 1st 2026 is February 28th");
    ok &= expect(report_previous_window(parsed("month", "2026-01-15")).label == "2025-12",
                 "the month before January is December of the previous year");
    ok &= expect(report_previous_window(parsed("quarter", "2026-01-15")).label == "2025-Q4",
                 "the quarter before Q1 is the previous year's Q4");
    ok &= expect(report_previous_window(parsed("quarter", "2026-10-15")).label == "2026-Q3",
                 "the quarter before Q4 is Q3");
    ok &= expect(report_previous_window(parsed("year", "2026-06-01")).label == "2025",
                 "the year before 2026 is 2025");
  }

  // ── Shorthand anchors and refused input ───────────────────────────────
  {
    ReportQuery q;
    std::string error;
    ok &= expect(parse_report_query("monthly", "2026-10", nullptr, q, error) &&
                     q.period == "month" && q.anchor == "2026-10-01",
                 "\"monthly\" and a YYYY-MM anchor are accepted");
    ok &= expect(parse_report_query("annual", "2026", nullptr, q, error) &&
                     q.period == "year" && q.anchor == "2026-01-01",
                 "\"annual\" and a YYYY anchor are accepted");
    ok &= expect(parse_report_query(nullptr, nullptr, nullptr, q, error) && q.period == "day",
                 "no period means today's report");
    ok &= expect(!parse_report_query("week", nullptr, nullptr, q, error), "unknown period refused");
    ok &= expect(!parse_report_query("day", "2026-02-30", nullptr, q, error),
                 "February 30th refused");
    ok &= expect(!parse_report_query("day", "last tuesday", nullptr, q, error), "free text refused");
    ok &= expect(!parse_report_query("day", "2026-13-01", nullptr, q, error), "month 13 refused");
    ok &= expect(!parse_report_query("day", nullptr, "0", q, error), "top 0 refused");
    ok &= expect(!parse_report_query("day", nullptr, "51", q, error), "top over 50 refused");
    ok &= expect(parse_report_query("day", nullptr, "3", q, error) && q.top == 3,
                 "top is read from the query");
  }

  // ── Aggregation over one day, against the day before ──────────────────
  write(active, {
    // The previous day: only the comparison totals count these.
    line(1, "auth.login.success", "alice", "2026-10-29T08:00:00Z"),
    line(2, "session.create", "alice", "2026-10-29T08:05:00Z", "{\"resourceName\":\"db-prod\",\"sessionId\":1}"),
    // The day of the report.
    line(3, "auth.login.success", "alice", "2026-10-30T07:30:00Z"),
    line(4, "auth.login.failure", "bob", "2026-10-30T07:45:00Z"),
    line(5, "session.create", "alice", "2026-10-30T09:10:00Z", "{\"resourceName\":\"db-prod\",\"sessionId\":2}"),
    line(6, "session.create", "bob", "2026-10-30T09:40:00Z", "{\"resourceName\":\"web-01\",\"sessionId\":3}"),
    line(7, "session.close", "alice", "2026-10-30T10:00:00Z", "{\"resourceName\":\"db-prod\",\"sessionId\":2}"),
    line(8, "session.create.unjustified", "bob", "2026-10-30T14:00:00Z", "{\"resourceName\":\"db-prod\"}"),
    line(9, "resource.update", "alice", "2026-10-30T14:30:00Z", "{\"resourceName\":\"db-prod\"}"),
    line(10, "access_request.create", "bob", "2026-10-30T15:00:00Z", "{\"resourceName\":\"db-prod\"}"),
    line(11, "access_request.approve", "alice", "2026-10-30T15:05:00Z", "{\"resourceName\":\"db-prod\"}"),
    line(12, "command_guard.block", "bob", "2026-10-30T15:30:00Z", "{\"command\":\"rm -rf /\"}"),
    // The day after: out of both windows.
    line(13, "auth.login.success", "carol", "2026-10-31T08:00:00Z")
  });
  const auto files = audit_log_files(active);
  {
    const Report report = build_report(files, std::nullopt, parsed("day", "2026-10-30"));
    ok &= expect(report.totals.events == 10, "only the day's events are counted");
    ok &= expect(report.totals.signIns == 1 && report.totals.signInFailures == 1,
                 "sign-ins and their failures are told apart");
    ok &= expect(report.totals.sessionsOpened == 2 && report.totals.sessionsClosed == 1,
                 "sessions opened and closed are counted");
    ok &= expect(report.totals.sessionsBlocked == 1, "a session refused for lack of a justification counts as blocked");
    ok &= expect(report.totals.accessRequests == 1 && report.totals.accessApproved == 1 &&
                     report.totals.accessDenied == 0,
                 "access requests and their decisions are counted");
    ok &= expect(report.totals.commandBlocks == 1, "blocked commands are counted");
    ok &= expect(report.totals.adminActions == 2, "the resource change and the approval are administration");
    ok &= expect(report.totals.failures == 3, "the failed sign-in, the refusal and the blocked command are failures");
    ok &= expect(report.totals.uniqueActors == 2, "alice and bob acted that day");
    ok &= expect(report.previousTotals.events == 2 && report.previousTotals.signIns == 1,
                 "the day before feeds the comparison totals");
    ok &= expect(report.previous.label == "2026-10-29", "the comparison period is named");
    ok &= expect(report.firstEventAt == "2026-10-30T07:30:00Z" &&
                     report.lastEventAt == "2026-10-30T15:30:00Z",
                 "the first and last event of the period are reported");
    ok &= expect(!report.truncated, "a small log is not truncated");

    ok &= expect(report.bucketUnit == "hour" && report.buckets.size() == 24,
                 "a day is bucketed into 24 hours");
    const ReportBucket *nine = bucket(report, "09:00");
    ok &= expect(nine && nine->events == 2 && nine->sessions == 2 && nine->failures == 0,
                 "the 9 o'clock bucket holds both session openings");
    const ReportBucket *fifteen = bucket(report, "15:00");
    ok &= expect(fifteen && fifteen->events == 3 && fifteen->failures == 1,
                 "the 15 o'clock bucket holds the blocked command");
    const ReportBucket *midnight = bucket(report, "00:00");
    ok &= expect(midnight && midnight->events == 0, "a quiet hour is still listed, at zero");

    ok &= expect(count_of(report.topActors, "bob") == 5 && count_of(report.topActors, "alice") == 5,
                 "both actors are tallied");
    ok &= expect(report.topActors.front().name == "alice", "equal counts are ordered by name");
    ok &= expect(count_of(report.topTargets, "db-prod") == 6 &&
                     count_of(report.topTargets, "web-01") == 1,
                 "targets come from the payload");
    ok &= expect(count_of(report.topEvents, "session.create") == 2, "event types are tallied");
    ok &= expect(count_of(report.families, "session") == 4 && count_of(report.families, "auth") == 2,
                 "families group the event types");
  }

  // ── The same log over a month, a quarter and a year ───────────────────
  {
    const Report month = build_report(files, std::nullopt, parsed("month", "2026-10-30"));
    ok &= expect(month.totals.events == 13, "the month covers every event of October");
    ok &= expect(month.bucketUnit == "day" && month.buckets.size() == 31,
                 "October is bucketed into its 31 days");
    const ReportBucket *day30 = bucket(month, "2026-10-30");
    ok &= expect(day30 && day30->events == 10, "the 30th keeps its ten events");
    ok &= expect(month.previous.label == "2026-09" && month.previousTotals.events == 0,
                 "September holds nothing");

    const Report quarter = build_report(files, std::nullopt, parsed("quarter", "2026-11-15"));
    ok &= expect(quarter.window.label == "2026-Q4" && quarter.totals.events == 13,
                 "Q4 covers the whole log");
    ok &= expect(quarter.bucketUnit == "day" && quarter.buckets.size() == 92,
                 "Q4 is bucketed into its 92 days");

    const Report year = build_report(files, std::nullopt, parsed("year", "2026-03-01"));
    ok &= expect(year.totals.events == 13, "the year covers the whole log");
    ok &= expect(year.bucketUnit == "month" && year.buckets.size() == 12,
                 "a year is bucketed into 12 months");
    const ReportBucket *october = bucket(year, "2026-10");
    ok &= expect(october && october->events == 13 && october->sessions == 3,
                 "every event of the log falls in October");
  }

  // ── Top lists are capped ──────────────────────────────────────────────
  {
    const Report report = build_report(files, std::nullopt, parsed("day", "2026-10-30", "1"));
    ok &= expect(report.topActors.size() == 1 && report.topEvents.size() == 1,
                 "top=1 keeps only the busiest entry");
    ok &= expect(report.families.size() >= 4, "the family list is never capped");
  }

  // ── The CSV export ────────────────────────────────────────────────────
  {
    const Report report = build_report({active}, std::nullopt, parsed("day", "2026-10-30"));
    const std::string csv = report_to_csv(report);
    ok &= expect(csv.rfind("\xEF\xBB\xBF", 0) == 0, "the CSV opens with a UTF-8 BOM");
    ok &= expect(csv.find("\"period\",\"label\",\"2026-10-30\"") != std::string::npos,
                 "the CSV names its period");
    ok &= expect(csv.find("\"total\",\"sessionsOpened\",\"2\"") != std::string::npos,
                 "the CSV carries the totals");
    ok &= expect(csv.find("\"previousTotal\",\"events\",\"2\"") != std::string::npos,
                 "the CSV carries the comparison totals");
    ok &= expect(csv.find("\"hour\",\"09:00\",\"2\"") != std::string::npos,
                 "the CSV carries the buckets");
    ok &= expect(csv.find("\"topActor\",\"alice\"") != std::string::npos,
                 "the CSV carries the top lists");
  }

  // ── An archive, and the active file's size snapshot ───────────────────
  {
    const std::string archive = active + ".1762000000";
    write(archive, {line(20, "auth.login.success", "dave", "2026-09-15T08:00:00Z"),
                    line(21, "session.create", "dave", "2026-09-15T08:30:00Z")});
    const auto rotated = audit_log_files(active);
    ok &= expect(rotated.size() == 2 && rotated.front() == active,
                 "the active file comes before its archive");
    const Report month = build_report(rotated, std::nullopt, parsed("month", "2026-10-01"));
    ok &= expect(month.previousTotals.events == 2,
                 "September's archive feeds the comparison totals");
    const Report september = build_report(rotated, std::nullopt, parsed("month", "2026-09-01"));
    ok &= expect(september.totals.events == 2 && september.totals.signIns == 1,
                 "the archive is reported on its own");

    // A line being appended must not be half-read: the snapshot caps the file.
    const auto snapshot = static_cast<uint64_t>(fs::file_size(active));
    {
      std::ofstream out(active, std::ios::binary | std::ios::app);
      out << line(30, "session.create", "erin", "2026-10-30T16:00:00Z");
    }
    const Report capped = build_report(rotated, snapshot, parsed("day", "2026-10-30"));
    ok &= expect(capped.totals.events == 10, "lines past the snapshot size are not read");
    const Report full = build_report(rotated, std::nullopt, parsed("day", "2026-10-30"));
    ok &= expect(full.totals.events == 11, "without a cap the new line is read");
  }

  // ── An empty log ──────────────────────────────────────────────────────
  {
    const Report report = build_report({}, std::nullopt, parsed("day", "2026-10-30"));
    ok &= expect(report.totals.events == 0 && report.buckets.size() == 24,
                 "an empty log still answers a full day of empty buckets");
    ok &= expect(report.firstEventAt.empty() && report.scannedFiles == 0,
                 "nothing was scanned");
  }

  // ── A payload that would be read as a formula by a spreadsheet ────────
  {
    const std::string sheet = (dir / "formula.jsonl").string();
    write(sheet, {line(1, "session.create", "=cmd()", "2026-10-30T09:00:00Z",
                       "{\"resourceName\":\"=HYPERLINK(1)\"}")});
    const Report report = build_report({sheet}, std::nullopt, parsed("day", "2026-10-30"));
    const std::string csv = report_to_csv(report);
    ok &= expect(csv.find("\"'=cmd()\"") != std::string::npos,
                 "an actor starting with = is quoted out of formula range");
    ok &= expect(csv.find("\"'=HYPERLINK(1)\"") != std::string::npos,
                 "a target starting with = is quoted out of formula range");
  }

  fs::remove_all(dir);
  if (ok) std::cout << "reporting tests passed" << std::endl;
  return ok ? 0 : 1;
}
