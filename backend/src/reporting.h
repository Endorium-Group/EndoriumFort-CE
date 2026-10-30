// ─── EndoriumFort — periodic reporting ──────────────────────────────────────
// Turns the on-disk audit log into a report over one calendar period: a day, a
// month, a quarter or a year. The log is the source of truth (audit_query.h),
// so a report covers the archives too and never depends on what is still in
// memory since the last restart.
//
// Each report carries the same totals for the period before it, so the UI can
// show a trend without a second request, and per-bucket series (hours of the
// day, days of the month/quarter, months of the year) for the chart.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct ReportQuery {
  std::string period = "day";   // "day" | "month" | "quarter" | "year"
  std::string anchor;           // YYYY-MM-DD inside the period (default: today)
  int top = 10;                 // length of the "top ..." lists, 1..50
};

// The calendar span of a period. `from`/`to` are inclusive ISO date-times in
// the same shape as AuditRow::createdAt, so they compare lexicographically.
struct ReportWindow {
  std::string label;   // "2026-10-30" | "2026-10" | "2026-Q4" | "2026"
  std::string from;    // "2026-10-01T00:00:00Z"
  std::string to;      // "2026-10-31T23:59:59Z"
  std::string anchor;  // first day of the period, YYYY-MM-DD
};

// What every report counts, for the period and for the one before it.
struct ReportTotals {
  int events = 0;
  int failures = 0;         // audit_type_is_failure()
  int adminActions = 0;     // audit_type_is_admin()
  int signIns = 0;          // local, LDAP and SSO sign-ins that succeeded
  int signInFailures = 0;   // wrong password, failed 2FA, rate limiting
  int sessionsOpened = 0;
  int sessionsClosed = 0;
  int sessionsBlocked = 0;  // containment, missing justification, time window
  int accessRequests = 0;
  int accessApproved = 0;
  int accessDenied = 0;
  int commandBlocks = 0;    // SSH command guard
  int incidents = 0;        // security incidents opened
  int uniqueActors = 0;
  int uniqueTargets = 0;
};

struct ReportBucket {
  std::string label;   // "14:00" | "2026-10-07" | "2026-10"
  int events = 0;
  int sessions = 0;
  int failures = 0;
};

struct ReportCount {
  std::string name;
  int count = 0;
};

struct Report {
  ReportWindow window;
  ReportWindow previous;
  ReportTotals totals;
  ReportTotals previousTotals;
  std::string bucketUnit;  // "hour" | "day" | "month"
  std::vector<ReportBucket> buckets;
  std::vector<ReportCount> topActors;
  std::vector<ReportCount> topTargets;
  std::vector<ReportCount> topEvents;    // by event type
  std::vector<ReportCount> families;     // every family seen, busiest first
  std::string firstEventAt;              // oldest event inside the period
  std::string lastEventAt;               // newest event inside the period
  int scannedLines = 0;
  int scannedFiles = 0;
  bool truncated = false;  // the scan limit was reached: totals are partial
};

// Parse the query string values; returns false with a message when invalid.
bool parse_report_query(const char *period, const char *date, const char *top,
                        ReportQuery &out, std::string &error);

// The period `query.anchor` falls in, and the one just before it.
ReportWindow report_window(const ReportQuery &query);
ReportWindow report_previous_window(const ReportQuery &query);

// Aggregate `files` (newest first, as audit_log_files() returns them).
// `active_size` caps how much of files[0] is read, so a line being appended
// concurrently is never half-read. Archives entirely outside the two windows
// are never opened past their first line.
Report build_report(const std::vector<std::string> &files,
                    std::optional<uint64_t> active_size,
                    const ReportQuery &query);

// The report as a CSV document (one "section,label,value" row per figure),
// ready to be served as a file download.
std::string report_to_csv(const Report &report);
