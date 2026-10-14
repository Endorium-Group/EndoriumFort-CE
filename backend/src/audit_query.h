// ─── EndoriumFort — audit log search ────────────────────────────────────────
// Reads the on-disk audit log (active file + rotated archives), newest first,
// with filters and cursor paging. The file is the source of truth: the
// in-memory buffer only holds the last events since the server started.
//
// Cursor: "<file id>:<line>", the file id being the start of the SHA-256 of the
// file's first line. Lines are never moved or rewritten, so a cursor stays valid
// when the active file is rotated into an archive; it expires only when its
// archive is purged by the retention policy.
#pragma once

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

struct AuditQuery {
  int limit = 50;           // 1..500
  std::string cursor;       // continue after this event ("" = newest)
  std::string actor;        // exact
  std::string family;       // "session" matches session.*, or an exact type
  std::string category;     // "" | "failure" | "admin"
  std::string from;         // ISO date or date-time, inclusive
  std::string to;           // ISO date (whole day) or date-time, inclusive
  std::string text;         // case-insensitive, anywhere in the event
  int sessionId = 0;        // payload.sessionId
  bool facets = false;      // also list every actor and family in the log
};

struct AuditRow {
  std::string key;          // unique: the cursor of this line
  int id = 0;               // per-boot counter, not unique across restarts
  std::string type;
  std::string actor;
  std::string role;
  std::string createdAt;
  std::string payloadRaw;   // JSON text, or the plain string
  bool payloadIsJson = false;
};

struct AuditPage {
  std::vector<AuditRow> items;
  std::string next;         // cursor of the following page, "" at the end
  bool cursorExpired = false;
  std::set<std::string> actors;    // with facets
  std::set<std::string> families;  // with facets
};

// Parse the query string values; returns false with a message when invalid.
bool parse_audit_query(const char *limit, const char *cursor, const char *actor,
                       const char *family, const char *category,
                       const char *from, const char *to, const char *text,
                       const char *session, const char *facets,
                       AuditQuery &out, std::string &error);

// The active log and its archives ("<path>.<epoch>"), newest first.
std::vector<std::string> audit_log_files(const std::string &active_path);

// Search `files` (newest first). `active_size` caps how much of files[0] is
// read, so a line being appended concurrently is never half-read.
AuditPage query_audit_files(const std::vector<std::string> &files,
                            std::optional<uint64_t> active_size,
                            const AuditQuery &query);

// Same families as the Journal page's quick filters.
bool audit_type_is_failure(const std::string &type);
bool audit_type_is_admin(const std::string &type);
