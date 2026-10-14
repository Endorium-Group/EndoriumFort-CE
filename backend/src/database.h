#pragma once
// ─── EndoriumFort — database access seam ────────────────────────────────
//
// Backend-agnostic wrapper over the SQL store. Call sites talk to
// db::Connection / db::Statement and never touch a driver type, so the store
// can be swapped without rewriting every query.
//
// The backend is chosen at RUNTIME from the DSN, so one binary serves both:
//   * "postgresql://..." or "postgres://..."  → PostgreSQL (production, HA)
//   * anything else                           → SQLite file path (default)
//
// Conventions that keep the SQL portable — follow them in new queries:
//   * Parameters are 1-based and the SQL uses NUMBERED placeholders
//     (?1, ?2, ...). The PostgreSQL backend rewrites those to $1, $2, ...
//   * Prefer `ON CONFLICT ... DO NOTHING/DO UPDATE`, which both engines accept.
//     `INSERT OR IGNORE` / `INSERT OR REPLACE` are SQLite-only.
//   * A Statement owns its driver handle and releases it. Call sites must never
//     free anything, and an early `return` cannot leak a statement.

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace db {

// Which engine a Connection is talking to. Schema code uses this for the few
// spots where the DDL genuinely differs (BLOB vs BYTEA).
enum class Backend { None, Sqlite, Postgres };

namespace detail {

// Driver-side statement. Implemented once per backend; no driver type appears
// in this header, so including it does not drag in sqlite3.h or libpq-fe.h.
class StatementImpl {
 public:
  virtual ~StatementImpl() = default;

  virtual void bind_int(int index, int value) = 0;
  virtual void bind_int64(int index, int64_t value) = 0;
  virtual void bind_text(int index, const std::string &value) = 0;
  virtual void bind_null(int index) = 0;
  virtual void bind_blob(int index, const void *data, int size) = 0;

  virtual bool step() = 0;
  virtual bool execute() = 0;
  virtual void reset() = 0;

  virtual int column_int(int index) const = 0;
  virtual int64_t column_int64(int index) const = 0;
  virtual std::string column_text(int index) const = 0;
  virtual std::vector<unsigned char> column_blob(int index) const = 0;
  virtual bool column_is_null(int index) const = 0;
};

class ConnectionImpl {
 public:
  virtual ~ConnectionImpl() = default;
  virtual bool exec(const std::string &sql, std::string &error) = 0;
  virtual std::unique_ptr<StatementImpl> prepare(const std::string &sql) = 0;
  virtual int changes() const = 0;
  virtual std::string last_error() const = 0;
  virtual Backend backend() const = 0;
};

}  // namespace detail

// A prepared statement. Falsy when preparation failed, so the usual shape is:
//   auto stmt = conn.prepare(sql);
//   if (!stmt) return false;
// Every accessor is null-safe, so a falsy statement degrades to no-ops and
// default values rather than crashing.
class Statement {
 public:
  Statement() = default;
  explicit Statement(std::unique_ptr<detail::StatementImpl> impl)
      : impl_(std::move(impl)) {}

  Statement(const Statement &) = delete;
  Statement &operator=(const Statement &) = delete;
  Statement(Statement &&) noexcept = default;
  Statement &operator=(Statement &&) noexcept = default;

  explicit operator bool() const { return impl_ != nullptr; }

  // ── Binding ──────────────────────────────────────────────────────────────
  void bind_int(int index, int value) {
    if (impl_) impl_->bind_int(index, value);
  }
  void bind_int64(int index, int64_t value) {
    if (impl_) impl_->bind_int64(index, value);
  }
  void bind_text(int index, const std::string &value) {
    if (impl_) impl_->bind_text(index, value);
  }
  // Binds SQL NULL for an empty string. Several tables distinguish "absent"
  // (NULL) from "set but blank", and the call sites expressed that with a
  // ternary around bind_null.
  void bind_text_or_null(int index, const std::string &value) {
    if (value.empty()) {
      bind_null(index);
    } else {
      bind_text(index, value);
    }
  }
  void bind_null(int index) {
    if (impl_) impl_->bind_null(index);
  }
  void bind_blob(int index, const void *data, int size) {
    if (impl_) impl_->bind_blob(index, data, size);
  }

  // ── Execution ────────────────────────────────────────────────────────────
  // step() is for queries: true while a row is available.
  bool step() { return impl_ && impl_->step(); }
  // execute() is for statements returning no rows: true when it completed.
  bool execute() { return impl_ && impl_->execute(); }
  // Re-run the same statement with fresh parameters.
  void reset() {
    if (impl_) impl_->reset();
  }

  // ── Column access (0-based, as in SQL result order) ──────────────────────
  int column_int(int index) const { return impl_ ? impl_->column_int(index) : 0; }
  int64_t column_int64(int index) const {
    return impl_ ? impl_->column_int64(index) : 0;
  }
  // Returns "" for SQL NULL, matching how call sites already treat it.
  std::string column_text(int index) const {
    return impl_ ? impl_->column_text(index) : std::string();
  }
  std::vector<unsigned char> column_blob(int index) const {
    return impl_ ? impl_->column_blob(index) : std::vector<unsigned char>();
  }
  bool column_is_null(int index) const {
    return !impl_ || impl_->column_is_null(index);
  }
  // Assigns only when the column is not NULL, so a NULL leaves whatever the
  // destination already held. Several structs rely on this: AccessPolicy
  // defaults riskLevel/mfaRequirement/timeWindow to "any" and approvalMode to
  // "inherit", and overwriting those with "" would change access decisions.
  void column_text_into(int index, std::string &out) const {
    if (!column_is_null(index)) out = column_text(index);
  }

 private:
  std::unique_ptr<detail::StatementImpl> impl_;
};

class Connection {
 public:
  // Guards work that must be atomic across several statements. Call sites lock
  // it directly, as they did with the original wrapper.
  std::mutex mutex;

  Connection() = default;
  Connection(const Connection &) = delete;
  Connection &operator=(const Connection &) = delete;
  ~Connection() = default;

  // Opens the store described by `dsn` (see the header comment for the scheme
  // rules). Returns false and fills `error` when the backend is unavailable or
  // the connection cannot be established.
  bool open(const std::string &dsn, std::string &error);

  void close() { impl_.reset(); }
  bool is_open() const { return impl_ != nullptr; }
  Backend backend() const {
    return impl_ ? impl_->backend() : Backend::None;
  }

  // DDL fragment for an auto-assigning integer primary key.
  // SQLite's "INTEGER PRIMARY KEY" aliases rowid and fills itself in, so rows
  // can omit the column; a plain INTEGER PRIMARY KEY in PostgreSQL generates
  // nothing and such an insert fails on NOT NULL. BY DEFAULT (rather than
  // ALWAYS) keeps the tables whose ids come from AppContext's counters working,
  // since those inserts do supply an explicit id.
  std::string autoinc_pk() const {
    return backend() == Backend::Postgres
               ? "INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY"
               : "INTEGER PRIMARY KEY";
  }

  // Multi-statement DDL / scripts. Not for parameterised queries.
  bool exec(const std::string &sql, std::string &error) {
    if (!impl_) {
      error = "no database connection";
      return false;
    }
    return impl_->exec(sql, error);
  }

  Statement prepare(const std::string &sql) {
    if (!impl_) return Statement();
    return Statement(impl_->prepare(sql));
  }

  // Rows touched by the last statement.
  int changes() const { return impl_ ? impl_->changes() : 0; }

  std::string last_error() const {
    return impl_ ? impl_->last_error() : std::string("no database connection");
  }

 private:
  std::unique_ptr<detail::ConnectionImpl> impl_;
};

}  // namespace db

// Transitional alias kept for the existing AppContext member declaration.
using SqliteDb = db::Connection;
