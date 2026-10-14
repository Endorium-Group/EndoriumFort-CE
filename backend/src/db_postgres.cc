// ─── EndoriumFort — PostgreSQL backend for the database seam ────────────
//
// Production store: a real server, so several app nodes can share it (which a
// single-writer SQLite file cannot support).
//
// Two things differ from SQLite and are handled here so call sites stay
// identical:
//   * Placeholders. The codebase writes ?1, ?2 ...; PostgreSQL wants $1, $2 ...
//     translate_placeholders() rewrites them, skipping quoted literals.
//   * Execution model. libpq has no row-at-a-time cursor like sqlite3_step():
//     a statement runs once and returns the whole result, which we then walk.
//     So the first step()/execute() sends the query and later step() calls just
//     advance the row index.

#include "db_backend.h"

#include <libpq-fe.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace db::detail {
namespace {

// Rewrite ?N into $N. Text inside single quotes is copied verbatim so a literal
// containing '?' is never touched. A bare '?' (no digits) is numbered in order
// of appearance, which matches SQLite's positional behaviour.
std::string translate_placeholders(const std::string &sql) {
  std::string out;
  out.reserve(sql.size() + 8);
  int next_positional = 0;
  bool in_literal = false;

  for (size_t i = 0; i < sql.size(); ++i) {
    const char c = sql[i];
    if (in_literal) {
      out.push_back(c);
      // '' inside a literal is an escaped quote, not the end of it.
      if (c == '\'') {
        if (i + 1 < sql.size() && sql[i + 1] == '\'') {
          out.push_back(sql[++i]);
        } else {
          in_literal = false;
        }
      }
      continue;
    }
    if (c == '\'') {
      in_literal = true;
      out.push_back(c);
      continue;
    }
    if (c != '?') {
      out.push_back(c);
      continue;
    }
    size_t j = i + 1;
    std::string digits;
    while (j < sql.size() && sql[j] >= '0' && sql[j] <= '9') digits.push_back(sql[j++]);
    if (digits.empty()) {
      digits = std::to_string(++next_positional);
    } else {
      i = j - 1;
    }
    out.push_back('$');
    out += digits;
  }
  return out;
}

class PgStatement final : public StatementImpl {
 public:
  PgStatement(PGconn *conn, std::string sql, int *changes_out)
      : conn_(conn), sql_(std::move(sql)), changes_out_(changes_out) {}

  ~PgStatement() override { clear_result(); }

  void bind_int(int index, int value) override {
    set_param(index, std::to_string(value), /*binary=*/false);
  }
  void bind_int64(int index, int64_t value) override {
    set_param(index, std::to_string(value), /*binary=*/false);
  }
  void bind_text(int index, const std::string &value) override {
    set_param(index, value, /*binary=*/false);
  }
  void bind_null(int index) override {
    ensure_slot(index);
    params_[index - 1].is_null = true;
  }
  void bind_blob(int index, const void *data, int size) override {
    const char *bytes = static_cast<const char *>(data);
    if (!bytes || size <= 0) {
      bind_null(index);
      return;
    }
    set_param(index, std::string(bytes, static_cast<size_t>(size)),
              /*binary=*/true);
  }

  // The query runs on the first call; later calls just walk the stored rows.
  bool step() override {
    if (!result_ && !run()) return false;
    if (row_ + 1 >= PQntuples(result_)) return false;
    ++row_;
    return true;
  }

  bool execute() override { return run(); }

  void reset() override {
    clear_result();
    for (auto &p : params_) {
      p.value.clear();
      p.is_null = true;
      p.binary = false;
    }
    row_ = -1;
  }

  int column_int(int index) const override {
    const char *v = raw(index);
    return v ? std::atoi(v) : 0;
  }
  int64_t column_int64(int index) const override {
    const char *v = raw(index);
    return v ? static_cast<int64_t>(std::strtoll(v, nullptr, 10)) : 0;
  }
  std::string column_text(int index) const override {
    const char *v = raw(index);
    return v ? std::string(v) : std::string();
  }
  std::vector<unsigned char> column_blob(int index) const override {
    const char *v = raw(index);
    if (!v) return {};
    // BYTEA comes back in text form (\x...); unescape it to raw bytes.
    size_t len = 0;
    unsigned char *bytes = PQunescapeBytea(
        reinterpret_cast<const unsigned char *>(v), &len);
    if (!bytes) return {};
    std::vector<unsigned char> out(bytes, bytes + len);
    PQfreemem(bytes);
    return out;
  }
  bool column_is_null(int index) const override {
    if (!result_ || row_ < 0 || row_ >= PQntuples(result_)) return true;
    if (index < 0 || index >= PQnfields(result_)) return true;
    return PQgetisnull(result_, row_, index) == 1;
  }

 private:
  struct Param {
    std::string value;
    bool is_null = true;
    bool binary = false;
  };

  void ensure_slot(int index) {
    if (index < 1) return;
    if (static_cast<size_t>(index) > params_.size()) params_.resize(index);
  }

  void set_param(int index, std::string value, bool binary) {
    ensure_slot(index);
    if (index < 1) return;
    Param &p = params_[index - 1];
    p.value = std::move(value);
    p.is_null = false;
    p.binary = binary;
  }

  const char *raw(int index) const {
    if (!result_ || row_ < 0 || row_ >= PQntuples(result_)) return nullptr;
    if (index < 0 || index >= PQnfields(result_)) return nullptr;
    if (PQgetisnull(result_, row_, index)) return nullptr;
    return PQgetvalue(result_, row_, index);
  }

  bool run() {
    clear_result();
    const int n = static_cast<int>(params_.size());
    std::vector<const char *> values(n, nullptr);
    std::vector<int> lengths(n, 0);
    std::vector<int> formats(n, 0);
    for (int i = 0; i < n; ++i) {
      if (params_[i].is_null) continue;
      values[i] = params_[i].value.c_str();
      lengths[i] = static_cast<int>(params_[i].value.size());
      formats[i] = params_[i].binary ? 1 : 0;
    }

    result_ = PQexecParams(conn_, sql_.c_str(), n, nullptr,
                           n ? values.data() : nullptr,
                           n ? lengths.data() : nullptr,
                           n ? formats.data() : nullptr, /*resultFormat=*/0);
    row_ = -1;
    if (!result_) return false;

    const ExecStatusType status = PQresultStatus(result_);
    if (status != PGRES_TUPLES_OK && status != PGRES_COMMAND_OK) {
      clear_result();
      return false;
    }
    if (changes_out_) {
      const char *affected = PQcmdTuples(result_);
      *changes_out_ = (affected && *affected) ? std::atoi(affected) : 0;
    }
    return true;
  }

  void clear_result() {
    if (result_) {
      PQclear(result_);
      result_ = nullptr;
    }
  }

  PGconn *conn_ = nullptr;
  std::string sql_;
  int *changes_out_ = nullptr;
  std::vector<Param> params_;
  PGresult *result_ = nullptr;
  int row_ = -1;
};

class PgConnection final : public ConnectionImpl {
 public:
  explicit PgConnection(PGconn *conn) : conn_(conn) {}
  ~PgConnection() override {
    if (conn_) PQfinish(conn_);
  }

  bool exec(const std::string &sql, std::string &error) override {
    PGresult *res = PQexec(conn_, sql.c_str());
    if (!res) {
      error = last_error();
      return false;
    }
    const ExecStatusType status = PQresultStatus(res);
    const bool ok = status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK;
    if (!ok) error = PQresultErrorMessage(res);
    PQclear(res);
    return ok;
  }

  std::unique_ptr<StatementImpl> prepare(const std::string &sql) override {
    if (!conn_ || PQstatus(conn_) != CONNECTION_OK) return nullptr;
    return std::make_unique<PgStatement>(conn_, translate_placeholders(sql),
                                         &changes_);
  }

  int changes() const override { return changes_; }

  std::string last_error() const override {
    if (!conn_) return "no database connection";
    const char *msg = PQerrorMessage(conn_);
    return msg ? std::string(msg) : std::string();
  }

  Backend backend() const override { return Backend::Postgres; }

 private:
  PGconn *conn_ = nullptr;
  int changes_ = 0;
};

}  // namespace

std::unique_ptr<ConnectionImpl> open_postgres(const std::string &dsn,
                                              std::string &error) {
  // libpq waits indefinitely by default, so an unreachable server would hang
  // startup instead of failing. A bounded wait lets the process exit and be
  // restarted, which is how a database that is not up yet resolves itself.
  // Only applied when the caller has not set its own value.
  std::string effective = dsn;
  if (effective.find("connect_timeout") == std::string::npos) {
    effective += (effective.find('?') == std::string::npos) ? "?" : "&";
    effective += "connect_timeout=10";
  }

  PGconn *conn = PQconnectdb(effective.c_str());
  if (!conn) {
    error = "cannot allocate PostgreSQL connection";
    return nullptr;
  }
  if (PQstatus(conn) != CONNECTION_OK) {
    const char *msg = PQerrorMessage(conn);
    error = msg ? msg : "PostgreSQL connection failed";
    PQfinish(conn);
    return nullptr;
  }
  return std::make_unique<PgConnection>(conn);
}

}  // namespace db::detail
