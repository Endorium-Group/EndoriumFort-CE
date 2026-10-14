// ─── EndoriumFort — SQLite backend for the database seam ────────────────
//
// The default store: a single file, no server, works air-gapped. It is a
// single-writer engine, which is why a deployment that needs several app
// nodes must use the PostgreSQL backend instead.

#include "db_backend.h"

#include <sqlite3.h>

namespace db::detail {
namespace {

class SqliteStatement final : public StatementImpl {
 public:
  explicit SqliteStatement(sqlite3_stmt *stmt) : stmt_(stmt) {}
  ~SqliteStatement() override {
    if (stmt_) sqlite3_finalize(stmt_);
  }

  void bind_int(int index, int value) override {
    sqlite3_bind_int(stmt_, index, value);
  }
  void bind_int64(int index, int64_t value) override {
    sqlite3_bind_int64(stmt_, index, value);
  }
  void bind_text(int index, const std::string &value) override {
    sqlite3_bind_text(stmt_, index, value.c_str(),
                      static_cast<int>(value.size()), SQLITE_TRANSIENT);
  }
  void bind_null(int index) override { sqlite3_bind_null(stmt_, index); }
  void bind_blob(int index, const void *data, int size) override {
    sqlite3_bind_blob(stmt_, index, data, size, SQLITE_TRANSIENT);
  }

  bool step() override { return sqlite3_step(stmt_) == SQLITE_ROW; }
  bool execute() override { return sqlite3_step(stmt_) == SQLITE_DONE; }
  void reset() override {
    sqlite3_reset(stmt_);
    sqlite3_clear_bindings(stmt_);
  }

  int column_int(int index) const override {
    return sqlite3_column_int(stmt_, index);
  }
  int64_t column_int64(int index) const override {
    return sqlite3_column_int64(stmt_, index);
  }
  std::string column_text(int index) const override {
    const unsigned char *text = sqlite3_column_text(stmt_, index);
    return text ? reinterpret_cast<const char *>(text) : std::string();
  }
  std::vector<unsigned char> column_blob(int index) const override {
    const auto *data =
        static_cast<const unsigned char *>(sqlite3_column_blob(stmt_, index));
    const int size = sqlite3_column_bytes(stmt_, index);
    if (!data || size <= 0) return {};
    return std::vector<unsigned char>(data, data + size);
  }
  bool column_is_null(int index) const override {
    return sqlite3_column_type(stmt_, index) == SQLITE_NULL;
  }

 private:
  sqlite3_stmt *stmt_ = nullptr;
};

class SqliteConnection final : public ConnectionImpl {
 public:
  explicit SqliteConnection(sqlite3 *db) : db_(db) {}
  ~SqliteConnection() override {
    if (db_) sqlite3_close(db_);
  }

  bool exec(const std::string &sql, std::string &error) override {
    char *errmsg = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errmsg) != SQLITE_OK) {
      if (errmsg) {
        error = errmsg;
        sqlite3_free(errmsg);
      } else {
        error = "database exec failed";
      }
      return false;
    }
    return true;
  }

  std::unique_ptr<StatementImpl> prepare(const std::string &sql) override {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), static_cast<int>(sql.size()),
                           &stmt, nullptr) != SQLITE_OK) {
      if (stmt) sqlite3_finalize(stmt);
      return nullptr;
    }
    return std::make_unique<SqliteStatement>(stmt);
  }

  int changes() const override { return sqlite3_changes(db_); }

  std::string last_error() const override {
    return db_ ? sqlite3_errmsg(db_) : std::string("no database connection");
  }

  Backend backend() const override { return Backend::Sqlite; }

 private:
  sqlite3 *db_ = nullptr;
};

}  // namespace

std::unique_ptr<ConnectionImpl> open_sqlite(const std::string &path,
                                            std::string &error) {
  sqlite3 *db = nullptr;
  if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
    error = db ? sqlite3_errmsg(db) : "cannot open database";
    if (db) sqlite3_close(db);
    return nullptr;
  }
  return std::make_unique<SqliteConnection>(db);
}

}  // namespace db::detail
