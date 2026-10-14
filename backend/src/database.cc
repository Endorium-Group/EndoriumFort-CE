// ─── EndoriumFort — database seam: backend selection ────────────────────

#include "db_backend.h"

namespace {

bool has_prefix(const std::string &value, const char *prefix) {
  const std::string p(prefix);
  return value.size() >= p.size() && value.compare(0, p.size(), p) == 0;
}

}  // namespace

namespace db {

bool Connection::open(const std::string &dsn, std::string &error) {
  impl_.reset();

  // A URI scheme selects PostgreSQL; everything else is a SQLite file path.
  if (has_prefix(dsn, "postgresql://") || has_prefix(dsn, "postgres://")) {
#ifdef ENDORIUMFORT_POSTGRES
    impl_ = detail::open_postgres(dsn, error);
#else
    error =
        "PostgreSQL DSN given but this build has no PostgreSQL support "
        "(rebuild with -DENDORIUMFORT_POSTGRES=ON)";
    return false;
#endif
  } else {
    impl_ = detail::open_sqlite(dsn, error);
  }

  return impl_ != nullptr;
}

}  // namespace db
