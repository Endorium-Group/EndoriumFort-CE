#pragma once
// Internal factory declarations shared by the database seam and its backends.
// Not included by call sites — they only ever see database.h.

#include "database.h"

#include <memory>
#include <string>

namespace db::detail {

std::unique_ptr<ConnectionImpl> open_sqlite(const std::string &path,
                                            std::string &error);

#ifdef ENDORIUMFORT_POSTGRES
std::unique_ptr<ConnectionImpl> open_postgres(const std::string &dsn,
                                              std::string &error);
#endif

}  // namespace db::detail
