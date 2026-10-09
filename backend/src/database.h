#pragma once
// ─── EndoriumFort — SQLite database wrapper ─────────────────────────────
// When built against SQLCipher (a drop-in SQLite fork with transparent
// AES-256), setting ENDORIUMFORT_DB_ENCRYPTION_KEY encrypts the database file
// at rest (PCI DSS 3.5 / RGPD art.32 / HDS). The sqlite3_* API is unchanged;
// the key is applied with a PRAGMA right after open. Without a key the file is
// plaintext exactly as before. If a key is set but the binary lacks SQLCipher,
// open() refuses to run rather than silently storing cleartext.

#include <sqlite3.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>

struct SqliteDb {
  sqlite3 *db = nullptr;
  std::mutex mutex;

  bool open(const std::string &path, std::string &error) {
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
      error = sqlite3_errmsg(db ? db : nullptr);
      return false;
    }
    return apply_encryption(path, error);
  }

  bool exec(const std::string &sql, std::string &error) {
    char *errmsg = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errmsg) != SQLITE_OK) {
      if (errmsg) {
        error = errmsg;
        sqlite3_free(errmsg);
      } else {
        error = "SQLite exec failed";
      }
      return false;
    }
    return true;
  }

  ~SqliteDb() {
    if (db) sqlite3_close(db);
  }

 private:
  // ── Encryption helpers (no-ops unless a key is configured) ──────────────

  static bool env_truthy(const char *name) {
    const char *v = std::getenv(name);
    if (!v || !*v) return false;
    std::string s(v);
    for (char &c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s == "1" || s == "true" || s == "yes" || s == "on";
  }

  // True when linked against SQLCipher (PRAGMA cipher_version returns a value).
  bool has_cipher_support() {
    bool supported = false;
    sqlite3_exec(
        db, "PRAGMA cipher_version;",
        [](void *out, int cols, char **vals, char **) -> int {
          if (cols > 0 && vals && vals[0] && vals[0][0] != '\0')
            *static_cast<bool *>(out) = true;
          return 0;
        },
        &supported, nullptr);
    return supported;
  }

  // The SQL literal for the key: a raw 32-byte key when given 64 hex chars
  // (no KDF, strongest), otherwise a passphrase (SQLCipher runs its KDF).
  static std::string key_literal(const std::string &raw) {
    bool is_hex64 = raw.size() == 64;
    for (char c : raw)
      if (!std::isxdigit((unsigned char)c)) { is_hex64 = false; break; }
    if (is_hex64) return "\"x'" + raw + "'\"";
    std::string escaped;
    escaped.reserve(raw.size());
    for (char c : raw) {
      if (c == '\'') escaped += "''";
      else escaped += c;
    }
    return "'" + escaped + "'";
  }

  bool key_works() {
    return sqlite3_exec(db, "SELECT count(*) FROM sqlite_master;", nullptr,
                        nullptr, nullptr) == SQLITE_OK;
  }

  static bool looks_like_plaintext_sqlite(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;  // no file → fresh DB, not a plaintext one to migrate
    char hdr[16] = {0};
    f.read(hdr, sizeof(hdr));
    if (f.gcount() < 16) return false;
    static const char kMagic[16] = {'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f',
                                     'o', 'r', 'm', 'a', 't', ' ', '3', '\0'};
    for (int i = 0; i < 16; ++i)
      if (hdr[i] != kMagic[i]) return false;
    return true;
  }

  bool apply_encryption(const std::string &path, std::string &error) {
    const char *raw_env = std::getenv("ENDORIUMFORT_DB_ENCRYPTION_KEY");
    if (!raw_env || !*raw_env) return true;  // encryption not requested
    const std::string key_sql = key_literal(std::string(raw_env));

    if (!has_cipher_support()) {
      error =
          "ENDORIUMFORT_DB_ENCRYPTION_KEY is set but this build has no "
          "SQLCipher; refusing to run with an unencrypted database.";
      return false;
    }

    if (sqlite3_exec(db, ("PRAGMA key = " + key_sql + ";").c_str(), nullptr,
                     nullptr, nullptr) != SQLITE_OK) {
      error = "Failed to apply database encryption key.";
      return false;
    }

    if (key_works()) return true;  // fresh or already-encrypted DB → good

    // Key set but the DB is unreadable: most likely an existing plaintext file.
    if (looks_like_plaintext_sqlite(path)) {
      if (env_truthy("ENDORIUMFORT_DB_ENCRYPTION_MIGRATE")) {
        return migrate_plaintext_to_encrypted(path, key_sql, error);
      }
      error = "Database '" + path +
              "' is unencrypted but ENDORIUMFORT_DB_ENCRYPTION_KEY is set. Set "
              "ENDORIUMFORT_DB_ENCRYPTION_MIGRATE=1 to encrypt it in place on "
              "next start (a plaintext backup is kept), or migrate manually.";
      return false;
    }
    error =
        "Could not open the encrypted database — wrong "
        "ENDORIUMFORT_DB_ENCRYPTION_KEY?";
    return false;
  }

  // Encrypt an existing plaintext DB in place using SQLCipher's sqlcipher_export
  // and swap it in, keeping a <path>.plaintext.bak backup.
  bool migrate_plaintext_to_encrypted(const std::string &path,
                                      const std::string &key_sql,
                                      std::string &error) {
    std::cerr << "[SECURITY] Encrypting existing plaintext database '" << path
              << "' (ENDORIUMFORT_DB_ENCRYPTION_MIGRATE=1)…\n";
    if (db) { sqlite3_close(db); db = nullptr; }

    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
      error = "Migration: cannot reopen plaintext database.";
      return false;
    }
    std::string path_esc;  // single-quote-escape for the SQL string literal
    for (char c : path) { path_esc += c; if (c == '\'') path_esc += '\''; }
    const std::string enc = path + ".enc-tmp";
    std::remove(enc.c_str());

    std::string enc_esc;
    for (char c : enc) { enc_esc += c; if (c == '\'') enc_esc += '\''; }

    std::string e;
    if (!exec("ATTACH DATABASE '" + enc_esc + "' AS encrypted KEY " + key_sql + ";", e) ||
        !exec("SELECT sqlcipher_export('encrypted');", e) ||
        !exec("DETACH DATABASE encrypted;", e)) {
      error = "Migration export failed: " + e;
      return false;
    }
    sqlite3_close(db);
    db = nullptr;

    if (std::rename(path.c_str(), (path + ".plaintext.bak").c_str()) != 0 ||
        std::rename(enc.c_str(), path.c_str()) != 0) {
      error = "Migration: failed to swap in the encrypted database.";
      return false;
    }

    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
      error = "Migration: cannot open the newly encrypted database.";
      return false;
    }
    if (sqlite3_exec(db, ("PRAGMA key = " + key_sql + ";").c_str(), nullptr,
                     nullptr, nullptr) != SQLITE_OK ||
        !key_works()) {
      error = "Migration: encrypted database failed verification.";
      return false;
    }
    std::cerr << "[SECURITY] Database encrypted. Plaintext backup kept at '"
              << path << ".plaintext.bak' — delete it once verified.\n";
    return true;
  }
};
