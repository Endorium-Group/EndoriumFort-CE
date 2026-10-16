// A resource's stored secret (ssh/http password) survives a restart, with or
// without ENDORIUMFORT_VAULT_KEY, and is kept when the resource is edited
// without retyping it.

#include "app_context.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    ++failures;
  }
}

Resource reload(const std::string &db_path, int id) {
  AppContext ctx;
  ctx.init_database(db_path);
  auto it = ctx.resources.find(id);
  return it == ctx.resources.end() ? Resource{} : it->second;
}

void run(const std::string &label, const std::string &db_path) {
  std::remove(db_path.c_str());
  {
    AppContext ctx;
    ctx.init_database(db_path);
    Resource r;
    r.id = 1;
    r.name = "srv";
    r.target = "10.0.0.1";
    r.protocol = "ssh";
    r.port = 22;
    r.credentialSource = "vaulted";
    r.sshUsername = "root";
    r.sshPassword = "S3cret-pass";
    r.httpUsername = "web";
    r.httpPassword = "Http-pass";
    r.riskLevel = "low";
    r.createdAt = r.updatedAt = "2026-01-01T00:00:00Z";
    expect(ctx.insert_resource(r), label + ": insert");
  }

  Resource loaded = reload(db_path, 1);
  expect(loaded.sshPassword == "S3cret-pass",
         label + ": ssh password lost after restart");
  expect(loaded.httpPassword == "Http-pass",
         label + ": http password lost after restart");

  // Edit without retyping the secret (the route keeps the stored one).
  {
    AppContext ctx;
    ctx.init_database(db_path);
    Resource r = ctx.resources[1];
    r.description = "edited";
    expect(ctx.update_resource_db(r), label + ": update");
  }
  loaded = reload(db_path, 1);
  expect(loaded.description == "edited", label + ": edit not saved");
  expect(loaded.sshPassword == "S3cret-pass",
         label + ": ssh password lost after edit + restart");
  std::remove(db_path.c_str());
}

}  // namespace

int main() {
  const std::string db_path = "resource_secret_test.db";

#ifdef _WIN32
  _putenv_s("ENDORIUMFORT_VAULT_KEY", "");
#else
  unsetenv("ENDORIUMFORT_VAULT_KEY");
#endif
  run("no vault key", db_path);

  const char *key =
      "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
#ifdef _WIN32
  _putenv_s("ENDORIUMFORT_VAULT_KEY", key);
#else
  setenv("ENDORIUMFORT_VAULT_KEY", key, 1);
#endif
  run("vault key", db_path);

  if (failures == 0) std::cout << "resource secret tests passed" << std::endl;
  return failures == 0 ? 0 : 1;
}
