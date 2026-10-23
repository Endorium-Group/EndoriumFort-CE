cmake_minimum_required(VERSION 3.16)
project(endoriumfort_backend LANGUAGES CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-30-2
)

FetchContent_Declare(
  crow
  GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
  GIT_TAG v1.3.5
)

FetchContent_MakeAvailable(asio)
set(ASIO_INCLUDE_DIR "${asio_SOURCE_DIR}/asio/include" CACHE PATH "" FORCE)
FetchContent_MakeAvailable(crow)

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(LibSSH2 QUIET)
if (NOT LibSSH2_FOUND)
  find_package(PkgConfig QUIET)
  if (PkgConfig_FOUND)
    pkg_check_modules(LIBSSH2 QUIET IMPORTED_TARGET libssh2)
  endif()
endif()

# Version is now managed by build-all.sh/ps1 (change-detection based).
# Manual fallback: increment on every build if version.h is missing.
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h")
  add_custom_target(increment_version
      COMMAND ${CMAKE_COMMAND} -DVERSION_FILE=${CMAKE_CURRENT_SOURCE_DIR}/VERSION -DVERSION_HEADER_FILE=${CMAKE_CURRENT_SOURCE_DIR}/src/version.h -P ${CMAKE_CURRENT_SOURCE_DIR}/scripts/increment_version.cmake
      COMMENT "Generating version.h (first build)..."
  )
else()
  add_custom_target(increment_version
      COMMENT "Version managed by build-all.sh — skipping auto-increment."
  )
endif()

# ── Database seam ───────────────────────────────────────────────────────────
# One small library so every target shares the same backend selection, and so
# adding a backend never means editing five source lists. SQLite is always
# built in (default store, air-gap friendly); PostgreSQL is opt-in for
# production deployments and is selected at RUNTIME from the DSN.
option(ENDORIUMFORT_POSTGRES "Build the PostgreSQL database backend" OFF)

set(EF_DB_SOURCES src/database.cc src/db_sqlite.cc)
if (ENDORIUMFORT_POSTGRES)
  list(APPEND EF_DB_SOURCES src/db_postgres.cc)
endif()

add_library(endoriumfort_db STATIC ${EF_DB_SOURCES})
target_include_directories(endoriumfort_db PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(endoriumfort_db PUBLIC SQLite::SQLite3)

if (ENDORIUMFORT_POSTGRES)
  find_package(PostgreSQL REQUIRED)
  target_link_libraries(endoriumfort_db PUBLIC PostgreSQL::PostgreSQL)
  target_compile_definitions(endoriumfort_db PUBLIC ENDORIUMFORT_POSTGRES)
  message(STATUS "EndoriumFort: PostgreSQL backend enabled")
endif()

# ── Core (Community edition) sources — no premium code ──
add_executable(endoriumfort_backend
  src/main.cc
  src/app_context.cc
  src/http_proxy.cc
  src/scim_query.cc
  src/audit_query.cc
  src/routes.cc
  src/route_common.cc
  src/settings.cc
  src/settings_routes.cc
  src/ssh_guard.cc
  src/ssh_guard_routes.cc
  src/iam_common.cc
  src/license.cc
  src/ssh.cc
  src/rbi.cc
  src/session_recording.cc
)

add_dependencies(endoriumfort_backend increment_version)

target_include_directories(endoriumfort_backend
  PRIVATE
    ${crow_SOURCE_DIR}/include
    ${asio_SOURCE_DIR}/asio/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(endoriumfort_backend
  PRIVATE ASIO_STANDALONE
)

# Dev/local builds may embed the non-production dev license issuer key so that
# scripts/gen-dev-license.sh tokens validate. NEVER enable for release images.
option(ENDORIUMFORT_LICENSE_DEV_KEY "Embed the dev license issuer public key" OFF)
if (ENDORIUMFORT_LICENSE_DEV_KEY)
  target_compile_definitions(endoriumfort_backend PRIVATE ENDORIUMFORT_LICENSE_DEV_KEY)
endif()

# A developer machine may embed its own test issuer (see backend/build-wsl.sh):
# set the kid and both public keys (base64url SPKI DER). NEVER for release images.
set(ENDORIUMFORT_LICENSE_LOCAL_KID "" CACHE STRING "Machine-local test license issuer kid")
set(ENDORIUMFORT_LICENSE_LOCAL_ED25519 "" CACHE STRING "Its Ed25519 public key (base64url SPKI DER)")
set(ENDORIUMFORT_LICENSE_LOCAL_MLDSA "" CACHE STRING "Its ML-DSA-65 public key (base64url SPKI DER)")
if (ENDORIUMFORT_LICENSE_LOCAL_KID)
  target_compile_definitions(endoriumfort_backend PRIVATE
    ENDORIUMFORT_LICENSE_LOCAL_KID="${ENDORIUMFORT_LICENSE_LOCAL_KID}"
    ENDORIUMFORT_LICENSE_LOCAL_ED25519="${ENDORIUMFORT_LICENSE_LOCAL_ED25519}"
    ENDORIUMFORT_LICENSE_LOCAL_MLDSA="${ENDORIUMFORT_LICENSE_LOCAL_MLDSA}")
endif()

# Production release builds embed the prod issuer public key (once populated in
# backend/src/license.h issuer_keys()). Off by default so dev/CI builds fail-safe.
option(ENDORIUMFORT_LICENSE_PROD_KEY "Embed the production license issuer public key" OFF)
if (ENDORIUMFORT_LICENSE_PROD_KEY)
  target_compile_definitions(endoriumfort_backend PRIVATE ENDORIUMFORT_LICENSE_PROD_KEY)
endif()

# Open-core edition switch. ON = Enterprise (compile pro/ premium modules).
# OFF = Community (premium code physically absent; a no-op stub is linked).
# Default is auto-detected from the presence of the pro/ overlay, so the public
# Community repo (no pro/) builds CE and the private repo builds EE without any
# flag. Override explicitly with -DENDORIUMFORT_PRO=ON/OFF when needed.
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/pro/pro_features.cc")
  set(_ef_pro_default ON)
else()
  set(_ef_pro_default OFF)
endif()
option(ENDORIUMFORT_PRO "Build the Enterprise edition (include pro/ modules)" ${_ef_pro_default})
if (ENDORIUMFORT_PRO)
  target_sources(endoriumfort_backend PRIVATE
    src/pro/pro_features.cc
    src/pro/cluster.cc
    src/pro/relay.cc
    src/pro/rdp.cc
    src/pro/vnc.cc
    src/pro/tunnel.cc
    src/pro/recording.cc
    src/pro/access_governance.cc
    src/pro/enterprise.cc
    src/pro/siem.cc
    src/pro/security_center.cc
    src/pro/governance.cc
    src/pro/session_premium.cc
    src/pro/scheduler.cc
    src/pro/vault_rotation.cc
    src/pro/vault_dynamic.cc
    src/pro/itdr.cc
    src/pro/k8s.cc
    src/pro/branding.cc
    src/pro/rbi_recording.cc
    src/pro/rbi_transfer.cc
    src/pro/push.cc
  )
  target_compile_definitions(endoriumfort_backend PRIVATE ENDORIUMFORT_PRO)
  # forkpty(3) for the Kubernetes exec PTY bridge (Linux: libutil).
  if (NOT WIN32)
    target_link_libraries(endoriumfort_backend PRIVATE util)
  endif()
else()
  target_sources(endoriumfort_backend PRIVATE src/pro_stub.cc)
endif()

target_link_libraries(endoriumfort_backend PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto)

if (LibSSH2_FOUND)
  target_link_libraries(endoriumfort_backend PRIVATE LibSSH2::LibSSH2)
  target_compile_definitions(endoriumfort_backend PRIVATE ENDORIUMFORT_SSH_ENABLED)
elseif (TARGET PkgConfig::LIBSSH2)
  target_link_libraries(endoriumfort_backend PRIVATE PkgConfig::LIBSSH2)
  target_compile_definitions(endoriumfort_backend PRIVATE ENDORIUMFORT_SSH_ENABLED)
else()
  message(WARNING "LibSSH2 not found: SSH proxy disabled")
endif()

if (WIN32)
  target_link_libraries(endoriumfort_backend PRIVATE ws2_32 mswsock)
endif()

# Dev/test stand-in for the RBI "tiles" engine helper (no CEF needed). Point
# ENDORIUMFORT_RBI_HELPER at it and set ENDORIUMFORT_RBI_ENGINE=tiles to exercise
# the homemade dirty-rect transport end-to-end. Not shipped in the image — and the
# Docker backend-build stage does not copy backend/tools/, so guard on the source
# being present (mirrors the pro/ block) to keep `cmake` generate happy there.
if (NOT WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/rbi_stub_helper.cc")
  add_executable(endoriumfort_rbi_stub tools/rbi_stub_helper.cc)
  find_package(Threads REQUIRED)
  target_link_libraries(endoriumfort_rbi_stub PRIVATE Threads::Threads)
endif()

if (BUILD_TESTING)
  add_executable(endoriumfort_backend_tests
    tests/utils_test.cc
  )

  add_executable(endoriumfort_backend_auth_mfa_tests
    tests/auth_mfa_test.cc
  )

  add_executable(endoriumfort_backend_runtime_config_tests
    tests/runtime_config_test.cc
  )

  add_executable(endoriumfort_backend_scim_query_tests
    tests/scim_query_test.cc
    src/scim_query.cc
  )

  add_executable(endoriumfort_backend_audit_query_tests
    tests/audit_query_test.cc
    src/audit_query.cc
  )

  add_executable(endoriumfort_backend_settings_tests
    tests/settings_test.cc
    src/settings.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/audit_query.cc
    src/route_common.cc
    src/iam_common.cc
    src/license.cc
  )

  add_executable(endoriumfort_backend_ssh_guard_tests
    tests/ssh_guard_test.cc
    src/ssh_guard.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/audit_query.cc
    src/route_common.cc
    src/iam_common.cc
    src/settings.cc
    src/license.cc
  )

  add_executable(endoriumfort_backend_device_tests
    tests/device_test.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/route_common.cc
    src/settings.cc
    src/iam_common.cc
    src/license.cc
  )

  if (ENDORIUMFORT_PRO)  # premium-dependent test targets (need src/pro/)
  add_executable(endoriumfort_backend_scim_routes_tests
    tests/scim_routes_test.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/audit_query.cc
    src/routes.cc
    src/route_common.cc
    src/settings.cc
    src/iam_common.cc
    src/license.cc
    src/pro/cluster.cc
    src/pro/vnc.cc
    src/pro/enterprise.cc
    src/pro/siem.cc
  )

  add_executable(endoriumfort_backend_security_alerts_tests
    tests/security_alerts_test.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/audit_query.cc
    src/routes.cc
    src/route_common.cc
    src/settings.cc
    src/iam_common.cc
    src/license.cc
    src/pro/security_center.cc
  )

  add_executable(endoriumfort_backend_siem_tests
    tests/siem_test.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/audit_query.cc
    src/route_common.cc
    src/settings.cc
    src/iam_common.cc
    src/license.cc
    src/pro/siem.cc
  )

  add_executable(endoriumfort_backend_vault_gen_tests
    tests/vault_gen_test.cc
  )

  add_executable(endoriumfort_backend_itdr_geo_tests
    tests/itdr_geo_test.cc
  )
  endif()

  add_executable(endoriumfort_backend_license_tests
    tests/license_test.cc
  )

  target_include_directories(endoriumfort_backend_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_auth_mfa_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_runtime_config_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_scim_query_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_settings_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_ssh_guard_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_device_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  if (ENDORIUMFORT_PRO)  # pro test include dirs
  target_include_directories(endoriumfort_backend_scim_routes_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_siem_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_security_alerts_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_vault_gen_tests
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_include_directories(endoriumfort_backend_itdr_geo_tests
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  endif()

  target_include_directories(endoriumfort_backend_license_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_compile_definitions(endoriumfort_backend_tests
    PRIVATE ASIO_STANDALONE
  )

  target_compile_definitions(endoriumfort_backend_auth_mfa_tests
    PRIVATE ASIO_STANDALONE
  )

  target_compile_definitions(endoriumfort_backend_runtime_config_tests
    PRIVATE ASIO_STANDALONE
  )

  target_compile_definitions(endoriumfort_backend_scim_query_tests
    PRIVATE ASIO_STANDALONE
  )

  target_include_directories(endoriumfort_backend_audit_query_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )

  target_compile_definitions(endoriumfort_backend_audit_query_tests
    PRIVATE ASIO_STANDALONE
  )

  target_compile_definitions(endoriumfort_backend_device_tests
    PRIVATE ASIO_STANDALONE
  )

  target_compile_definitions(endoriumfort_backend_settings_tests
    PRIVATE ASIO_STANDALONE
  )

  target_compile_definitions(endoriumfort_backend_ssh_guard_tests
    PRIVATE ASIO_STANDALONE
  )

  if (ENDORIUMFORT_PRO)  # pro test defs
  target_compile_definitions(endoriumfort_backend_scim_routes_tests
    PRIVATE ASIO_STANDALONE
  )

  target_compile_definitions(endoriumfort_backend_security_alerts_tests
    PRIVATE ASIO_STANDALONE
  )

  target_compile_definitions(endoriumfort_backend_siem_tests
    PRIVATE ASIO_STANDALONE
  )
  endif()

  target_compile_definitions(endoriumfort_backend_license_tests
    PRIVATE ASIO_STANDALONE
  )

  target_link_libraries(endoriumfort_backend_tests PRIVATE OpenSSL::Crypto)
  target_link_libraries(endoriumfort_backend_auth_mfa_tests PRIVATE OpenSSL::Crypto)
  target_link_libraries(endoriumfort_backend_runtime_config_tests PRIVATE OpenSSL::Crypto endoriumfort_db)
  target_link_libraries(endoriumfort_backend_scim_query_tests PRIVATE OpenSSL::Crypto)
  target_link_libraries(endoriumfort_backend_audit_query_tests PRIVATE OpenSSL::Crypto Threads::Threads)
  target_link_libraries(endoriumfort_backend_device_tests PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(endoriumfort_backend_settings_tests PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  target_link_libraries(endoriumfort_backend_ssh_guard_tests PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  if (ENDORIUMFORT_PRO)  # pro test libs
  target_link_libraries(endoriumfort_backend_scim_routes_tests PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(endoriumfort_backend_security_alerts_tests PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(endoriumfort_backend_siem_tests PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  endif()
  target_link_libraries(endoriumfort_backend_license_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto)

  if (ENDORIUMFORT_PRO)  # pro test ssh defs
  if (LibSSH2_FOUND)
    target_compile_definitions(endoriumfort_backend_scim_routes_tests PRIVATE ENDORIUMFORT_SSH_ENABLED)
    target_compile_definitions(endoriumfort_backend_security_alerts_tests PRIVATE ENDORIUMFORT_SSH_ENABLED)
  elseif (TARGET PkgConfig::LIBSSH2)
    target_compile_definitions(endoriumfort_backend_scim_routes_tests PRIVATE ENDORIUMFORT_SSH_ENABLED)
    target_compile_definitions(endoriumfort_backend_security_alerts_tests PRIVATE ENDORIUMFORT_SSH_ENABLED)
  endif()
  endif()

  if (ENDORIUMFORT_PRO)  # pro test win32
  if (WIN32)
    target_link_libraries(endoriumfort_backend_scim_routes_tests PRIVATE ws2_32 mswsock)
    target_link_libraries(endoriumfort_backend_security_alerts_tests PRIVATE ws2_32 mswsock)
  endif()
  endif()

  add_test(NAME backend_utils_test COMMAND endoriumfort_backend_tests)
  add_test(NAME backend_auth_mfa_test COMMAND endoriumfort_backend_auth_mfa_tests)
  add_test(NAME backend_runtime_config_test COMMAND endoriumfort_backend_runtime_config_tests)
  add_test(NAME backend_scim_query_test COMMAND endoriumfort_backend_scim_query_tests)
  add_test(NAME backend_audit_query_test COMMAND endoriumfort_backend_audit_query_tests)
  add_test(NAME backend_device_test COMMAND endoriumfort_backend_device_tests)

  # Resource secrets survive a restart and an edit, with or without vault key.
  add_executable(endoriumfort_backend_resource_secret_tests
    tests/resource_secret_test.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/audit_query.cc
    src/route_common.cc
    src/settings.cc
    src/iam_common.cc
    src/license.cc
  )
  target_include_directories(endoriumfort_backend_resource_secret_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(endoriumfort_backend_resource_secret_tests
    PRIVATE ASIO_STANDALONE
  )
  target_link_libraries(endoriumfort_backend_resource_secret_tests
    PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  if (WIN32)
    target_link_libraries(endoriumfort_backend_resource_secret_tests PRIVATE ws2_32 mswsock)
  endif()
  add_test(NAME backend_resource_secret_test COMMAND endoriumfort_backend_resource_secret_tests)

  # Failed sign-ins: no block for a few typos, backoff from 10 failures.
  add_executable(endoriumfort_backend_login_backoff_tests
    tests/login_backoff_test.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/audit_query.cc
    src/route_common.cc
    src/settings.cc
    src/iam_common.cc
    src/license.cc
  )
  target_include_directories(endoriumfort_backend_login_backoff_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(endoriumfort_backend_login_backoff_tests
    PRIVATE ASIO_STANDALONE
  )
  target_link_libraries(endoriumfort_backend_login_backoff_tests
    PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  if (WIN32)
    target_link_libraries(endoriumfort_backend_login_backoff_tests PRIVATE ws2_32 mswsock)
  endif()
  add_test(NAME backend_login_backoff_test COMMAND endoriumfort_backend_login_backoff_tests)
  add_test(NAME backend_settings_test COMMAND endoriumfort_backend_settings_tests)
  add_test(NAME backend_ssh_guard_test COMMAND endoriumfort_backend_ssh_guard_tests)
  if (ENDORIUMFORT_PRO)  # pro tests
  add_test(NAME backend_scim_routes_test COMMAND endoriumfort_backend_scim_routes_tests)
  add_test(NAME backend_security_alerts_test COMMAND endoriumfort_backend_security_alerts_tests)
  add_test(NAME backend_siem_test COMMAND endoriumfort_backend_siem_tests)
  add_test(NAME backend_vault_gen_test COMMAND endoriumfort_backend_vault_gen_tests)
  add_test(NAME backend_itdr_geo_test COMMAND endoriumfort_backend_itdr_geo_tests)

  # Agent tunnels follow the session access policy (pro/tunnel.cc).
  add_executable(endoriumfort_backend_agent_tunnel_jit_tests
    tests/agent_tunnel_jit_test.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/audit_query.cc
    src/routes.cc
    src/route_common.cc
    src/settings.cc
    src/iam_common.cc
    src/license.cc
    src/pro/tunnel.cc
  )
  target_include_directories(endoriumfort_backend_agent_tunnel_jit_tests
    PRIVATE
      ${crow_SOURCE_DIR}/include
      ${asio_SOURCE_DIR}/asio/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(endoriumfort_backend_agent_tunnel_jit_tests
    PRIVATE ASIO_STANDALONE
  )
  target_link_libraries(endoriumfort_backend_agent_tunnel_jit_tests
    PRIVATE endoriumfort_db OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  if (WIN32)
    target_link_libraries(endoriumfort_backend_agent_tunnel_jit_tests PRIVATE ws2_32 mswsock)
  endif()
  add_test(NAME backend_agent_tunnel_jit_test COMMAND endoriumfort_backend_agent_tunnel_jit_tests)
  endif()
  add_test(NAME backend_license_test COMMAND endoriumfort_backend_license_tests)
endif()
