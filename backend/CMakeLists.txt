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
  GIT_TAG v1.2.0
)

FetchContent_MakeAvailable(asio)
set(ASIO_INCLUDE_DIR "${asio_SOURCE_DIR}/asio/include" CACHE PATH "" FORCE)
FetchContent_MakeAvailable(crow)

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

# ── Core (Community edition) sources — no premium code ──
add_executable(endoriumfort_backend
  src/main.cc
  src/app_context.cc
  src/http_proxy.cc
  src/scim_query.cc
  src/routes.cc
  src/route_common.cc
  src/iam_common.cc
  src/license.cc
  src/ssh.cc
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
    src/pro/security_center.cc
    src/pro/governance.cc
    src/pro/session_premium.cc
  )
  target_compile_definitions(endoriumfort_backend PRIVATE ENDORIUMFORT_PRO)
else()
  target_sources(endoriumfort_backend PRIVATE src/pro_stub.cc)
endif()

target_link_libraries(endoriumfort_backend PRIVATE SQLite::SQLite3 OpenSSL::SSL OpenSSL::Crypto)

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

  if (ENDORIUMFORT_PRO)  # premium-dependent test targets (need src/pro/)
  add_executable(endoriumfort_backend_scim_routes_tests
    tests/scim_routes_test.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/routes.cc
    src/route_common.cc
    src/iam_common.cc
    src/license.cc
    src/pro/cluster.cc
    src/pro/vnc.cc
    src/pro/enterprise.cc
  )

  add_executable(endoriumfort_backend_security_alerts_tests
    tests/security_alerts_test.cc
    src/app_context.cc
    src/http_proxy.cc
    src/scim_query.cc
    src/routes.cc
    src/route_common.cc
    src/iam_common.cc
    src/license.cc
    src/pro/security_center.cc
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

  if (ENDORIUMFORT_PRO)  # pro test include dirs
  target_include_directories(endoriumfort_backend_scim_routes_tests
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

  if (ENDORIUMFORT_PRO)  # pro test defs
  target_compile_definitions(endoriumfort_backend_scim_routes_tests
    PRIVATE ASIO_STANDALONE
  )

  target_compile_definitions(endoriumfort_backend_security_alerts_tests
    PRIVATE ASIO_STANDALONE
  )
  endif()

  target_compile_definitions(endoriumfort_backend_license_tests
    PRIVATE ASIO_STANDALONE
  )

  target_link_libraries(endoriumfort_backend_tests PRIVATE OpenSSL::Crypto)
  target_link_libraries(endoriumfort_backend_auth_mfa_tests PRIVATE OpenSSL::Crypto)
  target_link_libraries(endoriumfort_backend_runtime_config_tests PRIVATE OpenSSL::Crypto SQLite::SQLite3)
  target_link_libraries(endoriumfort_backend_scim_query_tests PRIVATE OpenSSL::Crypto)
  if (ENDORIUMFORT_PRO)  # pro test libs
  target_link_libraries(endoriumfort_backend_scim_routes_tests PRIVATE SQLite::SQLite3 OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(endoriumfort_backend_security_alerts_tests PRIVATE SQLite::SQLite3 OpenSSL::SSL OpenSSL::Crypto)
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
  if (ENDORIUMFORT_PRO)  # pro tests
  add_test(NAME backend_scim_routes_test COMMAND endoriumfort_backend_scim_routes_tests)
  add_test(NAME backend_security_alerts_test COMMAND endoriumfort_backend_security_alerts_tests)
  endif()
  add_test(NAME backend_license_test COMMAND endoriumfort_backend_license_tests)
endif()
