# ─── EndoriumFort — RBI CEF-OSR helper build ─────────────────────────────────
# Standalone project: builds `endoriumfort-rbi-cef` against a CEF binary
# distribution. Kept out of the main backend CMake because it needs the (large)
# CEF SDK, which is fetched only in the Docker "rbi-cef" build stage (or locally
# by pointing CEF_ROOT at a downloaded CEF distribution).
#
#   cmake -S backend/tools/rbi-cef -B build-rbi-cef -DCEF_ROOT=/path/to/cef
#   cmake --build build-rbi-cef
#
# The resulting binary needs the CEF runtime files (libcef.so, *.pak,
# icudtl.dat, locales/, v8_context_snapshot.bin, chrome-sandbox…) beside it;
# the CEF cmake COPY_FILES steps below place them in the output dir.

cmake_minimum_required(VERSION 3.19)
project(endoriumfort_rbi_cef CXX C)

# CEF (recent builds) requires C++20 (uses std::same_as / std::derived_from).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CEF_ROOT)
  set(CEF_ROOT "$ENV{CEF_ROOT}")
endif()
if(NOT CEF_ROOT)
  message(FATAL_ERROR "CEF_ROOT is not set. Point it at a CEF binary distribution.")
endif()

# Use CEF's bundled cmake modules (FindCEF, cef_variables, cef_macros).
list(APPEND CMAKE_MODULE_PATH "${CEF_ROOT}/cmake")
find_package(CEF REQUIRED)

# Define the imported `libcef_lib` target (points at libcef.so) — the CEF sample
# tree does this at its top level; we must do it here since we build standalone.
ADD_LOGICAL_TARGET("libcef_lib" "${CEF_LIB_DEBUG}" "${CEF_LIB_RELEASE}")

# libcef DLL wrapper (built from the CEF distribution sources).
add_subdirectory("${CEF_ROOT}/libcef_dll" libcef_dll_wrapper)

# JPEG is optional: when present, tiles are JPEG-encoded (format 0); otherwise the
# helper streams raw-RGBA tiles (format 2), which the frontend also renders.
find_package(JPEG QUIET)

set(EF_RBI_TARGET endoriumfort-rbi-cef)
add_executable(${EF_RBI_TARGET} main.cc)
SET_EXECUTABLE_TARGET_PROPERTIES(${EF_RBI_TARGET})
add_dependencies(${EF_RBI_TARGET} libcef_dll_wrapper)
target_include_directories(${EF_RBI_TARGET} PRIVATE "${CEF_ROOT}")
target_link_libraries(${EF_RBI_TARGET}
  libcef_lib
  libcef_dll_wrapper
  ${CEF_STANDARD_LIBS}
)
if (JPEG_FOUND)
  target_compile_definitions(${EF_RBI_TARGET} PRIVATE EF_RBI_JPEG)
  target_link_libraries(${EF_RBI_TARGET} JPEG::JPEG)
endif()

# Copy the CEF runtime binaries + resources next to the helper so it can run.
COPY_FILES("${EF_RBI_TARGET}" "${CEF_BINARY_FILES}"   "${CEF_BINARY_DIR}"   "${CMAKE_CURRENT_BINARY_DIR}")
COPY_FILES("${EF_RBI_TARGET}" "${CEF_RESOURCE_FILES}" "${CEF_RESOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")
