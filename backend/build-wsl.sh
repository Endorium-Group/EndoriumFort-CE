#!/usr/bin/env bash
# Build the Enterprise backend (with tests) under WSL/Linux. The build dir lives
# on the Linux filesystem: CMake cannot set file permissions on /mnt/c.
cd "$(dirname "$0")/.."
BUILD_DIR="${EF_BUILD_DIR:-$HOME/ef-build}"
cmake -S backend -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DENDORIUMFORT_PRO=ON > /tmp/cfg.log 2>&1
echo "CFG=$?"; grep -n -A6 "CMake Error" /tmp/cfg.log | head -40
cmake --build "$BUILD_DIR" -j8 -- -k > /tmp/build.log 2>&1
echo "BUILD=$?"
grep -nE "error|Error" /tmp/build.log | head -60
