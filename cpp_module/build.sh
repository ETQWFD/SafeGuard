#!/usr/bin/env bash
# ================================================
# SafeGuard 共享库构建脚本 (Linux)
# 前置：sudo apt install libclamav-dev libyara-dev libssl-dev
# ================================================
set -e
cd "$(dirname "$0")"

BUILD_DIR=build

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --parallel

echo ""
echo "[OK] libsafeguard.so 已输出到 SafeGuard 项目根目录"
