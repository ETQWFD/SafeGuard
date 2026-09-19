#!/usr/bin/env bash
# ================================================
# SafeGuard JAR 构建脚本 (Linux)
# 前置：sudo apt install openjdk-17-jdk maven
# ================================================
set -e
cd "$(dirname "$0")"

command -v mvn >/dev/null 2>&1 || { echo "[ERROR] 未找到 mvn，请安装 Maven"; exit 1; }

mvn -q clean package -DskipTests

cp target/safeguard.jar ../safeguard.jar
echo "[OK] safeguard.jar 已输出到 SafeGuard 项目根目录"
