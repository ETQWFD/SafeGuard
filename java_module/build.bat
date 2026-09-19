@echo off
rem ================================================
rem SafeGuard JAR 构建脚本 (Windows)
rem 前置：安装 JDK 11+ 与 Maven，并将二者加入 PATH
rem ================================================
setlocal
cd /d %~dp0

where mvn >nul 2>nul
if errorlevel 1 (
    echo [ERROR] 未找到 mvn，请先安装 Maven：https://maven.apache.org/download.cgi
    exit /b 1
)

mvn -q clean package -DskipTests

if errorlevel 1 (
    echo [ERROR] 构建失败
    exit /b 1
)

copy /y target\safeguard.jar ..\safeguard.jar >nul
echo [OK] safeguard.jar 已输出到 SafeGuard 项目根目录
