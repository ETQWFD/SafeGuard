@echo off
rem ================================================
rem SafeGuard DLL 构建脚本 (Windows)
rem 前置：vcpkg install clamav:x64-windows yara:x64-windows openssl:x64-windows
rem ================================================
setlocal

cd /d %~dp0

if not defined VCPKG_ROOT (
    echo [INFO] VCPKG_ROOT 未设置，尝试默认路径
    if exist "%USERPROFILE%\vcpkg" set "VCPKG_ROOT=%USERPROFILE%\vcpkg"
)
if defined VCPKG_ROOT (
    set "CMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
    echo [INFO] 使用 vcpkg toolchain: %CMAKE_TOOLCHAIN_FILE%
)

set BUILD_DIR=build

if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"

cmake -S . -B "%BUILD_DIR%" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_TOOLCHAIN_FILE=%CMAKE_TOOLCHAIN_FILE%

if errorlevel 1 goto :fail

cmake --build "%BUILD_DIR%" --config Release --parallel

if errorlevel 1 goto :fail

echo.
echo [OK] safeguard.dll 已输出到 SafeGuard 项目根目录
goto :eof

:fail
echo.
echo [ERROR] 构建失败，请检查依赖是否安装：clamav / yara / openssl
exit /b 1
