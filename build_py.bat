@echo off
rem ================================================
rem SafeGuard Python 打包脚本 (Windows)
rem 生成 SafeGuard 可运行目录（含依赖说明）
rem ================================================
setlocal
cd /d %~dp0

echo [1/4] 检查 Python...
python --version >nul 2>nul || (echo [ERROR] 未安装 Python & exit /b 1)

echo [2/4] 安装依赖...
python -m pip install -r requirements.txt -q

echo [3/4] 验证 Python 语法...
python -m compileall -q core ui main.py scripts || (echo [ERROR] 语法检查失败 & exit /b 1)

echo [4/4] 生成可运行脚本 run_safeguard.bat
(
echo @echo off
echo cd /d %%~dp0
echo python main.py
) > run_safeguard.bat

echo.
echo [OK] 构建完成。运行：python main.py  或 双击 run_safeguard.bat
