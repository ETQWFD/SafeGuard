#!/usr/bin/env bash
# ================================================
# SafeGuard Python 构建脚本 (Linux)
# ================================================
set -e
cd "$(dirname "$0")"

echo "[1/4] 检查 Python..."
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] 未安装 Python3"; exit 1; }

echo "[2/4] 安装依赖..."
python3 -m pip install -r requirements.txt -q

echo "[3/4] 验证 Python 语法..."
python3 -m compileall -q core ui main.py scripts

echo "[4/4] 生成启动脚本 run_safeguard.sh"
cat > run_safeguard.sh <<'EOF'
#!/usr/bin/env bash
cd "$(dirname "$0")"
exec python3 main.py
EOF
chmod +x run_safeguard.sh

echo "[OK] 构建完成。运行：python3 main.py  或  ./run_safeguard.sh"
