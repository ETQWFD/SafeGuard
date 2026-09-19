#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update_clamav.py - 调用 freshclam 更新 ClamAV 病毒库（CVD）
用法：
    python scripts/update_clamav.py [freshclam 可执行文件路径]
默认在 PATH 中查找 freshclam；可指定 --config 传配置。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(ROOT, "data", "clamav")


def find_freshclam() -> str:
    path = shutil.which("freshclam")
    if path:
        return path
    candidates = [
        r"C:\Program Files\ClamAV\freshclam.exe",
        "/usr/bin/freshclam",
        "/usr/local/bin/freshclam",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return ""


def main() -> int:
    exe = sys.argv[1] if len(sys.argv) > 1 else find_freshclam()
    if not exe:
        print("[ERROR] 未找到 freshclam。请安装 ClamAV：")
        print("  Windows: vcpkg install clamav:x64-windows 或官方安装包")
        print("  Linux:   sudo apt install clamav")
        return 1

    os.makedirs(DB_DIR, exist_ok=True)
    cmd = [exe, f"--datadir={DB_DIR}"]
    if len(sys.argv) > 2:
        cmd.append(f"--config={sys.argv[2]}")

    print(f"[INFO] 运行: {' '.join(cmd)}")
    proc = subprocess.run(cmd)
    if proc.returncode == 0:
        print(f"[OK] ClamAV 病毒库已更新到 {DB_DIR}")
    else:
        print(f"[WARN] freshclam 退出码 {proc.returncode}（首次运行属正常）")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
