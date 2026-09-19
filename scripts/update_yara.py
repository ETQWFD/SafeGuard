#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update_yara.py - 拉取/更新社区 YARA 规则库
默认拉取两个知名开源仓库到 data/yara_rules/，之后可 git pull 增量更新。
用法：
    python scripts/update_yara.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(ROOT, "data", "yara_rules")

REPOS = {
    "signature-base": "https://github.com/Neo23x0/signature-base.git",
    "yara-rules": "https://github.com/Yara-Rules/rules.git",
}


def ensure_git() -> bool:
    return shutil.which("git") is not None


def update_repo(name: str, url: str) -> None:
    target = os.path.join(RULES_DIR, name)
    if os.path.isdir(os.path.join(target, ".git")):
        print(f"[INFO] {name}: git pull 增量更新")
        subprocess.run(["git", "-C", target, "pull", "--quiet"], check=True)
    else:
        print(f"[INFO] {name}: 首次克隆")
        os.makedirs(RULES_DIR, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", "--quiet",
                        url, target], check=True)


def main() -> int:
    if not ensure_git():
        print("[ERROR] 需要安装 git")
        return 1
    os.makedirs(RULES_DIR, exist_ok=True)
    for name, url in REPOS.items():
        try:
            update_repo(name, url)
            print(f"[OK] {name} 更新完成")
        except Exception as e:
            print(f"[ERROR] {name}: {e}")
    print(f"[INFO] 规则目录: {RULES_DIR}")
    print("[INFO] 提示：规则文件需自己挑选、检查后放入 "
          "data/virus_db/rules.yar 或由 Java 端 YaraEngine 引用")
    return 0


if __name__ == "__main__":
    sys.exit(main())
