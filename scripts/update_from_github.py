#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update_from_github.py - 从 GitHub 仓库拉取病毒库（替代第三方源）

病毒库托管在 GitHub 仓库本身：
  data/virus_db/signatures.json   哈希库
  data/virus_db/rules.yar         YARA 规则
  data/virus_db/behavior_rules.json  行为规则

用法：
    python scripts/update_from_github.py            # 全部更新
    python scripts/update_from_github.py --check    # 仅检查是否有更新
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import hashlib
from datetime import datetime, timezone

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_CFG = os.path.join(ROOT, "config", "repo.json")

TARGETS = [
    ("data/virus_db/signatures.json", "signatures"),
    ("data/virus_db/rules.yar", "yara"),
    ("data/virus_db/behavior_rules.json", "behavior"),
]


def load_repo_cfg() -> dict:
    with open(REPO_CFG, "r", encoding="utf-8") as f:
        return json.load(f)


def sha256_of_file(path: str) -> str:
    if not os.path.exists(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_remote_sha256(raw_base: str, rel_path: str) -> tuple[str, str]:
    """返回 (远程 sha256, 内容)。远程不存在则 ('', '')。"""
    url = f"{raw_base}/{rel_path}"
    try:
        resp = requests.get(url, timeout=30)
    except Exception as e:
        print(f"  [网络错误] {rel_path}: {e}")
        return "", ""
    if resp.status_code == 404:
        return "", ""
    if resp.status_code != 200:
        print(f"  [HTTP {resp.status_code}] {rel_path}")
        return "", ""
    content = resp.content
    return hashlib.sha256(content).hexdigest(), content.decode("utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="仅检查更新，不下载")
    args = ap.parse_args()

    cfg = load_repo_cfg()
    raw_base = cfg.get("raw_base", "")
    if not raw_base or "REPLACE_AFTER_REPO_CREATE" in raw_base:
        print("[ERROR] 请先在 config/repo.json 填入 github_owner（创建仓库后自动更新）")
        return 1

    updated = []
    for rel_path, _kind in TARGETS:
        local_path = os.path.join(ROOT, *rel_path.split("/"))
        remote_sha, content = fetch_remote_sha256(raw_base, rel_path)
        if not remote_sha:
            print(f"  [跳过] {rel_path} 远程不存在")
            continue
        local_sha = sha256_of_file(local_path)
        if remote_sha == local_sha:
            print(f"  [最新] {rel_path}")
            continue
        if args.check:
            print(f"  [有更新] {rel_path}  {local_sha[:12]} -> {remote_sha[:12]}")
            updated.append(rel_path)
            continue
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  [已更新] {rel_path}")
        updated.append(rel_path)

    # 写更新时间戳
    stamp = {
        "source": "github",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "files": updated,
    }
    with open(os.path.join(ROOT, "data", "virus_db", "last_update.json"),
              "w", encoding="utf-8") as f:
        json.dump(stamp, f, ensure_ascii=False, indent=2)

    if args.check and updated:
        print(f"\n[结论] {len(updated)} 个文件有更新")
    elif updated:
        print(f"\n[完成] 已更新 {len(updated)} 个文件")
    else:
        print("\n[完成] 病毒库已是最新")
    return 0


if __name__ == "__main__":
    sys.exit(main())
