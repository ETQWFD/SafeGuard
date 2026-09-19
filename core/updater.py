#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
updater.py - 真实更新检测（GitHub Releases API）

不依赖任何外部推送服务：直接查询 GitHub Releases 最新版本，
比对本地版本号，返回是否需要更新、下载地址、更新说明。
"""
from __future__ import annotations

import json
import os
import sys
from typing import Optional

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_CFG = os.path.join(ROOT, "config", "repo.json")
CURRENT_VERSION = "1.5.0"


def load_repo_cfg() -> dict:
    with open(REPO_CFG, "r", encoding="utf-8") as f:
        return json.load(f)


def _parse_version(v: str) -> tuple:
    parts = []
    for x in v.lstrip("vV").split("."):
        try:
            parts.append(int(x))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def check_for_update(timeout: int = 15) -> dict:
    """返回 {has_update, latest, current, notes, download_url, error?}"""
    cfg = load_repo_cfg()
    api_base = cfg.get("api_base", "")
    if not api_base or "REPLACE_AFTER_REPO_CREATE" in api_base:
        return {"has_update": False, "error": "repo_not_configured"}
    url = f"{api_base}/releases/latest"
    try:
        resp = requests.get(url, timeout=timeout,
                            headers={"Accept": "application/vnd.github+json"})
    except Exception as e:
        return {"has_update": False, "error": str(e)}
    if resp.status_code == 404:
        return {"has_update": False, "error": "no_release"}
    if resp.status_code != 200:
        return {"has_update": False, "error": f"http_{resp.status_code}"}
    data = resp.json()
    latest = data.get("tag_name", "0.0.0")
    has_update = _parse_version(latest) > _parse_version(CURRENT_VERSION)
    download_url = data.get("html_url", "")
    notes = data.get("body", "")
    return {
        "has_update": has_update,
        "latest": latest,
        "current": CURRENT_VERSION,
        "notes": notes,
        "download_url": download_url,
    }


def main() -> int:
    result = check_for_update()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
