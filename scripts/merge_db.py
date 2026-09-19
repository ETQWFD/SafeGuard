#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_db.py - 合并多个哈希来源，去重后生成 signatures.json
用法：
    python scripts/merge_db.py [来源1.json 来源2.json ...]
不传参数时自动合并 data/virus_db/ 下的 vt_entries.json 与 mb_entries.json。
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT, "data", "virus_db", "signatures.json")


def load_json(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data.get("entries", [])
        if isinstance(data, list):
            return data
    except Exception as e:
        print(f"[WARN] 跳过 {path}: {e}")
    return []


def normalize(entry: dict) -> dict | None:
    sha = str(entry.get("sha256", "")).strip().lower()
    if not sha or len(sha) != 64:
        return None
    return {
        "sha256": sha,
        "md5": str(entry.get("md5", "")).strip().lower(),
        "name": str(entry.get("name") or "Unknown.Sample"),
        "level": int(entry.get("level", 4)),
        "type": str(entry.get("type") or "malware"),
        "family": str(entry.get("family") or "unknown"),
        "source": str(entry.get("source") or "manual"),
        "first_seen": str(entry.get("first_seen") or
                         datetime.now(timezone.utc).strftime("%Y-%m-%d")),
    }


def main() -> int:
    sources = sys.argv[1:]
    if not sources:
        sources = [os.path.join(ROOT, "data", "virus_db", f)
                   for f in ("vt_entries.json", "mb_entries.json")
                   if os.path.exists(os.path.join(ROOT, "data",
                                                  "virus_db", f))]

    merged: dict[str, dict] = {}
    for path in sources:
        for entry in load_json(path):
            norm = normalize(entry)
            if norm:
                merged[norm["sha256"]] = norm

    # 保留既有库中未被覆盖的条目
    existing = load_json(DB_PATH)
    for entry in existing:
        norm = normalize(entry)
        if norm:
            merged.setdefault(norm["sha256"], norm)

    db = {
        "version": datetime.now(timezone.utc).strftime("%Y.%m.%d.%H%M"),
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(merged),
        "entries": sorted(merged.values(), key=lambda e: e["sha256"]),
    }
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    print(f"[OK] signatures.json 更新完成，共 {len(merged)} 条")
    print(f"     来源: {', '.join(sources)}")
    print("下一步：python scripts/validate_db.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
