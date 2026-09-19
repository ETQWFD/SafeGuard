#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_from_mb.py - 从 MalwareBazaar API 拉取最新样本
免费、无需 Key。用法：
    python scripts/collect_from_mb.py [数量] [输出.json]
默认拉取 100 条最新样本的哈希与签名。
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import requests

MB_API = "https://mb-api.abuse.ch/api/v1/"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fetch_recent(limit: int) -> list:
    resp = requests.post(MB_API, data={
        "query": "get_recent",
        "selector": "time",
        "limit": str(limit),
    }, headers={"User-Agent": "SafeGuard/1.0"}, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if data.get("query_status") != "ok":
        raise RuntimeError(f"MalwareBazaar 返回: {data.get('query_status')}")
    return data.get("data", [])


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    out_file = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(ROOT, "data", "virus_db", "mb_entries.json")

    try:
        samples = fetch_recent(limit)
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1

    entries = []
    for s in samples:
        sig = s.get("signature") or "MalwareBazaar.Sample"
        tags = s.get("tags") or []
        entries.append({
            "sha256": s.get("sha256_hash", "").lower(),
            "md5": s.get("md5_hash", "").lower(),
            "name": sig,
            "level": 5,
            "type": "malware",
            "family": str(tags[0]) if tags else "unknown",
            "source": "malwarebazaar",
            "first_seen": (s.get("first_seen") or
                           datetime.now(timezone.utc).strftime("%Y-%m-%d")),
        })

    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f"[OK] 从 MalwareBazaar 拉取 {len(entries)} 条 -> {out_file}")
    print("下一步：python scripts/merge_db.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
