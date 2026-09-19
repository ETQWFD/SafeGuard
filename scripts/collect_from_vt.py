#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_from_vt.py - 从 VirusTotal v3 API 批量查询哈希
限速 4 次/分钟（免费额度）。用法：
    python scripts/collect_from_vt.py hashes.txt [输出.json]
hashes.txt 每行一个 SHA256/MD5。
输出为可被 merge_db.py 合并的条目列表。
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

API_BASE = "https://www.virustotal.com/api/v3/files/{}"
RATE_LIMIT_S = 15.0  # 4 次/分钟

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_api_key() -> str:
    with open(os.path.join(ROOT, "config", "api_keys.json"),
              "r", encoding="utf-8") as f:
        return json.load(f).get("virus_total", "").strip()


def query_hash(key: str, h: str) -> dict:
    resp = requests.get(API_BASE.format(h.strip().lower()),
                        headers={"x-apikey": key}, timeout=30)
    if resp.status_code == 404:
        return {"sha256": h.strip().lower(), "found": False}
    if resp.status_code in (401, 403):
        raise RuntimeError("API Key 无效或额度用尽")
    resp.raise_for_status()
    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "sha256": attrs.get("sha256", h.strip().lower()),
        "md5": attrs.get("md5", ""),
        "name": _best_name(attrs),
        "level": 5 if stats.get("malicious", 0) > 0 else
                 (3 if stats.get("suspicious", 0) > 0 else 0),
        "type": "malware" if stats.get("malicious", 0) > 0 else "unknown",
        "family": _best_family(attrs),
        "source": "virustotal",
        "first_seen": _iso(attrs.get("first_submission_date")),
        "malicious_count": stats.get("malicious", 0),
        "found": True,
    }


def _best_name(attrs: dict) -> str:
    names = attrs.get("meaningful_name") or attrs.get("type_description") or ""
    return str(names) if names else "VT.Sample"


def _best_family(attrs: dict) -> str:
    tags = attrs.get("tags") or []
    return str(tags[0]) if tags else "unknown"


def _iso(ts) -> str:
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    hash_file = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(ROOT, "data", "virus_db", "vt_entries.json")

    key = load_api_key()
    if not key:
        print("[ERROR] 请在 config/api_keys.json 填入 VirusTotal API Key")
        return 1

    with open(hash_file, "r", encoding="utf-8") as f:
        hashes = [line.strip() for line in f if line.strip()]

    results = []
    for i, h in enumerate(hashes):
        try:
            r = query_hash(key, h)
            if r.get("found"):
                results.append(r)
                print(f"[{i + 1}/{len(hashes)}] {h} -> {r['name']} "
                      f"(malicious={r['malicious_count']})")
            else:
                print(f"[{i + 1}/{len(hashes)}] {h} -> 未收录")
        except Exception as e:
            print(f"[{i + 1}/{len(hashes)}] {h} -> ERROR: {e}")
        if i < len(hashes) - 1:
            time.sleep(RATE_LIMIT_S)  # 严格限速

    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"[OK] 写入 {out_file}，共 {len(results)} 条")
    print("下一步：python scripts/merge_db.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
