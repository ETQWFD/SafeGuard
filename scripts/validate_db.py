#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate_db.py - 校验病毒库格式
检查 signatures.json 结构、字段、哈希长度；检查 behavior_rules.json 与 rules.yar 基本语法。
用法：
    python scripts/validate_db.py
"""
from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def validate_signatures(path: str) -> int:
    errors = 0
    with open(path, "r", encoding="utf-8") as f:
        db = json.load(f)

    assert isinstance(db.get("version"), str), "version 必须为字符串"
    assert isinstance(db.get("updated"), str), "updated 必须为字符串"

    entries = db.get("entries", [])
    assert isinstance(entries, list), "entries 必须为数组"
    seen = set()
    for i, e in enumerate(entries):
        sha = e.get("sha256", "")
        md5 = e.get("md5", "")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
            print(f"[ERROR] entries[{i}] sha256 非法: {sha!r}")
            errors += 1
        if md5 and not re.fullmatch(r"[0-9a-fA-F]{32}", md5):
            print(f"[ERROR] entries[{i}] md5 非法: {md5!r}")
            errors += 1
        if sha.lower() in seen:
            print(f"[ERROR] entries[{i}] sha256 重复: {sha}")
            errors += 1
        seen.add(sha.lower())
        for field in ("name", "type", "family", "source"):
            if field not in e:
                print(f"[ERROR] entries[{i}] 缺少字段 {field}")
                errors += 1
        level = e.get("level")
        if not isinstance(level, int) or not (0 <= level <= 5):
            print(f"[ERROR] entries[{i}] level 非法: {level!r}")
            errors += 1

    if db.get("total") != len(entries):
        print(f"[WARN] total({db.get('total')}) 与 entries 数量({len(entries)}) 不一致")
    print(f"[OK] signatures.json: {len(entries)} 条，错误 {errors} 个")
    return errors


def validate_behavior(path: str) -> int:
    errors = 0
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    rules = data.get("rules", [])
    ids = set()
    for i, r in enumerate(rules):
        rid = r.get("id")
        if not rid:
            print(f"[ERROR] rules[{i}] 缺少 id")
            errors += 1
        elif rid in ids:
            print(f"[ERROR] rules[{i}] id 重复: {rid}")
            errors += 1
        ids.add(rid)
        if r.get("trigger") not in ("registry_write", "usb_insert",
                                    "file_write", "file_copy"):
            print(f"[ERROR] rules[{i}] trigger 非法: {r.get('trigger')}")
            errors += 1
        if r.get("action") not in ("alert", "block"):
            print(f"[ERROR] rules[{i}] action 非法: {r.get('action')}")
            errors += 1
    print(f"[OK] behavior_rules.json: {len(rules)} 条规则，错误 {errors} 个")
    return errors


def validate_yara(path: str) -> int:
    if not os.path.exists(path):
        print(f"[WARN] 未找到 YARA 规则文件: {path}")
        return 0
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    rules = re.findall(r"^\s*rule\s+(\w+)", text, re.MULTILINE)
    if not rules:
        print("[ERROR] rules.yar 未解析到任何 rule 定义")
        return 1
    # 括号配对粗查
    if text.count("(") != text.count(")"):
        print("[ERROR] rules.yar 括号不配对")
        return 1
    if text.count("{") != text.count("}"):
        print("[ERROR] rules.yar 花括号不配对")
        return 1
    print(f"[OK] rules.yar: {len(rules)} 条规则 {rules}")
    return 0


def main() -> int:
    base = os.path.join(ROOT, "data", "virus_db")
    total = 0
    total += validate_signatures(os.path.join(base, "signatures.json"))
    total += validate_behavior(os.path.join(base, "behavior_rules.json"))
    total += validate_yara(os.path.join(base, "rules.yar"))
    if total:
        print(f"\n[FAIL] 共 {total} 个错误，请修复后重试")
        return 1
    print("\n[OK] 病毒库校验全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
