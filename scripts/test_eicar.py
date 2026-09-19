#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_eicar.py - 生成 EICAR 测试文件并验证真实杀毒链路
流程：写 EICAR -> 计算真实哈希 -> 调用 DLL sg_scan_file
      （哈希库 / ClamAV / YARA 三重引擎真实检测）
用法：
    python scripts/test_eicar.py
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
         "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def find_dll() -> str:
    if platform.system() == "Windows":
        path = os.path.join(ROOT, "safeguard.dll")
    else:
        path = os.path.join(ROOT, "libsafeguard.so")
    return path if os.path.exists(path) else ""


def scan_with_ctypes(dll_path: str, file_path: str) -> dict:
    dll = ctypes.CDLL(dll_path)
    dll.sg_init.argtypes = [ctypes.c_char_p] * 5
    dll.sg_init.restype = ctypes.c_int
    dll.sg_scan_file.argtypes = [ctypes.c_char_p]
    dll.sg_scan_file.restype = ctypes.c_char_p
    dll.sg_free_string.argtypes = [ctypes.c_char_p]
    dll.sg_clamav_version.argtypes = []
    dll.sg_clamav_version.restype = ctypes.c_char_p
    dll.sg_yara_version.argtypes = []
    dll.sg_yara_version.restype = ctypes.c_char_p

    def cstr(s):
        return s.encode("utf-8") if s else b""

    r = dll.sg_init(
        cstr(os.path.join(ROOT, "data", "clamav")),
        cstr(os.path.join(ROOT, "data", "virus_db", "rules.yar")),
        cstr(os.path.join(ROOT, "data", "virus_db", "signatures.json")),
        cstr(os.path.join(ROOT, "data", "virus_db", "behavior_rules.json")),
        cstr(os.path.join(ROOT, "data", "white_list.json")),
    )
    if r != 0:
        return {"status": "error", "detail": "sg_init failed"}

    ptr = dll.sg_scan_file(cstr(file_path))
    text = ctypes.string_at(ptr).decode("utf-8", "replace") if ptr else "{}"
    dll.sg_free_string(ptr)
    clam = dll.sg_clamav_version()
    clam_txt = ctypes.string_at(clam).decode() if clam else "-"
    dll.sg_free_string(clam)
    dll.sg_shutdown()
    result = json.loads(text)
    result["clamav_version"] = clam_txt
    return result


def main() -> int:
    print("=" * 60)
    print("SafeGuard EICAR 真实杀毒验证")
    print("=" * 60)

    dll_path = find_dll()
    if not dll_path:
        print("[BLOCKER] 未找到 safeguard.dll / libsafeguard.so")
        print("         请先构建 C++ 模块：")
        print("         Windows: cd cpp_module && build.bat")
        print("         Linux:   cd cpp_module && ./build.sh")
        print("         （需先安装 ClamAV / YARA 开发库）")
        return 2

    tmp = os.path.join(tempfile.gettempdir(), "eicar_test.txt")
    with open(tmp, "w", encoding="ascii") as f:
        f.write(EICAR)
    print(f"[1] EICAR 测试文件已写入: {tmp}")

    print("[2] 调用 DLL 真实扫描…")
    result = scan_with_ctypes(dll_path, tmp)

    print(f"[3] 结果: status={result.get('status')} "
          f"threat={result.get('threat_name', '-')} "
          f"engine={result.get('engine', '-')}")
    print(f"    sha256={result.get('sha256', '-')}")
    print(f"    detail={result.get('detail', '-')}")
    print(f"    clamav={result.get('clamav_version', '-')}")

    if result.get("status") in ("infected", "suspicious"):
        print("\n[PASS] 引擎已真实识别 EICAR 测试文件，链路验证通过")
        return 0
    print("\n[FAIL] 未检出 EICAR。请检查：")
    print("  1) ClamAV 病毒库是否已下载（python scripts/update_clamav.py）")
    print("  2) YARA 规则是否加载（data/virus_db/rules.yar 应含 EICAR 规则）")
    print("  3) signatures.json 是否含 EICAR 哈希")
    return 1


if __name__ == "__main__":
    sys.exit(main())
