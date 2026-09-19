"""
core/dll_loader.py - ctypes 加载 safeguard.dll 并调用 C 导出函数
唯一的 DLL 通信入口。所有字符串返回需调用 sg_free_string 释放。
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
from typing import Any, Callable, Optional

PROGRESS_CB = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_int,
                               ctypes.c_char_p)
EVENT_CB = ctypes.CFUNCTYPE(None, ctypes.c_char_p)


class DllLoader:
    def __init__(self):
        self.dll = None
        self.available = False
        self._last_errors: list = []

    def find_library(self, root: str) -> str:
        """按平台定位 safeguard 动态库。"""
        if platform.system() == "Windows":
            names = ["safeguard.dll"]
            base = root
        else:
            names = ["libsafeguard.so", "safeguard.so"]
            base = root
        for name in names:
            path = os.path.join(base, name)
            if os.path.exists(path):
                return path
        return ""

    def load(self, root: str) -> bool:
        path = self.find_library(root)
        if not path:
            self._last_errors.append(f"library not found under {root}")
            return False
        try:
            self.dll = ctypes.CDLL(path)
        except OSError as e:
            self._last_errors.append(f"load failed: {e}")
            return False
        self._bind()
        self.available = True
        return True

    def _bind(self) -> None:
        d = self.dll
        d.sg_init.argtypes = [ctypes.c_char_p] * 5
        d.sg_init.restype = ctypes.c_int

        d.sg_shutdown.argtypes = []
        d.sg_shutdown.restype = None

        for fn in ("sg_version", "sg_clamav_version", "sg_yara_version"):
            f = getattr(d, fn)
            f.argtypes = []
            f.restype = ctypes.c_char_p

        d.sg_scan_file.argtypes = [ctypes.c_char_p]
        d.sg_scan_file.restype = ctypes.c_char_p

        d.sg_scan_dir.argtypes = [ctypes.c_char_p, PROGRESS_CB]
        d.sg_scan_dir.restype = ctypes.c_char_p

        d.sg_cancel_scan.argtypes = []
        d.sg_cancel_scan.restype = ctypes.c_int

        d.sg_start_realtime_monitor.argtypes = [ctypes.c_char_p, EVENT_CB]
        d.sg_start_realtime_monitor.restype = ctypes.c_int
        d.sg_stop_realtime_monitor.argtypes = []
        d.sg_stop_realtime_monitor.restype = ctypes.c_int

        d.sg_start_usb_monitor.argtypes = [EVENT_CB]
        d.sg_start_usb_monitor.restype = ctypes.c_int
        d.sg_stop_usb_monitor.argtypes = []
        d.sg_stop_usb_monitor.restype = ctypes.c_int

        d.sg_start_registry_monitor.argtypes = [EVENT_CB]
        d.sg_start_registry_monitor.restype = ctypes.c_int
        d.sg_stop_registry_monitor.argtypes = []
        d.sg_stop_registry_monitor.restype = ctypes.c_int

        d.sg_quarantine_add.argtypes = [ctypes.c_char_p]
        d.sg_quarantine_add.restype = ctypes.c_int
        d.sg_quarantine_restore.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        d.sg_quarantine_restore.restype = ctypes.c_int
        d.sg_quarantine_delete.argtypes = [ctypes.c_char_p]
        d.sg_quarantine_delete.restype = ctypes.c_int
        d.sg_quarantine_list.argtypes = []
        d.sg_quarantine_list.restype = ctypes.c_char_p

        d.sg_block_process.argtypes = [ctypes.c_char_p]
        d.sg_block_process.restype = ctypes.c_int
        d.sg_allow_once.argtypes = [ctypes.c_char_p]
        d.sg_allow_once.restype = ctypes.c_int

        d.sg_reload_virus_db.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        d.sg_reload_virus_db.restype = ctypes.c_int

        d.sg_free_string.argtypes = [ctypes.c_char_p]
        d.sg_free_string.restype = None

    # ---------- 调用封装 ----------

    def _cstr(self, s: str) -> bytes:
        return s.encode("utf-8") if s else b""

    def _take_string(self, ptr) -> str:
        if not ptr:
            return ""
        try:
            value = ctypes.string_at(ptr).decode("utf-8", "replace")
        except Exception:
            value = ""
        self.dll.sg_free_string(ptr)
        return value

    def _parse(self, ptr) -> dict:
        text = self._take_string(ptr)
        try:
            return json.loads(text)
        except Exception:
            return {"status": "error", "detail": text}

    # ---------- 导出函数（全部带空库保护，无 DLL 时优雅降级） ----------

    def init(self, clamav_dir: str, yara_rules: str, json_db: str,
             behavior_rules: str, white_list: str) -> int:
        if not self.available:
            return -1
        try:
            return int(self.dll.sg_init(self._cstr(clamav_dir), self._cstr(yara_rules),
                                        self._cstr(json_db), self._cstr(behavior_rules),
                                        self._cstr(white_list)))
        except Exception:
            return -1

    def shutdown(self) -> None:
        if not self.available:
            return
        try:
            self.dll.sg_shutdown()
        except Exception:
            pass

    def version(self) -> str:
        if not self.available:
            return "engine-not-loaded"
        try:
            return self._take_string(self.dll.sg_version())
        except Exception:
            return "engine-not-loaded"

    def clamav_version(self) -> str:
        if not self.available:
            return "clamav:not-loaded"
        try:
            return self._take_string(self.dll.sg_clamav_version())
        except Exception:
            return "clamav:not-loaded"

    def yara_version(self) -> str:
        if not self.available:
            return "yara:not-loaded"
        try:
            return self._take_string(self.dll.sg_yara_version())
        except Exception:
            return "yara:not-loaded"

    def scan_file(self, path: str) -> dict:
        if not self.available:
            return {"status": "error", "threat_name": "", "engine": "none",
                    "detail": "杀毒引擎未加载（请先编译 safeguard.dll）"}
        try:
            return self._parse(self.dll.sg_scan_file(self._cstr(path)))
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def scan_dir(self, path: str,
                 progress_cb: Optional[Callable[[int, int, str], None]]) -> dict:
        if not self.available:
            return {"status": "error", "detail": "engine not loaded", "total": 0,
                    "scanned": 0, "clean": 0, "infected": [], "suspicious": [], "errors": []}
        cb = None
        if progress_cb is not None:
            def _wrap(cur: int, total: int, name: bytes) -> None:
                progress_cb(int(cur), int(total),
                            name.decode("utf-8", "replace") if name else "")
            cb = PROGRESS_CB(_wrap)
        try:
            return self._parse(self.dll.sg_scan_dir(self._cstr(path), cb))
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def cancel_scan(self) -> None:
        if not self.available:
            return
        try:
            self.dll.sg_cancel_scan()
        except Exception:
            pass

    def start_realtime(self, dirs: list, event_cb: Callable[[dict], None]) -> int:
        if not self.available:
            return -1
        try:
            import json as _json
            cb = EVENT_CB(lambda s: event_cb(self._decode_event(s)))
            self._realtime_cb = cb
            return int(self.dll.sg_start_realtime_monitor(
                self._cstr(_json.dumps(dirs)), cb))
        except Exception:
            return -1

    def stop_realtime(self) -> int:
        if not self.available:
            return 0
        try:
            return int(self.dll.sg_stop_realtime_monitor())
        except Exception:
            return 0

    def start_usb(self, event_cb: Callable[[dict], None]) -> int:
        if not self.available:
            return -1
        try:
            cb = EVENT_CB(lambda s: event_cb(self._decode_event(s)))
            self._usb_cb = cb
            return int(self.dll.sg_start_usb_monitor(cb))
        except Exception:
            return -1

    def stop_usb(self) -> int:
        if not self.available:
            return 0
        try:
            return int(self.dll.sg_stop_usb_monitor())
        except Exception:
            return 0

    def start_registry(self, event_cb: Callable[[dict], None]) -> int:
        if not self.available:
            return -1
        try:
            cb = EVENT_CB(lambda s: event_cb(self._decode_event(s)))
            self._reg_cb = cb
            return int(self.dll.sg_start_registry_monitor(cb))
        except Exception:
            return -1

    def stop_registry(self) -> int:
        if not self.available:
            return 0
        try:
            return int(self.dll.sg_stop_registry_monitor())
        except Exception:
            return 0

    @staticmethod
    def _decode_event(raw: bytes) -> dict:
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return {"type": "unknown", "raw": raw.decode("utf-8", "replace")}

    def quarantine_add(self, path: str) -> int:
        if not self.available:
            return -1
        try:
            return int(self.dll.sg_quarantine_add(self._cstr(path)))
        except Exception:
            return -1

    def quarantine_restore(self, qid: str, restore_path: str) -> int:
        if not self.available:
            return -1
        try:
            return int(self.dll.sg_quarantine_restore(self._cstr(qid),
                                                      self._cstr(restore_path)))
        except Exception:
            return -1

    def quarantine_delete(self, qid: str) -> int:
        if not self.available:
            return -1
        try:
            return int(self.dll.sg_quarantine_delete(self._cstr(qid)))
        except Exception:
            return -1

    def quarantine_list(self) -> list:
        if not self.available:
            return []
        try:
            return self._parse(self.dll.sg_quarantine_list())
        except Exception:
            return []

    def block_process(self, pid_or_path: str) -> int:
        if not self.available:
            return -1
        try:
            return int(self.dll.sg_block_process(self._cstr(pid_or_path)))
        except Exception:
            return -1

    def allow_once(self, path: str) -> int:
        if not self.available:
            return -1
        try:
            return int(self.dll.sg_allow_once(self._cstr(path)))
        except Exception:
            return -1

    def reload_virus_db(self, json_db: str, yara_rules: str) -> int:
        if not self.available:
            return -1
        try:
            return int(self.dll.sg_reload_virus_db(self._cstr(json_db),
                                                   self._cstr(yara_rules)))
        except Exception:
            return -1
