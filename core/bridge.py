"""
core/bridge.py - 唯一业务桥接层
统一封装 DLL（本地查杀）与 JAR（云端情报）调用，向 UI 提供线程安全接口。
本文件只做调度与数据组装，不包含任何杀毒判定逻辑。
"""
from __future__ import annotations

import os
import threading
from typing import Callable, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from core.config_manager import ConfigManager
from core.dll_loader import DllLoader
from core.jar_launcher import JarLauncher


class BridgeSignals(QObject):
    scan_progress = pyqtSignal(int, int, str)     # cur, total, file
    scan_finished = pyqtSignal(dict)              # 目录扫描汇总
    file_scanned = pyqtSignal(dict)               # 单文件结果
    monitor_event = pyqtSignal(dict)              # 实时/USB/注册表事件
    quarantine_changed = pyqtSignal()
    jar_status = pyqtSignal(dict)


class Bridge:
    def __init__(self, root: str, config: ConfigManager):
        self.root = root
        self.config = config
        self.signals = BridgeSignals()
        self.dll = DllLoader()
        self.jar = JarLauncher(root)
        self._scan_lock = threading.Lock()
        self._scanning = False

    # ---------- DLL ----------

    def load_engine(self) -> bool:
        ok = self.dll.load(self.root)
        if not ok:
            return False
        r = self.dll.init(
            self.config.get_path("clamav_db", "data/clamav"),
            self.config.get_path("yara_rules", "data/virus_db/rules.yar"),
            self.config.get_path("json_db", "data/virus_db/signatures.json"),
            self.config.get_path("behavior_rules",
                                 "data/virus_db/behavior_rules.json"),
            self.config.get_path("white_list", "data/white_list.json"),
        )
        return r == 0

    def engine_version(self) -> str:
        return self.dll.version()

    def clamav_version(self) -> str:
        return self.dll.clamav_version()

    def yara_version(self) -> str:
        return self.dll.yara_version()

    def shutdown(self) -> None:
        self.stop_monitors()
        self.dll.shutdown()
        self.jar.stop()

    # ---------- 扫描 ----------

    def scan_file(self, path: str) -> dict:
        with self._scan_lock:
            result = self.dll.scan_file(path)
        self.signals.file_scanned.emit(result)
        return result

    def start_dir_scan(self, path: str) -> None:
        """后台线程执行目录扫描，通过信号回报进度。"""
        if self._scanning:
            return
        self._scanning = True

        def _progress(cur: int, total: int, name: str) -> None:
            self.signals.scan_progress.emit(cur, total, name)

        def _worker() -> None:
            try:
                result = self.dll.scan_dir(path, _progress)
                self.signals.scan_finished.emit(result)
            except Exception as e:
                self.signals.scan_finished.emit(
                    {"status": "error", "detail": str(e)})
            finally:
                self._scanning = False

        threading.Thread(target=_worker, daemon=True).start()

    def cancel_scan(self) -> None:
        self.dll.cancel_scan()

    def is_scanning(self) -> bool:
        return self._scanning

    # ---------- 监控 ----------

    def start_monitors(self) -> None:
        if self.config.get("realtime_monitor", True):
            dirs = [os.path.expanduser("~")]
            self.dll.start_realtime(dirs, self._on_event)
        if self.config.get("usb_monitor", True):
            self.dll.start_usb(self._on_event)
        if self.config.get("registry_monitor", False):
            self.dll.start_registry(self._on_event)

    def stop_monitors(self) -> None:
        try:
            self.dll.stop_realtime()
            self.dll.stop_usb()
            self.dll.stop_registry()
        except Exception:
            pass

    def _on_event(self, event: dict) -> None:
        self.signals.monitor_event.emit(event)

    # ---------- 隔离区 ----------

    def quarantine_add(self, path: str) -> int:
        code = self.dll.quarantine_add(path)
        if code == 0:
            self.signals.quarantine_changed.emit()
        return code

    def quarantine_restore(self, qid: str, restore_path: str = "") -> int:
        code = self.dll.quarantine_restore(qid, restore_path)
        if code == 0:
            self.signals.quarantine_changed.emit()
        return code

    def quarantine_delete(self, qid: str) -> int:
        code = self.dll.quarantine_delete(qid)
        if code == 0:
            self.signals.quarantine_changed.emit()
        return code

    def quarantine_list(self) -> List[dict]:
        data = self.dll.quarantine_list()
        return data if isinstance(data, list) else []

    # ---------- 进程与白名单 ----------

    def block_process(self, pid_or_path: str) -> int:
        return self.dll.block_process(pid_or_path)

    def allow_once(self, path: str) -> int:
        return self.dll.allow_once(path)

    def reload_virus_db(self) -> bool:
        r = self.dll.reload_virus_db(
            self.config.get_path("json_db", "data/virus_db/signatures.json"),
            self.config.get_path("yara_rules", "data/virus_db/rules.yar"))
        return r > 0

    # ---------- JAR（云端） ----------

    def jar_start(self) -> dict:
        started = self.jar.start()
        info = {"available": self.jar.available(), "running": started}
        self.signals.jar_status.emit(info)
        return info

    def vt_query(self, sha256: str) -> dict:
        return self.jar.post("/api/vt/query", {"sha256": sha256})

    def mb_query(self, sha256: str) -> dict:
        return self.jar.post("/api/mb/query", {"sha256": sha256})

    def intel_query(self, hash_value: str) -> dict:
        return self.jar.post("/api/intel/query", {"hash": hash_value})

    def db_status(self) -> dict:
        return self.jar.get("/api/virusdb/status")

    def db_update(self, mode: str = "all") -> dict:
        return self.jar.post("/api/virusdb/update", {"mode": mode})

    def report_generate(self, payload: dict) -> dict:
        return self.jar.post("/api/report/generate", payload)

    def log_archive(self, tag: str = "") -> dict:
        return self.jar.post("/api/log/archive", {"tag": tag})
