"""
core/config_manager.py - 配置管理
负责 config/settings.json、config/paths.json、config/api_keys.json、
data/stats.json 的读写。全部为真实文件操作。
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict


class ConfigManager:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self._lock = threading.Lock()
        self.settings_path = os.path.join(self.root, "config", "settings.json")
        self.paths_path = os.path.join(self.root, "config", "paths.json")
        self.api_keys_path = os.path.join(self.root, "config", "api_keys.json")
        self.stats_path = os.path.join(self.root, "data", "stats.json")

        self.defaults = {
            "language": "zh_CN",
            "theme": "dark",           # light / dark
            "accent": "#4A90E2",       # 4 种主题色之一
            "auto_start": False,
            "realtime_monitor": True,
            "usb_monitor": True,
            "registry_monitor": False,
            "scan_max_depth": 3,
            "skip_whitelist": True,
            "threat_action": "quarantine",  # quarantine / alert
            "last_scan": None,
        }
        self.settings: Dict[str, Any] = dict(self.defaults)
        self.paths: Dict[str, Any] = {}
        self.api_keys: Dict[str, Any] = {}
        self.stats: Dict[str, Any] = self._default_stats()

        self._ensure_dirs()
        self.load()

    def _default_stats(self) -> Dict[str, Any]:
        return {
            "theme_usage": {"light": 0, "dark": 0},
            "mode_switches": {"light_to_dark": 0, "dark_to_light": 0},
            "lang_usage": {"zh_CN": 0, "zh_TW": 0, "en_US": 0},
            "scans": {"quick": 0, "full": 0, "custom": 0, "files": 0, "threats": 0},
            "start_count": 0,
        }

    def _ensure_dirs(self) -> None:
        for d in ("config", "lang", "data/virus_db", "data/clamav",
                  "data/yara_rules", "logs", "quarantine", "reports"):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)

    def load(self) -> None:
        with self._lock:
            self.settings = self._read_json(self.settings_path, dict(self.defaults))
            self.paths = self._read_json(self.paths_path, {})
            self.api_keys = self._read_json(self.api_keys_path,
                                            {"virus_total": ""})
            self.stats = self._read_json(self.stats_path, self._default_stats())

    def _read_json(self, path: str, fallback: Any) -> Any:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback

    def _write_json(self, path: str, data: Any) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    # ---------- 各配置 ----------

    def save_settings(self) -> None:
        with self._lock:
            self._write_json(self.settings_path, self.settings)

    def get(self, key: str, default: Any = None) -> Any:
        return self.settings.get(key, default if default is not None
                                 else self.defaults.get(key))

    def set(self, key: str, value: Any) -> None:
        self.settings[key] = value
        self.save_settings()

    def save_paths(self) -> None:
        with self._lock:
            self._write_json(self.paths_path, self.paths)

    def get_path(self, key: str, default: str = "") -> str:
        v = self.paths.get(key, default)
        if not os.path.isabs(v):
            v = os.path.join(self.root, v)
        return v

    def set_path(self, key: str, value: str) -> None:
        self.paths[key] = value
        self.save_paths()

    def get_api_key(self, service: str = "virus_total") -> str:
        return str(self.api_keys.get(service, "") or "")

    def set_api_key(self, key: str, service: str = "virus_total") -> None:
        self.api_keys[service] = key
        with self._lock:
            self._write_json(self.api_keys_path, self.api_keys)

    # ---------- 统计 ----------

    def update_stats(self, **kwargs) -> None:
        """增量更新 stats.json，如 theme_usage=dict(light=1)。"""
        with self._lock:
            for key, value in kwargs.items():
                if key in self.stats and isinstance(self.stats[key], dict) \
                        and isinstance(value, dict):
                    for k, v in value.items():
                        self.stats[key][k] = self.stats[key].get(k, 0) + v
                else:
                    self.stats[key] = self.stats.get(key, 0) + value
            self._write_json(self.stats_path, self.stats)
