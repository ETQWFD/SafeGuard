"""
core/jar_launcher.py - 启动/管理 safeguard.jar 本地 HTTP 服务
JAR 在 127.0.0.1:17890 提供云服务接口，Python 通过 requests 调用。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from typing import Optional

import requests

BASE_URL = "http://127.0.0.1:17890"


class JarLauncher:
    def __init__(self, root: str):
        self.root = root
        self.jar_path = os.path.join(root, "safeguard.jar")
        self.process: Optional[subprocess.Popen] = None

    def available(self) -> bool:
        return os.path.exists(self.jar_path)

    def is_running(self) -> bool:
        try:
            r = requests.get(f"{BASE_URL}/api/version", timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    def start(self) -> bool:
        if self.is_running():
            return True
        if not self.available():
            return False
        java = shutil.which("java")
        if not java:
            return False
        self.process = subprocess.Popen(
            [java, "-jar", self.jar_path, self.root],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=self.root,
        )
        for _ in range(40):
            if self.is_running():
                return True
            if self.process.poll() is not None:
                return False
            time.sleep(0.25)
        return False

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        self.process = None

    # ---------- HTTP 调用 ----------

    @staticmethod
    def post(path: str, payload: dict, timeout: float = 60.0) -> dict:
        try:
            r = requests.post(f"{BASE_URL}{path}", json=payload, timeout=timeout)
            return r.json()
        except Exception as e:
            return {"ok": False, "error": f"jar service unavailable: {e}"}

    @staticmethod
    def get(path: str, timeout: float = 10.0) -> dict:
        try:
            r = requests.get(f"{BASE_URL}{path}", timeout=timeout)
            return r.json()
        except Exception as e:
            return {"ok": False, "error": f"jar service unavailable: {e}"}
