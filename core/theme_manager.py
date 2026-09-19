"""
core/theme_manager.py - 主题管理
明亮/暗黑 × 4 种主题色（浅蓝 #4A90E2 / 樱花粉 #FFB7C5 / 草原绿 #7CB342 / 橘黄 #FF9800），
读取 ui/themes/*.qss 模板，替换 {accent} 后应用。
"""
from __future__ import annotations

import os

ACCENTS = ["#4A90E2", "#FFB7C5", "#7CB342", "#FF9800"]
ACCENT_NAMES = ["accent.blue", "accent.pink", "accent.green", "accent.orange"]


class ThemeManager:
    def __init__(self, ui_dir: str):
        self.themes_dir = os.path.join(ui_dir, "themes")

    def qss_for(self, mode: str, accent: str) -> str:
        name = "dark.qss" if mode == "dark" else "light.qss"
        path = os.path.join(self.themes_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                qss = f.read()
        except Exception:
            qss = ""
        return qss.replace("{accent}", accent).replace("{accent_rgb}",
                                                       self._rgb(accent))

    @staticmethod
    def _rgb(hex_color: str) -> str:
        h = hex_color.lstrip("#")
        return f"{int(h[0:2], 16)}, {int(h[2:4], 16)}, {int(h[4:6], 16)}"
