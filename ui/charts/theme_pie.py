"""
ui/charts/theme_pie.py - 主题色使用占比环形图（QPainter 绘制）
数据来源：data/stats.json -> theme_usage
"""
from __future__ import annotations

import math

from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QColor, QPainter, QFont, QPen
from PyQt6.QtWidgets import QWidget

from core.theme_manager import ACCENTS


class ThemePie(QWidget):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self._title = "Theme Usage"
        self._labels = ("Light", "Dark")
        self._usage = {"light": 0, "dark": 0}
        self.setMinimumHeight(180)
        self.reload()

    def set_title(self, title: str) -> None:
        self._title = title
        self.update()

    def retranslate(self, light: str, dark: str) -> None:
        self._labels = (light, dark)
        self.update()

    def reload(self) -> None:
        self._usage = dict(self.config.stats.get("theme_usage",
                                                 {"light": 0, "dark": 0}))
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)

        f = QFont()
        f.setPointSize(10)
        f.setBold(True)
        p.setFont(f)
        p.drawText(self.rect().adjusted(0, 4, 0, 0),
                   Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                   self._title)

        total = sum(self._usage.values())
        rect = QRectF(self.width() / 2 - 62, 34, 124, 124)
        if total <= 0:
            p.setBrush(QColor("#E5E7EB"))
            p.drawPie(rect, 0, 360 * 16)
            p.setPen(QColor("#6B7280"))
            p.drawText(rect, Qt.AlignmentFlag.AlignCenter, "0")
            return

        start = 90 * 16
        colors = [QColor(ACCENTS[1]), QColor(ACCENTS[0])]  # 粉=明亮, 蓝=暗黑
        for i, key in enumerate(("light", "dark")):
            value = self._usage.get(key, 0)
            if value <= 0:
                continue
            span = int(-360 * 16 * value / total)
            p.setBrush(colors[i])
            p.drawPie(rect, start, span)
            start += span

        # 中心孔
        inner = QRectF(self.width() / 2 - 46, 50, 92, 92)
        p.setBrush(QColor(self._card_bg()))
        p.drawEllipse(inner)

        p.setPen(QColor("#1F2937"))
        p.setFont(QFont())
        p.drawText(inner, Qt.AlignmentFlag.AlignCenter, str(total))

        # 图例
        y = 172
        for i, key in enumerate(("light", "dark")):
            p.setBrush(colors[i])
            p.drawRect(int(self.width() / 2 - 58), y - 8, 10, 10)
            p.setPen(QColor("#6B7280"))
            p.drawText(int(self.width() / 2 - 42), y,
                       f"{self._labels[i]} {self._usage.get(key, 0)}")
            y += 18

    def _card_bg(self) -> str:
        return "#FFFFFF"
