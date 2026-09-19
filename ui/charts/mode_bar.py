"""
ui/charts/mode_bar.py - 明暗模式切换次数柱状图（QPainter 绘制）
数据来源：data/stats.json -> mode_switches
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPainter, QFont
from PyQt6.QtWidgets import QWidget


class ModeBar(QWidget):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self._title = "Mode Switches"
        self._data = {"light_to_dark": 0, "dark_to_light": 0}
        self.setMinimumHeight(180)
        self.reload()

    def set_title(self, title: str) -> None:
        self._title = title
        self.update()

    def reload(self) -> None:
        self._data = dict(self.config.stats.get("mode_switches",
                                                {"light_to_dark": 0,
                                                 "dark_to_light": 0}))
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

        max_val = max(self._data.values(), default=0) or 1
        keys = ["light_to_dark", "dark_to_light"]
        colors = [QColor("#4A90E2"), QColor("#FF9800")]
        labels = ["☀→🌙", "🌙→☀"]
        names = ["light_to_dark", "dark_to_light"]

        base_y = 158
        bar_w = 52
        gap = 46
        x0 = self.width() / 2 - (len(keys) * (bar_w + gap) - gap) / 2

        for i, key in enumerate(keys):
            value = self._data.get(key, 0)
            h = int(110 * value / max_val)
            x = x0 + i * (bar_w + gap)
            p.setBrush(colors[i])
            p.drawRoundedRect(int(x), base_y - h, bar_w, h, 8, 8)
            p.setPen(QColor("#6B7280"))
            p.setFont(QFont())
            p.drawText(int(x - 6), base_y + 18, labels[i])
            p.drawText(int(x + 12), base_y - h - 6, str(value))

        p.setPen(QColor("#9CA3AF"))
        p.drawLine(int(x0 - 10), base_y, int(x0 + len(keys) * (bar_w + gap) - gap + 10), base_y)
