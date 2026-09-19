"""
ui/charts/lang_pie.py - 语言使用分布饼图（QPainter 绘制）
数据来源：data/stats.json -> lang_usage
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QColor, QPainter, QFont, QPen
from PyQt6.QtWidgets import QWidget


class LangPie(QWidget):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self._title = "Language Usage"
        self._labels = ("简体", "繁體", "English")
        self._data = {"zh_CN": 0, "zh_TW": 0, "en_US": 0}
        self.setMinimumHeight(180)
        self.reload()

    def set_title(self, title: str) -> None:
        self._title = title
        self.update()

    def retranslate(self, zh_cn: str, zh_tw: str, en: str) -> None:
        self._labels = (zh_cn, zh_tw, en)
        self.update()

    def reload(self) -> None:
        self._data = dict(self.config.stats.get("lang_usage",
                                                {"zh_CN": 0, "zh_TW": 0,
                                                 "en_US": 0}))
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

        total = sum(self._data.values())
        colors = [QColor("#4A90E2"), QColor("#7CB342"), QColor("#FFB7C5")]
        keys = ["zh_CN", "zh_TW", "en_US"]

        rect = QRectF(self.width() / 2 - 60, 32, 120, 120)
        if total <= 0:
            p.setBrush(QColor("#E5E7EB"))
            p.drawEllipse(rect)
            return

        start = 90 * 16
        for i, key in enumerate(keys):
            value = self._data.get(key, 0)
            if value <= 0:
                continue
            span = int(-360 * 16 * value / total)
            p.setBrush(colors[i])
            p.drawPie(rect, start, span)
            start += span

        # 图例
        y = 168
        for i, key in enumerate(keys):
            p.setBrush(colors[i])
            p.drawRect(int(self.width() / 2 - 58), y - 8, 10, 10)
            p.setPen(QColor("#6B7280"))
            p.setFont(QFont())
            p.drawText(int(self.width() / 2 - 42), y,
                       f"{self._labels[i]} {self._data.get(key, 0)}")
            y += 18
