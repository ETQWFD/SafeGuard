"""
ui/widgets/theme_picker.py - 4 主题色选择器
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import QWidget, QHBoxLayout

from core.theme_manager import ACCENTS, ACCENT_NAMES


class _ColorDot(QWidget):
    clicked = pyqtSignal(str)

    def __init__(self, color: str, parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self._selected = False
        self.setFixedSize(34, 34)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_selected(self, selected: bool) -> None:
        self._selected = selected
        self.update()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._color.name())

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self.rect().adjusted(4, 4, -4, -4)
        p.setBrush(self._color)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(r)
        if self._selected:
            pen = p.pen()
            p.setPen(QColor("#ffffff"))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(self.rect().adjusted(2, 2, -2, -2))


class ThemePicker(QWidget):
    accent_changed = pyqtSignal(str)

    def __init__(self, current: str, parent=None):
        super().__init__(parent)
        self._dots = []
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        for color in ACCENTS:
            dot = _ColorDot(color)
            dot.clicked.connect(self._on_pick)
            self._dots.append(dot)
            layout.addWidget(dot)
        layout.addStretch(1)
        self.set_current(current)

    def _on_pick(self, color: str) -> None:
        self.set_current(color)
        self.accent_changed.emit(color)

    def set_current(self, color: str) -> None:
        for dot in self._dots:
            dot.set_selected(dot._color.name().upper() == color.upper())
