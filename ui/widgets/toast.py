"""
ui/widgets/toast.py - 轻量提示气泡
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtWidgets import QLabel, QWidget


class Toast(QLabel):
    def __init__(self, parent: QWidget, text: str, duration_ms: int = 2600):
        super().__init__(parent)
        self.setObjectName("toast")
        self.setText(text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.adjustSize()
        self._place()
        self.show()
        self._anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._anim.setDuration(320)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.start()
        QTimer.singleShot(duration_ms, self._fade_out)

    def _place(self) -> None:
        parent = self.parentWidget()
        if parent:
            x = (parent.width() - self.width()) // 2
            y = parent.height() - self.height() - 40
            self.move(max(x, 12), max(y, 12))

    def _fade_out(self) -> None:
        self._anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._anim.setDuration(360)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.0)
        self._anim.finished.connect(self.deleteLater)
        self._anim.start()
