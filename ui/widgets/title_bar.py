"""
ui/widgets/title_bar.py - 自定义标题栏（圆角窗口、可拖动、最小化/关闭）
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QPoint
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget


class TitleBar(QWidget):
    def __init__(self, title: str, parent: QWidget = None):
        super().__init__(parent)
        self._parent = parent
        self._drag_pos: QPoint | None = None
        self.setObjectName("titleBar")
        self.setFixedHeight(48)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 12, 0)
        layout.setSpacing(8)

        self.logo = QLabel("🛡")
        self.logo.setObjectName("titleLogo")
        self.title = QLabel(title)
        self.title.setObjectName("titleText")

        layout.addWidget(self.logo)
        layout.addWidget(self.title)
        layout.addStretch(1)

        for action, icon in (("min", "─"), ("close", "✕")):
            btn = QPushButton(icon)
            btn.setObjectName(f"titleBtn{action.capitalize()}")
            btn.setFixedSize(34, 30)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            if action == "min":
                btn.clicked.connect(self._on_min)
            else:
                btn.clicked.connect(self._on_close)
            layout.addWidget(btn)
            setattr(self, f"{action}_btn", btn)

    def _on_min(self) -> None:
        if self._parent:
            self._parent.showMinimized()

    def _on_close(self) -> None:
        if self._parent:
            self._parent.close()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event) -> None:
        if self._drag_pos and self._parent and \
                event.buttons() & Qt.MouseButton.LeftButton:
            delta = event.globalPosition().toPoint() - self._drag_pos
            self._parent.move(self._parent.pos() + delta)
            self._drag_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event) -> None:
        self._drag_pos = None

    def set_title(self, text: str) -> None:
        self.title.setText(text)
