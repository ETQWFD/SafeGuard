"""
ui/widgets/sidebar.py - 左侧导航菜单
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QListWidget, QListWidgetItem


class Sidebar(QListWidget):
    page_changed = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFrameShape(QListWidget.Shape.NoFrame)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSpacing(4)
        self.currentRowChanged.connect(self.page_changed)
        self._items = []

    def setup(self, entries: list[tuple[str, str]]) -> None:
        """entries: [(icon, key), ...]，key 为 i18n 键。"""
        self._items = entries
        for icon, key in entries:
            item = QListWidgetItem(f"{icon}  {key}")
            item.setSizeHint(item.sizeHint().height() + 26, 46)
            self.addItem(item)

    def retranslate(self, keys: list[str]) -> None:
        for i, (icon, _key) in enumerate(self._items):
            if i < len(keys):
                self.item(i).setText(f"{icon}  {keys[i]}")
