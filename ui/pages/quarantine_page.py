"""
ui/pages/quarantine_page.py - 隔离区：列表、恢复、删除
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView)

from ui.widgets.toast import Toast


class QuarantinePage(QWidget):
    def __init__(self, root, config, i18n, bus, bridge, parent=None):
        super().__init__(parent)
        self.root, self.config, self.i18n = root, config, i18n
        self.bus, self.bridge = bus, bridge

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        top = QHBoxLayout()
        self.title = QLabel("")
        self.title.setObjectName("pageTitle")
        top.addWidget(self.title)
        top.addStretch(1)
        self.btn_refresh = QPushButton("")
        self.btn_restore = QPushButton("")
        self.btn_delete = QPushButton("")
        self.btn_refresh.setObjectName("primaryBtn")
        self.btn_restore.setObjectName("ghostBtn")
        self.btn_delete.setObjectName("dangerBtn")
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_restore)
        top.addWidget(self.btn_delete)
        layout.addLayout(top)

        self.empty = QLabel("")
        self.empty.setObjectName("cardBody")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.empty)

        self.table = QTableWidget(0, 6)
        self.table.setObjectName("resultTable")
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table, 1)

        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_restore.clicked.connect(self._restore)
        self.btn_delete.clicked.connect(self._delete)
        bridge.signals.quarantine_changed.connect(self.refresh)

        self.retranslate()
        self.refresh()

    def refresh(self) -> None:
        items = self.bridge.quarantine_list()
        self.table.setRowCount(0)
        self.empty.setVisible(not items)
        for item in items:
            row = self.table.rowCount()
            self.table.insertRow(row)
            vals = [item.get("id", ""), item.get("original_path", ""),
                    item.get("sha256", "")[:16] + "…",
                    item.get("date", ""), item.get("size", ""),
                    item.get("threat_name", item.get("name", "-"))]
            for c, v in enumerate(vals):
                self.table.setItem(row, c, QTableWidgetItem(str(v)))

    def _selected_id(self) -> str:
        row = self.table.currentRow()
        if row < 0:
            return ""
        return self.table.item(row, 0).text()

    def _restore(self) -> None:
        qid = self._selected_id()
        if not qid:
            Toast(self, self.i18n.tr("quarantine.select_first", "请先选择一项"))
            return
        code = self.bridge.quarantine_restore(qid)
        Toast(self, self.i18n.tr("toast.restored", "已恢复") if code == 0
              else self.i18n.tr("toast.failed", "操作失败"))

    def _delete(self) -> None:
        qid = self._selected_id()
        if not qid:
            Toast(self, self.i18n.tr("quarantine.select_first", "请先选择一项"))
            return
        code = self.bridge.quarantine_delete(qid)
        Toast(self, self.i18n.tr("toast.deleted", "已彻底删除") if code == 0
              else self.i18n.tr("toast.failed", "操作失败"))

    def retranslate(self) -> None:
        t = self.i18n.tr
        self.title.setText(t("quarantine.title", "隔离区"))
        self.btn_refresh.setText(t("common.refresh", "刷新"))
        self.btn_restore.setText(t("quarantine.restore", "恢复"))
        self.btn_delete.setText(t("quarantine.delete", "彻底删除"))
        self.empty.setText(t("quarantine.empty",
                             "隔离区为空 · 所有隔离文件均经 AES-256 加密存放，可随时恢复"))
        self.table.setHorizontalHeaderLabels(
            [t("quarantine.id", "ID"), t("quarantine.orig", "原始路径"),
             t("quarantine.sha", "SHA256"), t("quarantine.date", "隔离时间"),
             t("quarantine.size", "大小"), t("quarantine.threat", "威胁")])
