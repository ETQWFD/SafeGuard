"""
ui/widgets/threat_dialog.py - 威胁详情弹窗（隔离 / 放行 / 忽略）
"""
from __future__ import annotations

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QFrame)

from ui.widgets.toast import Toast


class ThreatDialog(QDialog):
    def __init__(self, i18n, bridge, result: dict, parent=None):
        super().__init__(parent)
        self._i18n = i18n
        self._bridge = bridge
        self._result = result
        self.setWindowTitle(i18n.tr("threat.title", "威胁处理"))
        self.setModal(True)
        self.resize(520, 340)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 20)
        layout.setSpacing(14)

        title = QLabel(f"{i18n.tr('threat.found', '发现威胁')} · {result.get('threat_name', '')}")
        title.setObjectName("threatTitle")
        layout.addWidget(title)

        info = QFrame()
        info.setObjectName("threatInfo")
        v = QVBoxLayout(info)
        v.setContentsMargins(16, 12, 16, 12)
        rows = [
            ("path", result.get("path", "")),
            ("sha256", result.get("sha256", "")),
            ("md5", result.get("md5", "")),
            ("engine", result.get("engine", "")),
            ("detail", result.get("detail", "")),
            ("level", str(result.get("level", 0))),
        ]
        for label, value in rows:
            r = QHBoxLayout()
            r.addWidget(QLabel(i18n.tr(f"threat.{label}", label)))
            val = QLabel(value if value else "-")
            val.setWordWrap(True)
            val.setTextInteractionFlags(val.textInteractionFlags() |
                                        val.textInteractionFlags().TextSelectableByMouse)
            r.addWidget(val, 1)
            v.addLayout(r)
        layout.addWidget(info, 1)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        quarantine = QPushButton(i18n.tr("threat.quarantine", "隔离"))
        allow = QPushButton(i18n.tr("threat.allow", "放行"))
        cancel = QPushButton(i18n.tr("common.cancel", "取消"))
        for b in (quarantine, allow, cancel):
            b.setObjectName("primaryBtn" if b is quarantine else "ghostBtn")
            btn_row.addWidget(b)

        quarantine.clicked.connect(self._on_quarantine)
        allow.clicked.connect(self._on_allow)
        cancel.clicked.connect(self.reject)
        layout.addLayout(btn_row)

    def _toast(self, text: str) -> None:
        parent = self.parentWidget()
        if parent:
            Toast(parent, text)

    def _on_quarantine(self) -> None:
        path = self._result.get("path", "")
        if path:
            self._bridge.quarantine_add(path)
            self._toast(self._i18n.tr("toast.quarantined", "已隔离"))
        self.accept()

    def _on_allow(self) -> None:
        path = self._result.get("path", "")
        if path:
            self._bridge.allow_once(path)
            self._toast(self._i18n.tr("toast.allowed", "已放行"))
        self.accept()
