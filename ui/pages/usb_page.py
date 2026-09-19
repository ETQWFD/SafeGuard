"""
ui/pages/usb_page.py - U盘页：插拔事件与自动扫描日志
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QDateTime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QListWidget, QListWidgetItem)


class UsbPage(QWidget):
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
        self.status = QLabel("")
        self.status.setObjectName("cardBody")
        top.addWidget(self.status)
        self.btn_clear = QPushButton("")
        self.btn_clear.setObjectName("ghostBtn")
        top.addWidget(self.btn_clear)
        layout.addLayout(top)

        self.log = QListWidget()
        self.log.setObjectName("eventList")
        layout.addWidget(self.log, 1)

        self.btn_clear.clicked.connect(self.log.clear)
        bridge.signals.monitor_event.connect(self._on_event)
        bus.subscribe("engine_ready", self._on_engine)
        self.retranslate()

    def _on_engine(self, ok: bool) -> None:
        self.status.setText(
            self.i18n.tr("usb.monitor_on", "U盘监控已开启")
            if ok else self.i18n.tr("usb.monitor_off", "U盘监控未运行"))

    def _on_event(self, event: dict) -> None:
        stamp = QDateTime.currentDateTime().toString("HH:mm:ss")
        etype = event.get("type", "?")
        if etype == "usb":
            ev = event.get("event", "")
            drive = event.get("drive", "")
            if ev == "inserted":
                text = f"[{stamp}] {self.i18n.tr('usb.inserted', '检测到U盘插入')}: {drive}"
                self.log.insertItem(0, QListWidgetItem(text))
            elif ev == "removed":
                text = f"[{stamp}] {self.i18n.tr('usb.removed', 'U盘已移除')}: {drive}"
                self.log.insertItem(0, QListWidgetItem(text))
            elif ev == "autorun_found":
                text = (f"[{stamp}] ⚠ {self.i18n.tr('usb.autorun', '发现 autorun.inf')} "
                        f"{drive} · {event.get('threat_name', '')}")
                item = QListWidgetItem(text)
                item.setForeground(Qt.GlobalColor.red)
                self.log.insertItem(0, item)
            elif ev == "threat":
                text = (f"[{stamp}] ⚠ {self.i18n.tr('usb.threat', 'U盘发现威胁')}: "
                        f"{event.get('path', '')} "
                        f"({event.get('threat_name', '')} / {event.get('engine', '')})")
                item = QListWidgetItem(text)
                item.setForeground(Qt.GlobalColor.red)
                self.log.insertItem(0, item)
        elif etype == "file":
            status = event.get("status", "")
            if status in ("infected", "suspicious"):
                text = (f"[{stamp}] ⚠ {self.i18n.tr('usb.realtime_hit', '实时防护拦截')}: "
                        f"{event.get('path', '')} ({event.get('threat_name', '')})")
                item = QListWidgetItem(text)
                item.setForeground(Qt.GlobalColor.red)
                self.log.insertItem(0, item)
        elif etype == "behavior":
            text = (f"[{stamp}] ⚠ {self.i18n.tr('usb.behavior', '行为规则命中')}: "
                    f"{event.get('name', '')} @ {event.get('path', '')}")
            item = QListWidgetItem(text)
            item.setForeground(Qt.GlobalColor.darkYellow)
            self.log.insertItem(0, item)
        elif etype == "registry":
            text = (f"[{stamp}] ⚠ {self.i18n.tr('usb.registry', '注册表变更')}: "
                    f"{event.get('path', '')}")
            item = QListWidgetItem(text)
            item.setForeground(Qt.GlobalColor.darkYellow)
            self.log.insertItem(0, item)

    def retranslate(self) -> None:
        t = self.i18n.tr
        self.title.setText(t("usb.title", "U盘与实时防护"))
        self.btn_clear.setText(t("common.clear", "清空"))
        self.status.setText(t("usb.waiting", "等待引擎初始化…"))
