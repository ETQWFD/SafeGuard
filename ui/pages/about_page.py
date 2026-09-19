"""
ui/pages/about_page.py - 关于页
"""
from __future__ import annotations

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout)


class AboutPage(QWidget):
    def __init__(self, root, config, i18n, bus, bridge, parent=None):
        super().__init__(parent)
        self.root, self.config, self.i18n = root, config, i18n
        self.bus, self.bridge = bus, bridge

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        self.title = QLabel("")
        self.title.setObjectName("pageTitle")
        layout.addWidget(self.title)

        card = QFrame()
        card.setObjectName("infoCard")
        v = QVBoxLayout(card)
        v.setContentsMargins(20, 18, 20, 18)
        v.setSpacing(10)

        logo = QLabel("🛡 SafeGuard 安全卫士")
        logo.setObjectName("aboutLogo")
        v.addWidget(logo)

        self.version = QLabel("")
        self.version.setObjectName("cardBody")
        self.engine = QLabel("")
        self.engine.setObjectName("cardBody")
        self.clamav = QLabel("")
        self.clamav.setObjectName("cardBody")
        self.yara = QLabel("")
        self.yara.setObjectName("cardBody")
        self.arch = QLabel("")
        self.arch.setObjectName("cardBody")
        self.arch.setWordWrap(True)
        self.credits = QLabel("")
        self.credits.setObjectName("cardBody")
        self.credits.setWordWrap(True)
        for w in (self.version, self.engine, self.clamav, self.yara,
                  self.arch, self.credits):
            v.addWidget(w)
        layout.addWidget(card)
        layout.addStretch(1)

        bus.subscribe("engine_ready", self._on_engine)
        self.retranslate()

    def _on_engine(self, ok: bool) -> None:
        if ok:
            self.engine.setText(
                f"{self.i18n.tr('about.engine', '引擎')}: {self.bridge.engine_version()}")
            self.clamav.setText(f"ClamAV: {self.bridge.clamav_version()}")
            self.yara.setText(f"YARA: {self.bridge.yara_version()}")

    def retranslate(self) -> None:
        t = self.i18n.tr
        self.title.setText(t("about.title", "关于"))
        self.version.setText(
            f"{t('about.version', '版本')}: 1.0.0 (2026.09)")
        self.engine.setText(t("about.engine_pending", "引擎：等待初始化…"))
        self.clamav.setText("ClamAV: -")
        self.yara.setText("YARA: -")
        self.arch.setText(t("about.arch",
            "架构：Python (PyQt6 界面) → C++ DLL (ClamAV/YARA 真实查杀) → "
            "Java JAR (VirusTotal 云端情报)。本地优先，隐私不出门。"))
        self.credits.setText(t("about.credits",
            "致谢：ClamAV (Cisco Talos) · YARA (VirusTotal) · VirusTotal API · "
            "Qt for Python · 病毒库由用户自行维护。"))
