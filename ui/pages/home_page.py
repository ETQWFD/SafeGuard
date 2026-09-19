"""
ui/pages/home_page.py - 首页：状态总览、快捷扫描、统计图表
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QFrame, QGridLayout)

from ui.charts.theme_pie import ThemePie
from ui.charts.mode_bar import ModeBar
from ui.charts.lang_pie import LangPie
from ui.widgets.toast import Toast


class HomePage(QWidget):
    def __init__(self, root, config, i18n, bus, bridge, parent=None):
        super().__init__(parent)
        self.root, self.config, self.i18n = root, config, i18n
        self.bus, self.bridge = bus, bridge

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # 顶部状态卡
        status_row = QHBoxLayout()
        self.status_card = QFrame()
        self.status_card.setObjectName("statusCard")
        sv = QHBoxLayout(self.status_card)
        sv.setContentsMargins(20, 16, 20, 16)
        self.status_icon = QLabel("🛡")
        self.status_icon.setObjectName("statusIcon")
        sv.addWidget(self.status_icon)
        self.status_text = QLabel("")
        self.status_text.setObjectName("statusText")
        sv.addWidget(self.status_text, 1)
        sv.addStretch(1)
        status_row.addWidget(self.status_card, 3)

        self.engine_card = QFrame()
        self.engine_card.setObjectName("infoCard")
        ev = QVBoxLayout(self.engine_card)
        ev.setContentsMargins(16, 12, 16, 12)
        self.engine_title = QLabel("")
        self.engine_title.setObjectName("cardTitle")
        self.engine_ver = QLabel("")
        self.engine_ver.setObjectName("cardBody")
        self.clamav_ver = QLabel("")
        self.clamav_ver.setObjectName("cardBody")
        ev.addWidget(self.engine_title)
        ev.addWidget(self.engine_ver)
        ev.addWidget(self.clamav_ver)
        ev.addStretch(1)
        status_row.addWidget(self.engine_card, 2)
        layout.addLayout(status_row)

        # 快捷扫描
        quick_row = QHBoxLayout()
        quick_row.setSpacing(12)
        self.btn_quick = QPushButton("")
        self.btn_full = QPushButton("")
        self.btn_custom = QPushButton("")
        for b in (self.btn_quick, self.btn_full, self.btn_custom):
            b.setObjectName("primaryBtn")
            b.setFixedHeight(44)
            quick_row.addWidget(b)
        layout.addLayout(quick_row)

        # 图表区
        charts = QGridLayout()
        charts.setSpacing(16)
        self.theme_pie = ThemePie(self.config)
        self.mode_bar = ModeBar(self.config)
        self.lang_pie = LangPie(self.config)
        for i, w in enumerate((self.theme_pie, self.mode_bar, self.lang_pie)):
            frame = QFrame()
            frame.setObjectName("chartCard")
            fv = QVBoxLayout(frame)
            fv.setContentsMargins(12, 12, 12, 12)
            fv.addWidget(w)
            charts.addWidget(frame, 0, i)
        layout.addLayout(charts, 1)

        self.btn_quick.clicked.connect(lambda: self._start_scan("quick"))
        self.btn_full.clicked.connect(lambda: self._start_scan("full"))
        self.btn_custom.clicked.connect(self._pick_custom)
        bus.subscribe("engine_ready", self._on_engine_ready)
        bus.subscribe("stats_changed", self._refresh_charts)

        self.retranslate()

    def _start_scan(self, mode: str) -> None:
        self.bus.publish("navigate", 1)
        self.bus.publish("start_scan", mode)

    def _pick_custom(self) -> None:
        self.bus.publish("navigate", 1)
        self.bus.publish("start_scan", "custom")

    def _on_engine_ready(self, ok: bool) -> None:
        self.engine_ver.setText(f"{self.i18n.tr('home.engine', '杀毒引擎')}: " +
                                (self.bridge.engine_version() if ok
                                 else self.i18n.tr("home.engine_missing",
                                                   "未加载（请先编译 DLL）")))
        self.clamav_ver.setText(self.bridge.clamav_version()
                                if ok else self.i18n.tr("home.clamav_missing",
                                                        "ClamAV 引擎未初始化"))
        self.status_text.setText(
            self.i18n.tr("home.status.safe", "防护正常 · 正在守护你的电脑")
            if ok else self.i18n.tr("home.status.pending", "等待引擎初始化"))
        self._refresh_charts()

    def _refresh_charts(self) -> None:
        self.theme_pie.reload()
        self.mode_bar.reload()
        self.lang_pie.reload()

    def retranslate(self) -> None:
        t = self.i18n.tr
        self.status_text.setText(t("home.status.safe", "防护正常 · 正在守护你的电脑"))
        self.engine_title.setText(t("home.engine_title", "引擎状态"))
        self.engine_ver.setText(t("home.engine_pending", "引擎加载中…"))
        self.clamav_ver.setText("")
        self.btn_quick.setText(t("home.quick_scan", "快速扫描"))
        self.btn_full.setText(t("home.full_scan", "全盘扫描"))
        self.btn_custom.setText(t("home.custom_scan", "自定义扫描"))
        self.theme_pie.set_title(t("charts.theme_usage", "主题色使用占比"))
        self.mode_bar.set_title(t("charts.mode_switches", "明暗切换次数"))
        self.lang_pie.set_title(t("charts.lang_usage", "语言使用分布"))
        self.theme_pie.retranslate(t("charts.light", "明亮"), t("charts.dark", "暗黑"))
        self.lang_pie.retranslate(
            t("charts.zh_cn", "简体"), t("charts.zh_tw", "繁体"), t("charts.en", "英文"))
