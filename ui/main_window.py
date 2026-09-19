"""
ui/main_window.py - 主窗口
无边框 + 圆角 + 阴影容器；顶部标题栏；左侧菜单；QStackedWidget 页面。
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
                             QGraphicsDropShadowEffect, QFrame)

from core.theme_manager import ACCENTS
from ui.pages.about_page import AboutPage
from ui.pages.home_page import HomePage
from ui.pages.quarantine_page import QuarantinePage
from ui.pages.scan_page import ScanPage
from ui.pages.settings_page import SettingsPage
from ui.pages.usb_page import UsbPage
from ui.widgets.sidebar import Sidebar
from ui.widgets.title_bar import TitleBar


class MainWindow(QWidget):
    def __init__(self, root, config, i18n, theme, bus, bridge, parent=None):
        super().__init__(parent)
        self.root, self.config = root, config
        self.i18n, self.theme = i18n, theme
        self.bus, self.bridge = bus, bridge

        self.setWindowFlags(Qt.WindowType.FramelessWindowHint |
                            Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.resize(1080, 680)
        self.setMinimumSize(920, 600)

        # 容器（圆角 + 阴影）
        self.container = QFrame()
        self.container.setObjectName("windowContainer")
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(36)
        shadow.setOffset(0, 8)
        shadow.setColor(Qt.GlobalColor.black)
        self.container.setGraphicsEffect(shadow)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.addWidget(self.container)

        root_layout = QVBoxLayout(self.container)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self.title_bar = TitleBar("SafeGuard 安全卫士", self)
        root_layout.addWidget(self.title_bar)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        self.sidebar = Sidebar()
        self.sidebar.setFixedWidth(190)
        body.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        body.addWidget(self.stack, 1)
        root_layout.addLayout(body, 1)

        # 页面
        self.pages = {
            "home": HomePage(root, config, i18n, bus, bridge),
            "scan": ScanPage(root, config, i18n, bus, bridge),
            "quarantine": QuarantinePage(root, config, i18n, bus, bridge),
            "usb": UsbPage(root, config, i18n, bus, bridge),
            "settings": SettingsPage(root, config, i18n, bus, bridge),
            "about": AboutPage(root, config, i18n, bus, bridge),
        }
        for page in self.pages.values():
            self.stack.addWidget(page)

        self.sidebar.page_changed.connect(self._switch)
        bus.subscribe("navigate", self._navigate)
        bus.subscribe("language_changed", self._on_language)
        bus.subscribe("theme_changed", self._on_theme)

        self._retranslate_sidebar()
        self.sidebar.setCurrentRow(0)
        self._apply_theme(config.get("theme", "dark"),
                          config.get("accent", "#4A90E2"))

    # ---------- 导航 ----------

    def _switch(self, row: int) -> None:
        if 0 <= row < self.stack.count():
            self.stack.setCurrentIndex(row)

    def _navigate(self, index: int) -> None:
        if 0 <= index < self.sidebar.count():
            self.sidebar.setCurrentRow(index)

    # ---------- 语言 / 主题 ----------

    def _on_language(self, lang: str) -> None:
        self._retranslate_sidebar()
        for page in self.pages.values():
            page.retranslate()

    def _retranslate_sidebar(self) -> None:
        t = self.i18n.tr
        if self.sidebar.count() == 0:
            self.sidebar.setup([
                ("🏠", t("nav.home", "首页")),
                ("🔍", t("nav.scan", "扫描")),
                ("🔒", t("nav.quarantine", "隔离区")),
                ("💾", t("nav.usb", "U盘")),
                ("⚙️", t("nav.settings", "设置")),
                ("ℹ️", t("nav.about", "关于")),
            ])
        else:
            keys = [t("nav.home", "首页"), t("nav.scan", "扫描"),
                    t("nav.quarantine", "隔离区"), t("nav.usb", "U盘"),
                    t("nav.settings", "设置"), t("nav.about", "关于")]
            self.sidebar.retranslate(keys)

    def _on_theme(self, mode: str, accent: str) -> None:
        self._apply_theme(mode, accent)

    def _apply_theme(self, mode: str, accent: str) -> None:
        qss = self.theme.qss_for(mode, accent)
        self.setStyleSheet(qss)
