"""
SafeGuard 安全卫士 - 程序入口
Python 只做三件事：PyQt6 界面、ctypes 调用 DLL、requests 调用 JAR。
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon

from core.bridge import Bridge
from core.config_manager import ConfigManager
from core.event_bus import EventBus
from core.i18n import I18n
from core.theme_manager import ThemeManager
from ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("SafeGuard")
    app.setOrganizationName("SafeGuard")

    icon_path = os.path.join(ROOT, "assets", "icons", "app.ico")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    config = ConfigManager(ROOT)
    i18n = I18n(os.path.join(ROOT, "lang"), config.get("language", "zh_CN"))
    theme = ThemeManager(os.path.join(ROOT, "ui"))
    bus = EventBus()
    bridge = Bridge(ROOT, config)

    window = MainWindow(ROOT, config, i18n, theme, bus, bridge)
    window.show()

    # 引擎与云服务后台初始化（不阻塞界面）
    import threading

    def _bootstrap() -> None:
        engine_ok = bridge.load_engine()
        bridge.jar_start()
        bus.publish("engine_ready", engine_ok)
        if engine_ok:
            bridge.start_monitors()

    threading.Thread(target=_bootstrap, daemon=True).start()

    exit_code = app.exec()
    bridge.shutdown()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
