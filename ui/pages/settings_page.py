"""
ui/pages/settings_page.py - 设置页：语言、主题、主题色、API Key、白名单、病毒库更新
"""
from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QComboBox, QPushButton, QFrame, QLineEdit,
                             QListWidget, QListWidgetItem, QFileDialog,
                             QCheckBox)

from core.theme_manager import ACCENT_NAMES, ACCENTS
from ui.widgets.theme_picker import ThemePicker
from ui.widgets.toast import Toast


class SettingsPage(QWidget):
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

        # 语言
        self.lang_frame = self._section("settings.language", "语言")
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(["简体中文 (zh_CN)", "繁體中文 (zh_TW)",
                                  "English (en_US)"])
        idx = {"zh_CN": 0, "zh_TW": 1, "en_US": 2}.get(config.get("language"), 0)
        self.lang_combo.setCurrentIndex(idx)
        self.lang_combo.currentIndexChanged.connect(self._on_lang)
        self.lang_frame.addWidget(self.lang_combo)

        # 明暗主题
        self.mode_frame = self._section("settings.theme_mode", "明暗模式")
        self.mode_check = QCheckBox("")
        self.mode_check.setChecked(config.get("theme") == "dark")
        self.mode_check.toggled.connect(self._on_mode)
        self.mode_frame.addWidget(self.mode_check)

        # 主题色
        self.accent_frame = self._section("settings.accent", "主题色")
        self.picker = ThemePicker(config.get("accent", "#4A90E2"))
        self.picker.accent_changed.connect(self._on_accent)
        self.accent_frame.addWidget(self.picker)

        # API Key
        self.key_frame = self._section("settings.api_key", "VirusTotal API Key")
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("VirusTotal v3 API Key（可选，用于云端情报）")
        self.key_edit.setText(config.get_api_key("virus_total"))
        self.key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_save = QPushButton("")
        self.key_save.setObjectName("primaryBtn")
        self.key_save.clicked.connect(self._save_key)
        self.key_frame.addWidget(self.key_edit)
        self.key_frame.addWidget(self.key_save)

        # 病毒库更新
        self.db_frame = self._section("settings.virusdb", "病毒库")
        self.db_status = QLabel("")
        self.db_status.setObjectName("cardBody")
        self.db_update = QPushButton("")
        self.db_update.setObjectName("primaryBtn")
        self.db_update.clicked.connect(self._update_db)
        self.db_frame.addWidget(self.db_status)
        self.db_frame.addWidget(self.db_update)

        # 白名单
        self.wl_frame = self._section("settings.whitelist", "白名单")
        wl_row = QHBoxLayout()
        self.wl_list = QListWidget()
        self.wl_list.setFixedHeight(120)
        self.wl_add = QPushButton("")
        self.wl_del = QPushButton("")
        self.wl_add.setObjectName("ghostBtn")
        self.wl_del.setObjectName("dangerBtn")
        self.wl_add.clicked.connect(self._add_whitelist)
        self.wl_del.clicked.connect(self._del_whitelist)
        wl_row.addWidget(self.wl_list, 1)
        col = QVBoxLayout()
        col.addWidget(self.wl_add)
        col.addWidget(self.wl_del)
        col.addStretch(1)
        wl_row.addLayout(col)
        self.wl_frame.addLayout(wl_row)

        # 行为选项
        self.beh_frame = self._section("settings.behavior", "防护选项")
        self.realtime_check = QCheckBox("")
        self.realtime_check.setChecked(config.get("realtime_monitor", True))
        self.realtime_check.toggled.connect(self._on_realtime)
        self.usb_check = QCheckBox("")
        self.usb_check.setChecked(config.get("usb_monitor", True))
        self.usb_check.toggled.connect(self._on_usb)
        self.beh_frame.addWidget(self.realtime_check)
        self.beh_frame.addWidget(self.usb_check)

        layout.addStretch(1)
        self._load_whitelist()
        self.retranslate()

    def _section(self, key: str, fallback: str) -> QVBoxLayout:
        frame = QFrame()
        frame.setObjectName("infoCard")
        v = QVBoxLayout(frame)
        v.setContentsMargins(16, 12, 16, 12)
        v.setSpacing(8)
        label = QLabel("")
        label.setObjectName("cardTitle")
        label.setProperty("sectionKey", key)
        label.setProperty("sectionFallback", fallback)
        v.addWidget(label)
        self.layout().addWidget(frame)
        return v

    # ---------- 事件 ----------

    def _on_lang(self, idx: int) -> None:
        lang = ["zh_CN", "zh_TW", "en_US"][idx]
        self.config.set("language", lang)
        self.config.update_stats(lang_usage={lang: 1})
        self.i18n.set_language(lang)
        self.bus.publish("language_changed", lang)
        self.retranslate()
        self.bus.publish("stats_changed")
        Toast(self, self.i18n.tr("toast.lang_changed", "语言已切换"))

    def _on_mode(self, dark: bool) -> None:
        old = self.config.get("theme", "dark")
        new = "dark" if dark else "light"
        self.config.set("theme", new)
        key = "light_to_dark" if new == "dark" else "dark_to_light"
        self.config.update_stats(mode_switches={key: 1},
                                 theme_usage={new: 1})
        self.bus.publish("theme_changed", new,
                         self.config.get("accent", "#4A90E2"))
        self.bus.publish("stats_changed")
        Toast(self, self.i18n.tr("toast.theme_changed", "主题已切换"))

    def _on_accent(self, color: str) -> None:
        self.config.set("accent", color)
        usage = {name: 0 for name in ACCENTS}
        usage[color.upper()] = 1
        self.config.update_stats(theme_usage=usage)
        self.bus.publish("theme_changed", self.config.get("theme", "dark"), color)
        self.bus.publish("stats_changed")

    def _save_key(self) -> None:
        self.config.set_api_key(self.key_edit.text().strip(), "virus_total")
        Toast(self, self.i18n.tr("toast.saved", "已保存"))

    def _update_db(self) -> None:
        Toast(self, self.i18n.tr("settings.updating", "正在更新病毒库…"))
        result = self.bridge.db_update("all")
        if result.get("ok"):
            mb = result.get("malwarebazaar", {})
            self.db_status.setText(
                f"{self.i18n.tr('settings.db_done', '更新完成')} · "
                f"MalwareBazaar +{mb.get('added', 0)} 条 · "
                f"YARA {result.get('yara', {}).get('downloaded', 0)} 个规则文件")
        else:
            self.db_status.setText(
                self.i18n.tr("settings.db_fail", "更新失败") +
                f": {result.get('error', '')}")

    def _load_whitelist(self) -> None:
        self.wl_list.clear()
        path = os.path.join(self.root, "data", "white_list.json")
        try:
            import json
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for p in data.get("paths", []):
                self.wl_list.addItem(QListWidgetItem(p))
        except Exception:
            pass

    def _add_whitelist(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, self.i18n.tr("settings.choose_wl", "选择要信任的目录"))
        if not path:
            return
        self.wl_list.addItem(QListWidgetItem(path))
        self._save_whitelist()
        self.bridge.reload_virus_db()

    def _del_whitelist(self) -> None:
        for item in self.wl_list.selectedItems():
            self.wl_list.takeItem(self.wl_list.row(item))
        self._save_whitelist()
        self.bridge.reload_virus_db()

    def _save_whitelist(self) -> None:
        import json
        paths = [self.wl_list.item(i).text() for i in range(self.wl_list.count())]
        path = os.path.join(self.root, "data", "white_list.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"paths": paths}, f, ensure_ascii=False, indent=2)

    def _on_realtime(self, checked: bool) -> None:
        self.config.set("realtime_monitor", checked)
        if checked:
            self.bridge.dll.start_realtime(
                [os.path.expanduser("~")], self.bridge._on_event)
        else:
            self.bridge.dll.stop_realtime()

    def _on_usb(self, checked: bool) -> None:
        self.config.set("usb_monitor", checked)
        if checked:
            self.bridge.dll.start_usb(self.bridge._on_event)
        else:
            self.bridge.dll.stop_usb()

    def retranslate(self) -> None:
        t = self.i18n.tr
        self.title.setText(t("settings.title", "设置"))
        for i in range(self.layout().count()):
            item = self.layout().itemAt(i)
            w = item.widget() if item else None
            if w and isinstance(w, QFrame):
                for lbl in w.findChildren(QLabel):
                    key = lbl.property("sectionKey")
                    fallback = lbl.property("sectionFallback")
                    if key:
                        lbl.setText(t(key, fallback))
        self.mode_check.setText(t("settings.dark_mode", "暗黑模式"))
        self.key_save.setText(t("common.save", "保存"))
        self.db_update.setText(t("settings.db_update_btn", "在线更新病毒库"))
        self.db_status.setText(t("settings.db_idle", "病毒库由本地维护（JSON/YARA/CVD）"))
        self.wl_add.setText(t("settings.wl_add", "添加目录"))
        self.wl_del.setText(t("settings.wl_del", "移除"))
        self.realtime_check.setText(t("settings.realtime", "文件实时监控"))
        self.usb_check.setText(t("settings.usb", "U盘自动扫描"))
