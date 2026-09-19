"""
core/i18n.py - 多语言支持（zh_CN / zh_TW / en_US 运行时切换）
"""
from __future__ import annotations

import json
import os
from typing import Dict


class I18n:
    LANGS = ("zh_CN", "zh_TW", "en_US")

    def __init__(self, lang_dir: str, language: str = "zh_CN"):
        self.lang_dir = lang_dir
        self.language = language
        self._tables: Dict[str, Dict[str, str]] = {}
        self._load_all()

    def _load_all(self) -> None:
        for lang in self.LANGS:
            path = os.path.join(self.lang_dir, f"{lang}.json")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self._tables[lang] = json.load(f)
            except Exception:
                self._tables[lang] = {}

    def set_language(self, lang: str) -> None:
        if lang in self._tables:
            self.language = lang

    def tr(self, key: str, default: str = "") -> str:
        table = self._tables.get(self.language, {})
        if key in table and table[key]:
            return table[key]
        zh = self._tables.get("zh_CN", {})
        return zh.get(key, default or key)

    def load_lang_json(self) -> Dict[str, str]:
        return self._tables.get(self.language, {})
