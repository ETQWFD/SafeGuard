"""
ui/pages/scan_page.py - 扫描页：全盘/自定义扫描、进度、结果表、取消
"""
from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QFrame, QProgressBar, QTableWidget,
                             QTableWidgetItem, QFileDialog, QHeaderView)

from ui.widgets.threat_dialog import ThreatDialog
from ui.widgets.toast import Toast


class ScanPage(QWidget):
    def __init__(self, root, config, i18n, bus, bridge, parent=None):
        super().__init__(parent)
        self.root, self.config, self.i18n = root, config, i18n
        self.bus, self.bridge = bus, bridge
        self._scanning = False
        self._mode = "full"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # 控制条
        controls = QHBoxLayout()
        self.title = QLabel("")
        self.title.setObjectName("pageTitle")
        controls.addWidget(self.title)
        controls.addStretch(1)
        self.btn_scan = QPushButton("")
        self.btn_cancel = QPushButton("")
        self.btn_report = QPushButton("")
        self.btn_scan.setObjectName("primaryBtn")
        self.btn_cancel.setObjectName("dangerBtn")
        self.btn_report.setObjectName("ghostBtn")
        controls.addWidget(self.btn_scan)
        controls.addWidget(self.btn_cancel)
        controls.addWidget(self.btn_report)
        layout.addLayout(controls)

        # 进度
        progress_frame = QFrame()
        progress_frame.setObjectName("infoCard")
        pv = QVBoxLayout(progress_frame)
        pv.setContentsMargins(16, 12, 16, 12)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress_label = QLabel("")
        self.progress_label.setObjectName("cardBody")
        pv.addWidget(self.progress)
        pv.addWidget(self.progress_label)
        layout.addWidget(progress_frame)

        # 结果表
        self.table = QTableWidget(0, 6)
        self.table.setObjectName("resultTable")
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table, 1)

        self.btn_scan.clicked.connect(lambda: self._start(self._mode))
        self.btn_cancel.clicked.connect(self._cancel)
        self.btn_report.clicked.connect(self._report)

        bus.subscribe("start_scan", self._on_request_scan)
        bridge.signals.scan_progress.connect(self._on_progress)
        bridge.signals.scan_finished.connect(self._on_finished)
        bridge.signals.file_scanned.connect(self._on_file_result)

        self.retranslate()

    # ---------- 动作 ----------

    def _on_request_scan(self, mode: str) -> None:
        if mode == "custom":
            path = QFileDialog.getExistingDirectory(
                self, self.i18n.tr("scan.choose_dir", "选择扫描目录"))
            if not path:
                return
            self._mode = "custom"
            self._start(path)
        elif mode == "quick":
            self._mode = "quick"
            self._start(os.path.expanduser("~"))
        else:
            self._mode = "full"
            if os.name == "nt":
                roots = [f"{chr(d)}:\\" for d in range(ord('C'), ord('Z') + 1)
                         if os.path.exists(f"{chr(d)}:\\")]
                self._start(roots[0] if roots else "C:\\")
            else:
                self._start("/")

    def _start(self, path: str) -> None:
        if self._scanning:
            Toast(self, self.i18n.tr("scan.busy", "扫描进行中"))
            return
        self.table.setRowCount(0)
        self.progress.setValue(0)
        self.progress_label.setText(
            self.i18n.tr("scan.starting", "正在扫描…") + f"  {path}")
        self._scanning = True
        self.config.update_stats(scans={"custom" if self._mode == "custom"
                                        else self._mode: 1})
        self.bridge.start_dir_scan(path)

    def _cancel(self) -> None:
        self.bridge.cancel_scan()
        self.progress_label.setText(self.i18n.tr("scan.canceling", "正在取消…"))

    def _report(self) -> None:
        rows = self.table.rowCount()
        threats = []
        infected = suspicious = 0
        for r in range(rows):
            status = self.table.item(r, 1).text()
            if status in ("infected", "suspicious"):
                threats.append(
                    f"{self.table.item(r, 0).text()} | "
                    f"{self.table.item(r, 2).text()} | "
                    f"{self.table.item(r, 3).text()}")
                if status == "infected":
                    infected += 1
                else:
                    suspicious += 1
        payload = {
            "mode": self._mode,
            "scanned": rows,
            "infected_count": infected,
            "suspicious_count": suspicious,
            "threats": "\n".join(threats),
        }
        result = self.bridge.report_generate(payload)
        if result.get("ok"):
            Toast(self, f"{self.i18n.tr('scan.report_done', '报告已生成')}: "
                        f"{result.get('html', '')}")
        else:
            Toast(self, self.i18n.tr("scan.report_fail",
                                     "报告生成失败（需先编译并启动 JAR）"))

    # ---------- 信号处理 ----------

    def _on_progress(self, cur: int, total: int, name: str) -> None:
        if total > 0:
            self.progress.setValue(int(cur * 100 / total))
        self.progress_label.setText(
            self.i18n.tr("scan.progress", "扫描进度") +
            f"  {cur}/{total}  {os.path.basename(name)}")

    def _on_finished(self, result: dict) -> None:
        self._scanning = False
        self.progress.setValue(100 if result.get("status") != "canceled" else 0)
        status = result.get("status", "error")
        if status == "error":
            self.progress_label.setText(
                self.i18n.tr("scan.failed", "扫描失败") +
                f": {result.get('detail', '')}")
            return
        self.progress_label.setText(
            self.i18n.tr("scan.done", "扫描完成") +
            f"  · {self.i18n.tr('scan.scanned', '已扫描')} "
            f"{result.get('scanned', 0)} · "
            f"{self.i18n.tr('scan.infected', '威胁')} "
            f"{len(result.get('infected', []))} · "
            f"{self.i18n.tr('scan.suspicious', '可疑')} "
            f"{len(result.get('suspicious', []))}")
        self.config.update_stats(scans={
            "files": result.get("scanned", 0),
            "threats": len(result.get("infected", [])) +
                       len(result.get("suspicious", []))})
        self._fill(result.get("infected", []), "infected")
        self._fill(result.get("suspicious", []), "suspicious")

    def _fill(self, items: list, status: str) -> None:
        for item in items:
            row = self.table.rowCount()
            self.table.insertRow(row)
            vals = [item.get("path", ""), status,
                    item.get("threat_name", ""), item.get("engine", ""),
                    item.get("detail", ""), str(self.config.get("last_scan", ""))]
            for c, v in enumerate(vals):
                self.table.setItem(row, c, QTableWidgetItem(v))

    def _on_file_result(self, result: dict) -> None:
        st = result.get("status", "")
        if st in ("infected", "suspicious"):
            ThreatDialog(self.i18n, self.bridge, result, self).exec()

    def retranslate(self) -> None:
        t = self.i18n.tr
        self.title.setText(t("scan.title", "扫描中心"))
        self.btn_scan.setText(t("scan.start", "开始扫描"))
        self.btn_cancel.setText(t("scan.cancel", "取消"))
        self.btn_report.setText(t("scan.report", "生成报告"))
        self.table.setHorizontalHeaderLabels(
            [t("scan.file", "文件"), t("scan.status", "状态"),
             t("scan.threat", "威胁"), t("scan.engine", "引擎"),
             t("scan.detail", "详情"), t("scan.time", "时间")])
