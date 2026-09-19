#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_icon.py - 生成 SafeGuard 应用图标 assets/icons/app.ico
纯 Python 实现：程序化绘制盾牌 + 对勾 PNG（zlib/struct），再封装为
ICO（含 256x256 PNG 条目，Vista+ 支持）。无需 PIL 等第三方库。

用法：
    python scripts/make_icon.py
"""
from __future__ import annotations

import math
import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "assets", "icons", "app.ico")
SIZE = 256
PRIMARY = (74, 144, 226, 255)      # #4A90E2 浅蓝
DARK = (24, 42, 74, 255)           # 盾内暗蓝
WHITE = (255, 255, 255, 255)
BG = (0, 0, 0, 0)                  # 透明底


def make_pixel(x: float, y: float) -> tuple:
    """判定 (x,y) 属于盾牌 / 暗区 / 对勾 / 背景，返回 RGBA。"""
    # 归一化到 [0,1]
    u, v = x / SIZE, y / SIZE
    # 盾牌轮廓（由两条贝塞尔近似）：中心 (0.5, 0.52)，半径按比例
    dx = (u - 0.5) * 2.0
    dy = (v - 0.54) * 2.2
    # 盾形：上部圆角矩形 + 下部收尖
    in_shield = False
    if abs(dx) <= 0.82 and dy >= -0.62:
        if dy <= 0.0:
            in_shield = abs(dx) <= 0.82 and dy >= -0.62
        else:
            # 下部三角形收窄
            half = 0.82 * (1.0 - dy * 0.45)
            in_shield = abs(dx) <= half and dy <= 0.62
    if not in_shield:
        return BG

    # 暗区内区（略小）
    in_dark = False
    if abs(dx) <= 0.68 and dy >= -0.50:
        if dy <= 0.0:
            in_dark = True
        else:
            half = 0.68 * (1.0 - dy * 0.5)
            in_dark = abs(dx) <= half and dy <= 0.50

    # 对勾：两条线段（斜 45°）
    def on_check():
        # 竖段：从 (0.32,0.50) 到 (0.47,0.66)；横段：(0.47,0.66) 到 (0.70,0.40)
        segs = [((0.32, 0.52), (0.46, 0.66)), ((0.46, 0.66), (0.70, 0.40))]
        for (ax, ay), (bx, by) in segs:
            # 点到线段距离
            vx, vy = bx - ax, by - ay
            wx, wy = u - ax, v - ay
            t = max(0.0, min(1.0, (wx * vx + wy * vy) / (vx * vx + vy * vy)))
            px, py = ax + t * vx, ay + t * vy
            if math.hypot(u - px, v - py) < 0.045:
                return True
        return False

    if on_check():
        return WHITE
    return DARK if in_dark else PRIMARY


def build_png(size: int) -> bytes:
    rows = []
    for y in range(size):
        row = bytearray([0])  # filter type 0
        for x in range(size):
            r, g, b, a = make_pixel(x + 0.5, y + 0.5)
            row += bytes((r, g, b, a))
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) +
            chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def build_ico(png: bytes, size: int) -> bytes:
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0,
                        1, 32, len(png), 22)
    return header + entry + png


def main() -> int:
    png = build_png(SIZE)
    ico = build_ico(png, SIZE)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(ico)
    # 同时导出 PNG 供宣传片/文档使用
    png_out = os.path.join(ROOT, "assets", "icons", "app.png")
    with open(png_out, "wb") as f:
        f.write(png)
    print(f"[OK] 图标已生成: {OUT} ({len(ico)} bytes)")
    print(f"[OK] PNG 副本:   {png_out} ({len(png)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
