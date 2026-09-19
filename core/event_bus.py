"""
core/event_bus.py - 轻量事件总线（Qt 信号替代）
页面与核心通过字符串主题订阅/发布消息。
"""
from __future__ import annotations

from typing import Callable, Dict, List


class EventBus:
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = {}

    def subscribe(self, topic: str, handler: Callable) -> None:
        self._handlers.setdefault(topic, []).append(handler)

    def unsubscribe(self, topic: str, handler: Callable) -> None:
        handlers = self._handlers.get(topic, [])
        if handler in handlers:
            handlers.remove(handler)

    def publish(self, topic: str, *args, **kwargs) -> None:
        for handler in list(self._handlers.get(topic, [])):
            try:
                handler(*args, **kwargs)
            except Exception:
                continue
