"""
Event logger for CONNECT, drops, TLS, WebSocket, OAST, and proxy errors.

History only stores completed HTTP flows. This is the rest of the tape.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class EventLog:
    def __init__(self, maxlen: int = 2000) -> None:
        self._items: deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0

    def add(self, kind: str, message: str, **extra) -> dict:
        with self._lock:
            self._seq += 1
            item = {
                "id": self._seq,
                "ts": time.time(),
                "kind": kind,
                "message": message,
                **extra,
            }
            self._items.append(item)
            return item

    def list(self, *, kind: str = "", limit: int = 400) -> list:
        with self._lock:
            rows = list(self._items)
        if kind:
            rows = [r for r in rows if r.get("kind") == kind]
        return list(reversed(rows[-limit:]))

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def count(self) -> int:
        with self._lock:
            return len(self._items)
