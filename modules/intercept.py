"""
Live intercept — hold a request (or response), edit it, forward or drop.

This is the Proxy habit: traffic pauses in a queue until the operator decides.
Out-of-scope hosts pass through untouched. Intercept off = transparent proxy.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from urllib.parse import urlsplit

from core.interceptor import BaseAddon
from core.http_message import Flow
from modules.repeater import Repeater


class FlowDropped(Exception):
    """Operator dropped this flow in intercept."""


class HeldItem:
    def __init__(self, kind: str, flow: Flow, raw: str, scheme: str) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.created = time.time()
        req = flow.request
        self.method = req.method
        self.host = req.host
        self.path = req.path
        self.url = req.url
        self.raw = raw
        self.scheme = scheme
        self.future: asyncio.Future = asyncio.get_event_loop().create_future()

    def public(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "created": self.created,
            "method": self.method, "host": self.host, "path": self.path,
            "url": self.url, "raw": self.raw, "scheme": self.scheme,
        }


class InterceptQueue(BaseAddon):
    def __init__(self, interceptor) -> None:
        self._scope = interceptor
        self.enabled = False
        self.hold_requests = True
        self.hold_responses = False
        self._held: dict[str, HeldItem] = {}

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "hold_requests": self.hold_requests,
            "hold_responses": self.hold_responses,
            "held": [h.public() for h in self._held.values()],
        }

    def configure(self, *, enabled=None, hold_requests=None, hold_responses=None):
        if enabled is not None:
            self.enabled = bool(enabled)
            if not self.enabled:
                self.forward_all()
        if hold_requests is not None:
            self.hold_requests = bool(hold_requests)
        if hold_responses is not None:
            self.hold_responses = bool(hold_responses)
        return self.status()

    def _should(self, host: str, kind: str) -> bool:
        if not self.enabled:
            return False
        if kind == "request" and not self.hold_requests:
            return False
        if kind == "response" and not self.hold_responses:
            return False
        return self._scope.in_scope(host.split(":")[0])

    async def _park(self, item: HeldItem):
        self._held[item.id] = item
        try:
            return await asyncio.wait_for(item.future, timeout=300)
        except asyncio.TimeoutError:
            return ("forward", item.raw)
        finally:
            self._held.pop(item.id, None)

    async def on_request(self, flow: Flow):
        if not self._should(flow.request.host, "request"):
            return None
        scheme = urlsplit(flow.request.url).scheme or "https"
        raw = flow.request.raw().decode("latin-1")
        item = HeldItem("request", flow, raw, scheme)
        action, edited = await self._park(item)
        if action == "drop":
            raise FlowDropped()
        if edited != raw:
            return Repeater.parse_raw(edited, scheme)
        return None

    async def on_response(self, flow: Flow):
        if not flow.response or not self._should(flow.request.host, "response"):
            return None
        scheme = urlsplit(flow.request.url).scheme or "https"
        raw = flow.response.raw().decode("latin-1")
        item = HeldItem("response", flow, raw, scheme)
        action, edited = await self._park(item)
        if action == "drop":
            raise FlowDropped()
        return None

    def _resolve(self, item: HeldItem, action: str, raw: str | None = None) -> bool:
        if item.future.done():
            return False
        payload = (action, raw if raw is not None else item.raw)
        loop = item.future.get_loop()
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            item.future.set_result(payload)
        else:
            loop.call_soon_threadsafe(item.future.set_result, payload)
        return True

    def forward(self, hold_id: str, raw: str | None = None) -> bool:
        item = self._held.get(hold_id)
        if not item:
            return False
        return self._resolve(item, "forward", raw)

    def drop(self, hold_id: str) -> bool:
        item = self._held.get(hold_id)
        if not item:
            return False
        return self._resolve(item, "drop")

    def forward_all(self) -> int:
        n = 0
        for item in list(self._held.values()):
            if self._resolve(item, "forward"):
                n += 1
        return n

    def drop_all(self) -> int:
        n = 0
        for item in list(self._held.values()):
            if self._resolve(item, "drop"):
                n += 1
        return n
