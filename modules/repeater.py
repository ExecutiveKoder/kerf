"""
Replay: edit a single request and send it again, inspecting each response.
This is manual testing you drive yourself against a target you choose.

It reuses the proxy's own upstream code path so a replayed request behaves
exactly like a proxied one.
"""

from __future__ import annotations

import time

from core.http_message import HttpRequest, HttpResponse, Flow
from core.proxy import ProxyServer


class Repeater:
    def __init__(self, proxy: ProxyServer) -> None:
        self._proxy = proxy
        self._history: list[Flow] = []

    @staticmethod
    def parse_raw(raw: str, scheme: str = "https") -> HttpRequest:
        """Parse a raw HTTP request (as edited in the UI) into an HttpRequest."""
        raw = raw.replace("\r\n", "\n")
        head, _, body = raw.partition("\n\n")
        lines = head.split("\n")
        method, target, version = (lines[0].split(" ") + ["", ""])[:3]
        headers: list[tuple[str, str]] = []
        host = ""
        for line in lines[1:]:
            if not line.strip():
                continue
            k, _, v = line.partition(":")
            k, v = k.strip(), v.strip()
            headers.append((k, v))
            if k.lower() == "host":
                host = v
        # Build absolute URL from Host header + origin-form target.
        if target.startswith("http"):
            url = target
        else:
            url = f"{scheme}://{host}{target}"
        return HttpRequest(method or "GET", url, headers, body.encode("latin-1"),
                           version or "HTTP/1.1")

    async def send(self, request: HttpRequest) -> Flow:
        flow = Flow(request=request)
        started = time.perf_counter()
        resp = await self._proxy._send_upstream(request)
        flow.duration_ms = (time.perf_counter() - started) * 1000
        flow.response = resp
        self._history.append(flow)
        return flow

    async def send_raw(self, raw: str, scheme: str = "https") -> Flow:
        return await self.send(self.parse_raw(raw, scheme))

    @property
    def history(self) -> list[Flow]:
        return self._history
