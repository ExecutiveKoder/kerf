"""
Addon/interception chain.

An Addon can observe or mutate requests and responses. The proxy calls the chain
for every flow. This is the plugin seam: history, the passive scanner, the UI
intercept queue, and any user extension are all just Addons.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

from .http_message import Flow, HttpRequest, HttpResponse


class Addon(Protocol):
    async def on_request(self, flow: Flow) -> HttpRequest | None: ...
    async def on_response(self, flow: Flow) -> HttpResponse | None: ...
    async def on_flow_complete(self, flow: Flow) -> None: ...


class BaseAddon:
    """Convenience base so addons only override what they need."""

    async def on_request(self, flow: Flow) -> HttpRequest | None:
        return None

    async def on_response(self, flow: Flow) -> HttpResponse | None:
        return None

    async def on_flow_complete(self, flow: Flow) -> None:
        return None


class Interceptor:
    def __init__(self) -> None:
        self._addons: list[BaseAddon] = []
        # Scope: only flows matching an in-scope host get deep processing.
        self.scope_hosts: set[str] = set()

    def add(self, addon: BaseAddon) -> None:
        self._addons.append(addon)

    def in_scope(self, host: str) -> bool:
        if not self.scope_hosts:
            return True
        h = host.split(":")[0]
        return any(h == s or h.endswith("." + s) for s in self.scope_hosts)

    async def on_request(self, flow: Flow) -> HttpRequest:
        for addon in self._addons:
            res = await addon.on_request(flow)
            if res is not None:
                flow.request = res
        return flow.request

    async def on_response(self, flow: Flow) -> HttpResponse:
        for addon in self._addons:
            res = await addon.on_response(flow)
            if res is not None:
                flow.response = res
        return flow.response

    async def on_flow_complete(self, flow: Flow) -> None:
        results = await asyncio.gather(
            *(addon.on_flow_complete(flow) for addon in self._addons),
            return_exceptions=True,
        )
        for addon, res in zip(self._addons, results):
            if isinstance(res, Exception):
                print(f"[interceptor] {addon.__class__.__name__}."
                      f"on_flow_complete error: {res!r}")
