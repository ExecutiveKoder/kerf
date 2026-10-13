"""
Application wiring: build the shared context, start the proxy and the web UI
together.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

import uvicorn

from core.interceptor import Interceptor
from core.proxy import ProxyServer
from modules.history import HistoryStore
from modules.passive_scanner import PassiveScanner
from modules.repeater import Repeater
from modules.active_scan import ActiveScanEngine
from modules.extensions import ExtensionAPI, ExtensionManager
from ui.server import create_app


@dataclass
class AppContext:
    interceptor: Interceptor
    proxy: ProxyServer
    history: HistoryStore
    passive: PassiveScanner
    repeater: Repeater
    active: ActiveScanEngine
    extensions_loaded: list[str] = field(default_factory=list)


def build_context(*, proxy_host="127.0.0.1", proxy_port=8080,
                  db_path="dastday.db", ext_dir="extensions") -> AppContext:
    interceptor = Interceptor()
    proxy = ProxyServer(proxy_host, proxy_port, interceptor)

    history = HistoryStore(db_path)
    passive = PassiveScanner()
    repeater = Repeater(proxy)

    # Active engine wired to the proxy's upstream path, but UNAUTHORIZED and with
    # zero checks by default. It does nothing until an operator supplies checks
    # and authorizes a scope.
    async def send(req):
        from core.http_message import Flow
        import time
        flow = Flow(request=req)
        t = time.perf_counter()
        flow.response = await proxy._send_upstream(req)
        flow.duration_ms = (time.perf_counter() - t) * 1000
        return flow

    active = ActiveScanEngine(send, authorized=False)

    # Register addons in order: history + passive scanning observe every flow.
    interceptor.add(history)
    interceptor.add(passive)

    # Load extensions (passive example ships; active checks are operator-supplied).
    api = ExtensionAPI(interceptor, passive, active)
    loaded = ExtensionManager(api, ext_dir).load_all()

    return AppContext(interceptor, proxy, history, passive, repeater, active, loaded)


async def run(proxy_host="127.0.0.1", proxy_port=8080,
              ui_host="127.0.0.1", ui_port=8000, db_path="dastday.db"):
    ctx = build_context(proxy_host=proxy_host, proxy_port=proxy_port, db_path=db_path)
    app = create_app(ctx)

    config = uvicorn.Config(app, host=ui_host, port=ui_port, log_level="warning")
    server = uvicorn.Server(config)

    print(f"[dastday] proxy   → http://{proxy_host}:{proxy_port}")
    print(f"[dastday] web UI  → http://{ui_host}:{ui_port}")
    print(f"[dastday] extensions loaded: {ctx.extensions_loaded or 'none'}")
    print("[dastday] install the CA from the UI, then point your browser's "
          "proxy at the address above.")

    await asyncio.gather(
        ctx.proxy.serve_forever(),
        server.serve(),
    )
