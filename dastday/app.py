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
from modules.intruder import IntruderEngine
from modules.projects import ProjectManager
from modules.assistant import Assistant
from modules.intercept import InterceptQueue
from modules.browser import EmbeddedBrowser
from modules.upstream import UpstreamRoute
from modules.extensions import ExtensionAPI, ExtensionManager
from modules.rules import RuleEngine
from modules.session import SessionHandler
from modules.logger import EventLog
from modules.oast import OastListener
from modules.crawler import Crawler
from ui.server import create_app


@dataclass
class AppContext:
    interceptor: Interceptor
    proxy: ProxyServer
    history: HistoryStore
    passive: PassiveScanner
    repeater: Repeater
    active: ActiveScanEngine
    intruder: IntruderEngine
    projects: ProjectManager
    assistant: Assistant
    intercept: InterceptQueue
    rules: RuleEngine
    session: SessionHandler
    events: EventLog
    oast: OastListener
    crawler: Crawler
    extensions_loaded: list[str] = field(default_factory=list)
    browser: EmbeddedBrowser = field(default_factory=EmbeddedBrowser)
    upstream: UpstreamRoute = field(default_factory=UpstreamRoute)


def build_context(*, proxy_host="127.0.0.1", proxy_port=8080,
                  db_path="dastday.db", ext_dir="extensions",
                  projects_dir="projects") -> AppContext:
    interceptor = Interceptor()
    proxy = ProxyServer(proxy_host, proxy_port, interceptor)

    history = HistoryStore(db_path)
    passive = PassiveScanner()
    repeater = Repeater(proxy)

    # Active engine wired to the proxy's upstream path. It ships with the bundled
    # checks registered, but stays UNAUTHORIZED until the operator asserts a
    # scope: no check runs against any host until then.
    async def send(req):
        from core.http_message import Flow
        import time
        flow = Flow(request=req)
        t = time.perf_counter()
        flow.response = await proxy._send_upstream(req)
        flow.duration_ms = (time.perf_counter() - t) * 1000
        return flow

    active = ActiveScanEngine(send, authorized=False)
    active.register_defaults()

    # Intruder shares the active engine's authorization: a target host must be in
    # the authorized active scope before payload automation will run.
    def authz(url):
        return active.authorized and active._in_scope(url)

    intruder = IntruderEngine(repeater.send_raw, authz=authz)

    projects = ProjectManager(history=history, interceptor=interceptor,
                              passive=passive, active=active, db_path=db_path,
                              projects_dir=projects_dir)

    events = EventLog()
    rules = RuleEngine()
    session = SessionHandler(send_raw=repeater.send_raw)
    intercept = InterceptQueue(interceptor, rules=rules)
    # Rewrite and session cookies first; intercept sees the result; history last.
    interceptor.add(rules)
    interceptor.add(session)
    interceptor.add(intercept)
    interceptor.add(history)
    interceptor.add(passive)

    oast = OastListener(events=events)
    crawler = Crawler(send=send, interceptor=interceptor, history=history,
                      events=events)

    # Load extensions (passive + active examples ship; add your own checks too).
    api = ExtensionAPI(interceptor, passive, active, intruder)
    loaded = ExtensionManager(api, ext_dir).load_all()

    ctx = AppContext(interceptor, proxy, history, passive, repeater, active,
                     intruder, projects, None, intercept, rules, session,
                     events, oast, crawler, loaded)  # type: ignore[arg-type]
    ctx.assistant = Assistant(ctx)
    ctx.browser = EmbeddedBrowser()
    ctx.upstream = UpstreamRoute()
    ctx.proxy.upstream = ctx.upstream
    ctx.proxy.events = events
    return ctx


async def run(proxy_host="127.0.0.1", proxy_port=8080,
              ui_host="127.0.0.1", ui_port=8000, db_path="dastday.db"):
    ctx = build_context(proxy_host=proxy_host, proxy_port=proxy_port, db_path=db_path)
    app = create_app(ctx)

    config = uvicorn.Config(app, host=ui_host, port=ui_port, log_level="warning")
    server = uvicorn.Server(config)

    print(f"[sureguard] proxy   → http://{proxy_host}:{proxy_port}")
    print(f"[sureguard] web UI  → http://{ui_host}:{ui_port}")
    print(f"[sureguard] extensions loaded: {ctx.extensions_loaded or 'none'}")
    print("[sureguard] click Open browser in the UI — Chromium is already "
          "pointed at the proxy.")

    await asyncio.gather(
        ctx.proxy.serve_forever(),
        server.serve(),
    )
