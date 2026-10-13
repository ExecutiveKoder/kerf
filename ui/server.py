"""
Web UI backend.

A FastAPI app that exposes the tool's modules over HTTP + serves the single-page
UI. It runs in the same process as the proxy (on a different port) and talks to
the shared module instances.

Note: we intentionally do NOT use `from __future__ import annotations` here.
FastAPI resolves Pydantic body models from real annotations at route-build time;
stringized annotations break body parsing. Request models are module-level for
the same reason.
"""

from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from modules import decoder, comparer, sequencer

UI_DIR = Path(__file__).parent / "static"


# ----------------------------------------------------------- body models

class Scope(BaseModel):
    hosts: List[str]


class RepeaterReq(BaseModel):
    raw: str
    scheme: str = "https"


class DecodeReq(BaseModel):
    transform: str
    value: str


class CompareReq(BaseModel):
    a: str
    b: str


class SeqReq(BaseModel):
    samples: List[str]


def create_app(ctx) -> FastAPI:
    """ctx carries the shared module instances (see dastday.app.AppContext)."""
    app = FastAPI(title="DastDay")

    # ------------------------------------------------------------- history

    @app.get("/api/history")
    def history(host: str = "", method: str = "", status: int = 0, search: str = ""):
        return ctx.history.list(
            host=host or None, method=method or None,
            status=status or None, search=search or None,
        )

    @app.get("/api/flow/{flow_id}")
    def flow(flow_id: str):
        f = ctx.history.get(flow_id)
        if not f:
            raise HTTPException(404, "flow not found")
        return f

    @app.delete("/api/history")
    def clear_history():
        ctx.history.clear()
        return {"ok": True}

    # ------------------------------------------------------------- scope

    @app.get("/api/scope")
    def get_scope():
        return {"hosts": sorted(ctx.interceptor.scope_hosts)}

    @app.post("/api/scope")
    def set_scope(scope: Scope):
        ctx.interceptor.scope_hosts = set(scope.hosts)
        return {"hosts": sorted(ctx.interceptor.scope_hosts)}

    # ----------------------------------------------------------- repeater

    @app.post("/api/repeater/send")
    async def repeater_send(body: RepeaterReq):
        flow = await ctx.repeater.send_raw(body.raw, body.scheme)
        return {
            "status": flow.response.status_code if flow.response else None,
            "duration_ms": flow.duration_ms,
            "response_raw": flow.response.raw().decode("latin-1") if flow.response else "",
        }

    # ------------------------------------------------------------ decoder

    @app.post("/api/decoder")
    def decode(body: DecodeReq):
        try:
            return {"result": decoder.apply(body.transform, body.value)}
        except Exception as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/decoder/smart")
    def smart_decode(body: DecodeReq):
        return {"results": decoder.smart_decode(body.value)}

    # ------------------------------------------------------------ comparer

    @app.post("/api/comparer")
    def compare(body: CompareReq):
        return {
            "stats": comparer.stats(body.a, body.b),
            "word_diff": comparer.word_diff(body.a, body.b),
        }

    # ----------------------------------------------------------- sequencer

    @app.post("/api/sequencer")
    def seq(body: SeqReq):
        return sequencer.analyze(body.samples)

    # ------------------------------------------------------- passive scan

    @app.get("/api/findings")
    def findings():
        return ctx.passive.report()

    # --------------------------------------------------------------- CA

    @app.get("/api/ca-cert", response_class=PlainTextResponse)
    def ca_cert():
        return ctx.proxy.ca.ca_cert_pem.decode()

    # ------------------------------------------------------------- status

    @app.get("/api/status")
    def status():
        return {
            "proxy": f"{ctx.proxy.host}:{ctx.proxy.port}",
            "scope": sorted(ctx.interceptor.scope_hosts),
            "extensions": ctx.extensions_loaded,
            "flows": len(ctx.history.list(limit=100000)),
            "findings": len(ctx.passive.findings),
        }

    # --------------------------------------------------------------- UI

    if UI_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index():
        idx = UI_DIR / "index.html"
        return idx.read_text() if idx.exists() else "<h1>DastDay</h1>"

    return app
