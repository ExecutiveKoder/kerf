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
from typing import List, Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.http_message import Flow
from modules import decoder, comparer, sequencer, payloads, reporting
from modules.active_scan import discover_insertion_points
from modules.assistant import list_providers
from modules.repeater import Repeater

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


class AuthorizeReq(BaseModel):
    hosts: List[str]


class ActiveScanReq(BaseModel):
    flow_id: str


class IntruderStartReq(BaseModel):
    template: str
    scheme: str = "https"
    attack_type: str = "sniper"
    set_names: List[str] = []
    custom: Optional[List[List[str]]] = None
    grep: List[str] = []
    concurrency: int = 20
    throttle_ms: int = 0


class IntruderPreviewReq(BaseModel):
    template: str
    attack_type: str = "sniper"
    set_names: List[str] = []
    custom: Optional[List[List[str]]] = None


class ProjectSaveReq(BaseModel):
    name: str
    note: str = ""


class ProjectNameReq(BaseModel):
    name: str


class AssistantSettingsReq(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    enabled: Optional[bool] = None


class AssistantChatReq(BaseModel):
    message: str


class InterceptCfg(BaseModel):
    enabled: Optional[bool] = None
    hold_requests: Optional[bool] = None
    hold_responses: Optional[bool] = None


class InterceptAction(BaseModel):
    raw: Optional[str] = None


class HostScanReq(BaseModel):
    host: str


class UpstreamReq(BaseModel):
    enabled: Optional[bool] = None
    preset: Optional[str] = None
    kind: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None


def _request_from_history(ctx, flow_id: str):
    row = ctx.history.get(flow_id)
    if not row:
        raise HTTPException(404, "flow not found")
    scheme = urlsplit(row["url"]).scheme or "https"
    return Repeater.parse_raw(row["req_raw"], scheme)


def create_app(ctx) -> FastAPI:
    """ctx carries the shared module instances (see dastday.app.AppContext)."""
    app = FastAPI(title="SureGuard")

    # ------------------------------------------------------------- history

    @app.get("/api/history")
    def history(host: str = "", method: str = "", status: int = 0, search: str = "",
                mime: str = "", hide_noise: bool = False, status_class: int = 0,
                path: str = ""):
        return ctx.history.list(
            host=host or None, method=method or None,
            status=status or None, search=search or None,
            mime_contains=mime or None, hide_noise=hide_noise,
            status_class=status_class or None, path_prefix=path or None,
        )

    @app.get("/api/sitemap")
    def sitemap():
        return ctx.history.sitemap()

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

    # ---------------------------------------------------- payload/issue libs

    @app.get("/api/payload-sets")
    def payload_sets():
        return payloads.list_payload_sets()

    @app.get("/api/issues")
    def issues():
        return payloads.list_issue_types()

    # -------------------------------------------------------- active scanner

    @app.get("/api/active/status")
    def active_status():
        return {
            "authorized": ctx.active.authorized,
            "scope": sorted(ctx.active.scope_hosts),
            "checks": ctx.active.check_names,
            "findings": len(ctx.active.findings),
            "last_scan": ctx.active.last_scan,
        }

    @app.post("/api/active/authorize")
    def active_authorize(body: AuthorizeReq):
        ctx.active.authorize_scope(set(body.hosts))
        return {"authorized": ctx.active.authorized,
                "scope": sorted(ctx.active.scope_hosts)}

    @app.post("/api/active/revoke")
    def active_revoke():
        ctx.active.revoke()
        return {"authorized": ctx.active.authorized}

    @app.get("/api/active/points")
    def active_points(flow_id: str):
        req = _request_from_history(ctx, flow_id)
        pts = discover_insertion_points(req)
        return {"url": req.url,
                "points": [{"kind": p.kind, "name": p.name, "value": p.value}
                           for p in pts]}

    @app.post("/api/active/scan")
    async def active_scan(body: ActiveScanReq):
        req = _request_from_history(ctx, body.flow_id)
        try:
            found = await ctx.active.scan_flow(Flow(request=req))
        except PermissionError as exc:
            raise HTTPException(403, str(exc))
        return {"findings": [f.to_dict() for f in found],
                "total": len(ctx.active.findings)}

    @app.get("/api/active/findings")
    def active_findings():
        return ctx.active.report()

    @app.delete("/api/active/findings")
    def active_clear():
        ctx.active.clear()
        return {"ok": True}

    @app.post("/api/active/scan-host")
    def active_scan_host(body: HostScanReq):
        host = body.host.strip()
        if not host:
            raise HTTPException(400, "host required")
        rows = ctx.history.list(host=host, hide_noise=True, limit=80)
        flows = []
        for row in rows:
            full = ctx.history.get(row["id"])
            if not full or not full.get("req_raw"):
                continue
            scheme = urlsplit(full["url"]).scheme or "https"
            flows.append(Flow(request=Repeater.parse_raw(full["req_raw"], scheme)))
        try:
            return ctx.active.start_job(host, flows)
        except PermissionError as exc:
            raise HTTPException(403, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/active/jobs")
    def active_jobs():
        return ctx.active.list_jobs()

    @app.get("/api/active/job/{job_id}")
    def active_job(job_id: str):
        j = ctx.active.job(job_id)
        if not j:
            raise HTTPException(404, "job not found")
        return j

    # -------------------------------------------------------------- intruder

    @app.post("/api/intruder/preview")
    def intruder_preview(body: IntruderPreviewReq):
        return ctx.intruder.preview(body.template, body.attack_type,
                                    body.set_names, body.custom)

    @app.post("/api/intruder/start")
    def intruder_start(body: IntruderStartReq):
        try:
            return ctx.intruder.start(
                template=body.template, scheme=body.scheme,
                attack_type=body.attack_type, set_names=body.set_names,
                custom=body.custom, grep=body.grep,
                concurrency=body.concurrency, throttle_ms=body.throttle_ms)
        except PermissionError as exc:
            raise HTTPException(403, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/intruder/attacks")
    def intruder_attacks():
        return ctx.intruder.list_attacks()

    @app.get("/api/intruder/attack/{attack_id}")
    def intruder_attack(attack_id: str):
        state = ctx.intruder.public_state(attack_id)
        if not state:
            raise HTTPException(404, "attack not found")
        return state

    @app.post("/api/intruder/stop/{attack_id}")
    def intruder_stop(attack_id: str):
        return {"stopped": ctx.intruder.stop(attack_id)}

    # -------------------------------------------------------------- projects

    @app.get("/api/projects")
    def projects_list():
        return {"current": ctx.projects.current, "projects": ctx.projects.list()}

    @app.post("/api/projects/save")
    def projects_save(body: ProjectSaveReq):
        if not body.name.strip():
            raise HTTPException(400, "project name required")
        return ctx.projects.save(body.name, body.note)

    @app.post("/api/projects/load")
    def projects_load(body: ProjectNameReq):
        try:
            return ctx.projects.load(body.name)
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc))

    @app.post("/api/projects/delete")
    def projects_delete(body: ProjectNameReq):
        return {"deleted": ctx.projects.delete(body.name)}

    # --------------------------------------------------------------- report

    @app.get("/api/report")
    def report(format: str = "html"):
        data = reporting.build_report(
            history=ctx.history, passive=ctx.passive, active=ctx.active,
            interceptor=ctx.interceptor,
            project=(ctx.projects.current or ""))
        if format == "json":
            return JSONResponse(data)
        html = reporting.render_html(data)
        return HTMLResponse(html, headers={
            "Content-Disposition": "attachment; filename=sureguard-report.html"})

    # --------------------------------------------------------------- CA

    @app.get("/api/intercept")
    def intercept_status():
        return ctx.intercept.status()

    @app.post("/api/intercept")
    def intercept_cfg(body: InterceptCfg):
        return ctx.intercept.configure(
            enabled=body.enabled, hold_requests=body.hold_requests,
            hold_responses=body.hold_responses)

    @app.post("/api/intercept/forward/{hold_id}")
    def intercept_forward(hold_id: str, body: InterceptAction = InterceptAction()):
        if not ctx.intercept.forward(hold_id, body.raw):
            raise HTTPException(404, "held item not found")
        return ctx.intercept.status()

    @app.post("/api/intercept/drop/{hold_id}")
    def intercept_drop(hold_id: str):
        if not ctx.intercept.drop(hold_id):
            raise HTTPException(404, "held item not found")
        return ctx.intercept.status()

    @app.post("/api/intercept/forward-all")
    def intercept_forward_all():
        return {"forwarded": ctx.intercept.forward_all()}

    @app.post("/api/intercept/drop-all")
    def intercept_drop_all():
        return {"dropped": ctx.intercept.drop_all()}

    @app.get("/api/browser")
    def browser_status():
        return ctx.browser.status()

    @app.post("/api/browser/open")
    async def browser_open():
        return await ctx.browser.open(ctx.proxy.host, ctx.proxy.port)

    @app.get("/api/upstream")
    def upstream_get():
        return ctx.upstream.public()

    @app.post("/api/upstream")
    def upstream_set(body: UpstreamReq):
        patch = body.model_dump(exclude_none=True) if hasattr(body, "model_dump") else body.dict(exclude_none=True)
        return ctx.upstream.configure(patch)

    @app.post("/api/upstream/test")
    async def upstream_test():
        return await ctx.upstream.test()

    @app.get("/api/ca-cert", response_class=PlainTextResponse)
    def ca_cert():
        return ctx.proxy.ca.ca_cert_pem.decode()

    # ----------------------------------------------------------- assistant

    @app.get("/api/assistant/providers")
    def assistant_providers():
        return list_providers()

    @app.get("/api/assistant/settings")
    def assistant_settings():
        return ctx.assistant.public()

    @app.post("/api/assistant/settings")
    def assistant_save(body: AssistantSettingsReq):
        data = body.model_dump() if hasattr(body, "model_dump") else body.dict()
        patch = {k: v for k, v in data.items() if v is not None}
        return ctx.assistant.save_settings(patch)

    @app.post("/api/assistant/test")
    async def assistant_test():
        return await ctx.assistant.test_connection()

    @app.get("/api/assistant/models")
    async def assistant_models():
        return await ctx.assistant.list_models()

    @app.post("/api/assistant/chat")
    async def assistant_chat(body: AssistantChatReq):
        if not body.message.strip():
            raise HTTPException(400, "message required")
        return await ctx.assistant.chat(body.message)

    @app.get("/api/assistant/transcript")
    def assistant_transcript():
        return {"messages": ctx.assistant.transcript()}

    @app.post("/api/assistant/reset")
    def assistant_reset():
        ctx.assistant.reset_conversation()
        return {"ok": True}

    # ------------------------------------------------------------- status

    @app.get("/api/status")
    def status():
        return {
            "proxy": f"{ctx.proxy.host}:{ctx.proxy.port}",
            "scope": sorted(ctx.interceptor.scope_hosts),
            "extensions": ctx.extensions_loaded,
            "flows": ctx.history.count(),
            "findings": len(ctx.passive.findings),
            "active_findings": len(ctx.active.findings),
            "active_authorized": ctx.active.authorized,
            "active_scope": sorted(ctx.active.scope_hosts),
            "checks": len(ctx.active.check_names),
            "project": ctx.projects.current or "",
            "assistant": ctx.assistant.public(),
            "intercept_on": ctx.intercept.enabled,
            "intercept_held": len(ctx.intercept._held),
            "browser": ctx.browser.status(),
            "upstream": ctx.upstream.public(),
        }

    # --------------------------------------------------------------- UI

    if UI_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index():
        idx = UI_DIR / "index.html"
        return idx.read_text() if idx.exists() else "<h1>SureGuard</h1>"

    return app
