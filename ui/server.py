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

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.http_message import Flow
from modules import decoder, comparer, sequencer, payloads, reporting
from modules import exportfmt, analyzer, sca, openapi, packets, billing
from modules.brand import NAME, catalog as brand_catalog
from modules.active_scan import discover_insertion_points
from modules.assistant import list_providers
from modules.repeater import Repeater

UI_DIR = Path(__file__).parent / "static"
ROOT_DIR = Path(__file__).resolve().parent.parent
LICENSE_FILE = ROOT_DIR / "LICENSE"


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
    extract: str = ""
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
    client_cert: Optional[str] = None
    client_key: Optional[str] = None


class RuleReq(BaseModel):
    enabled: Optional[bool] = True
    location: Optional[str] = "request-header"
    match: Optional[str] = ""
    replace: Optional[str] = ""
    regex: Optional[bool] = False
    header: Optional[str] = ""
    hosts: Optional[List[str]] = None
    comment: Optional[str] = ""


class FilterReq(BaseModel):
    methods: Optional[List[str]] = None
    path_regex: Optional[str] = None
    url_contains: Optional[str] = None
    mime_contains: Optional[str] = None
    in_scope_only: Optional[bool] = None


class SessionReq(BaseModel):
    inject: Optional[bool] = None
    update: Optional[bool] = None
    retry_on_401: Optional[bool] = None
    login_raw: Optional[str] = None
    login_scheme: Optional[str] = None


class CookieReq(BaseModel):
    host: str
    name: str
    value: str = ""


class CopyReq(BaseModel):
    raw: str
    scheme: str = "https"
    fmt: str = "curl"


class HarImportReq(BaseModel):
    har: dict


class FlowMetaReq(BaseModel):
    color: Optional[str] = None
    notes: Optional[List[str]] = None


class OastStartReq(BaseModel):
    host: str = "127.0.0.1"
    port: int = 0


class CrawlReq(BaseModel):
    seed: str
    max_pages: int = 40
    map_paths: bool = True


class OpenApiReq(BaseModel):
    spec: str
    base_url: str = ""
    record: bool = False


class ScaReq(BaseModel):
    path: Optional[str] = None
    text: Optional[str] = None
    filename: Optional[str] = "requirements.txt"


class AnalyzerReq(BaseModel):
    host: str = ""


class LicenseBody(BaseModel):
    key: str = ""
    attest: bool = False


class CheckoutBody(BaseModel):
    plan: str
    email: str = ""
    return_url: str = ""


class ClaimBody(BaseModel):
    session_id: str
    install: bool = True


class BillingConfigBody(BaseModel):
    stripe_secret: Optional[str] = None
    public_url: Optional[str] = None
    webhook_secret: Optional[str] = None


class GiftBody(BaseModel):
    email: str
    plan: str = "personal"
    days: int = 365
    seats: int = 1


class CloudBody(BaseModel):
    hosted_oast: Optional[str] = None
    hosted_ai_url: Optional[str] = None
    hosted_ai_key: Optional[str] = None
    vault_url: Optional[str] = None
    vault_token: Optional[str] = None
    sca_watch_path: Optional[str] = None


class TeamPackBody(BaseModel):
    name: str = ""


class RepoAddBody(BaseModel):
    repo: str


class RepoIdBody(BaseModel):
    id: str
    full: bool = False


class RepoStopBody(BaseModel):
    id: str = ""


class RepoCfgBody(BaseModel):
    token: Optional[str] = None
    authorized: Optional[bool] = None


def _request_from_history(ctx, flow_id: str):
    row = ctx.history.get(flow_id)
    if not row:
        raise HTTPException(404, "flow not found")
    scheme = urlsplit(row["url"]).scheme or "https"
    return Repeater.parse_raw(row["req_raw"], scheme)


def create_app(ctx) -> FastAPI:
    """ctx carries the shared module instances (see dastday.app.AppContext)."""
    app = FastAPI(title=NAME)

    @app.middleware("http")
    async def require_personal_license(request: Request, call_next):
        path = request.url.path
        if ctx.licenses.unlocked:
            return await call_next(request)
        if path == "/" or path == "/LICENSE" or path.startswith("/static"):
            return await call_next(request)
        if path.startswith("/api/license"):
            return await call_next(request)
        if path == "/api/status":
            return await call_next(request)
        return JSONResponse(
            {"detail": "Kerf is locked. Accept the Kerf Personal Use License "
                       "to unlock (no commercial use, no redistribution). "
                       "For a commercial license, email accounts@kerf.software.",
             "locked": True},
            status_code=403,
        )

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

    @app.post("/api/flow/{flow_id}/meta")
    def flow_meta(flow_id: str, body: FlowMetaReq):
        row = ctx.history.update_meta(flow_id, color=body.color, notes=body.notes)
        if not row:
            raise HTTPException(404, "flow not found")
        return row

    @app.post("/api/copy")
    def copy_as(body: CopyReq):
        if body.fmt == "fetch":
            return {"text": exportfmt.copy_as_fetch(body.raw, body.scheme)}
        if body.fmt == "python":
            return {"text": exportfmt.copy_as_python(body.raw, body.scheme)}
        return {"text": exportfmt.copy_as_curl(body.raw, body.scheme)}

    @app.get("/api/har")
    def export_har(host: str = "", search: str = "", limit: int = 200):
        rows = ctx.history.list(host=host or None, search=search or None, limit=limit)
        full = []
        for r in rows:
            item = ctx.history.get(r["id"])
            if item:
                full.append(item)
        return exportfmt.export_har(full)

    @app.post("/api/har")
    def import_har(body: HarImportReq):
        flows = exportfmt.import_har(body.har)
        for fl in flows:
            ctx.history.record(fl)
        return {"imported": len(flows)}

    @app.get("/api/packets")
    def packets_list(filter: str = "", limit: int = 800):
        try:
            return packets.list_packets(ctx.history, expr=filter, limit=limit)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/packets/{flow_id}")
    def packets_one(flow_id: str):
        d = packets.packet_detail(ctx.history, flow_id)
        if not d:
            raise HTTPException(404, "packet not found")
        return d

    @app.get("/api/packets/{flow_id}/stream")
    def packets_stream(flow_id: str):
        row = ctx.history.get(flow_id)
        if not row:
            raise HTTPException(404, "packet not found")
        host = row.get("host") or ""
        full = []
        for s in ctx.history.list(host=host, hide_noise=False, limit=400):
            item = ctx.history.get(s["id"])
            if item:
                full.append(item)
        full.sort(key=lambda r: r.get("timestamp") or 0)
        return packets.follow_stream(full, host)

    @app.get("/api/packets.pcap")
    def packets_pcap(filter: str = "", limit: int = 400):
        listing = packets.list_packets(ctx.history, expr=filter, limit=limit)
        rows = []
        for p in listing["packets"]:
            item = ctx.history.get(p["id"])
            if item:
                rows.append(item)
        blob = packets.export_pcap(rows)
        return Response(content=blob, media_type="application/vnd.tcpdump.pcap",
                        headers={"Content-Disposition": "attachment; filename=kerf.pcap"})

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
                custom=body.custom, grep=body.grep, extract=body.extract,
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
            "Content-Disposition": "attachment; filename=kerf-report.html"})

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

    # ------------------------------------------------------- match/replace

    @app.get("/api/rules")
    def rules_get():
        return ctx.rules.public()

    @app.post("/api/rules")
    def rules_add(body: RuleReq):
        data = body.model_dump() if hasattr(body, "model_dump") else body.dict()
        try:
            return ctx.rules.add_rule(data)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/rules/{rule_id}")
    def rules_update(rule_id: str, body: RuleReq):
        data = body.model_dump(exclude_none=True) if hasattr(body, "model_dump") else body.dict(exclude_none=True)
        try:
            return ctx.rules.update_rule(rule_id, data)
        except KeyError:
            raise HTTPException(404, "rule not found")

    @app.delete("/api/rules/{rule_id}")
    def rules_delete(rule_id: str):
        if not ctx.rules.delete_rule(rule_id):
            raise HTTPException(404, "rule not found")
        return {"ok": True}

    @app.post("/api/filters")
    def filters_set(body: FilterReq):
        data = body.model_dump(exclude_none=True) if hasattr(body, "model_dump") else body.dict(exclude_none=True)
        return ctx.rules.set_filters(data)

    # ------------------------------------------------------------- session

    @app.get("/api/session")
    def session_get():
        return ctx.session.public()

    @app.post("/api/session")
    def session_set(body: SessionReq):
        data = body.model_dump(exclude_none=True) if hasattr(body, "model_dump") else body.dict(exclude_none=True)
        return ctx.session.configure(data)

    @app.post("/api/session/cookie")
    def session_cookie(body: CookieReq):
        return ctx.session.set_cookie(body.host, body.name, body.value)

    @app.delete("/api/session/cookie")
    def session_cookie_del(host: str, name: str):
        return ctx.session.delete_cookie(host, name)

    @app.delete("/api/session")
    def session_clear():
        return ctx.session.clear()

    # -------------------------------------------------------------- logger

    @app.get("/api/events")
    def events_list(kind: str = "", limit: int = 400):
        return ctx.events.list(kind=kind, limit=limit)

    @app.delete("/api/events")
    def events_clear():
        ctx.events.clear()
        return {"ok": True}

    @app.get("/api/websockets")
    def websockets():
        return ctx.proxy.ws_log[-80:]

    # ---------------------------------------------------------------- oast

    @app.get("/api/oast")
    def oast_get():
        data = ctx.oast.public()
        hosted = ctx.cloud.hosted_oast_url()
        if hosted:
            data["hosted_url"] = hosted
        data["can_hosted"] = ctx.licenses.unlocked
        return data

    @app.post("/api/oast/start")
    async def oast_start(body: OastStartReq):
        return await ctx.oast.start(body.host, body.port)

    @app.post("/api/oast/stop")
    async def oast_stop():
        return await ctx.oast.stop()

    @app.delete("/api/oast")
    def oast_clear():
        return ctx.oast.clear()

    # -------------------------------------------------------------- crawler

    @app.post("/api/crawl")
    def crawl_start(body: CrawlReq):
        try:
            return ctx.crawler.start(body.seed, max_pages=body.max_pages,
                                     map_paths=body.map_paths)
        except PermissionError as exc:
            raise HTTPException(403, str(exc))

    @app.get("/api/crawl")
    def crawl_jobs():
        return ctx.crawler.list_jobs()

    # ------------------------------------------------------------- analyzer

    @app.get("/api/analyze")
    def analyze(host: str = ""):
        return analyzer.analyze_history(ctx.history, host=host)

    # --------------------------------------------------------------- sca

    @app.post("/api/sca")
    async def sca_scan(body: ScaReq):
        try:
            if body.path:
                packages = sca.parse_path(body.path)
            else:
                packages = sca.parse_any(body.filename or "requirements.txt",
                                         body.text or "")
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc))
        try:
            findings = await sca.query_osv(packages)
        except Exception as exc:
            raise HTTPException(502, f"OSV lookup failed: {exc}")
        return {
            "packages": packages,
            "findings": findings,
            "sbom": sca.cyclonedx(packages, findings),
        }

    # ---------------------------------------------------------- github repos

    @app.get("/api/repos")
    def repos_get():
        return ctx.repos.public()

    @app.post("/api/repos")
    def repos_add(body: RepoAddBody):
        try:
            return ctx.repos.add(body.repo)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/api/repos/{repo_id}")
    def repos_delete(repo_id: str):
        return ctx.repos.remove(repo_id)

    @app.post("/api/repos/config")
    def repos_config(body: RepoCfgBody):
        return ctx.repos.configure(token=body.token, authorized=body.authorized)

    @app.post("/api/repos/scan")
    async def repos_scan(body: RepoIdBody):
        try:
            return ctx.repos.start_scan(body.id, full=body.full)
        except PermissionError as exc:
            raise HTTPException(403, str(exc))
        except KeyError:
            raise HTTPException(404, "repo not found")
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc))
        except Exception as exc:
            raise HTTPException(502, str(exc))

    @app.post("/api/repos/scan-all")
    async def repos_scan_all():
        try:
            return await ctx.repos.scan_all()
        except PermissionError as exc:
            raise HTTPException(403, str(exc))
        except Exception as exc:
            raise HTTPException(502, str(exc))

    @app.post("/api/repos/scan/stop")
    async def repos_scan_stop(body: RepoStopBody):
        return await ctx.repos.stop(body.id)

    # ------------------------------------------------------------- openapi

    @app.post("/api/openapi")
    def openapi_import(body: OpenApiReq):
        try:
            items = openapi.parse_spec(body.spec, base_url=body.base_url)
        except Exception as exc:
            raise HTTPException(400, str(exc))
        recorded = 0
        if body.record:
            for fl in openapi.flows_from_spec(body.spec, base_url=body.base_url):
                ctx.history.record(fl)
                recorded += 1
        return {"endpoints": items, "recorded": recorded}

    # ------------------------------------------------------------- status

    @app.get("/api/status")
    def status():
        return {
            "product": NAME,
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
            "events": ctx.events.count(),
            "oast": ctx.oast.public().get("listening"),
            "ws": len(ctx.proxy.ws_log),
            "http2": True,
            "license": ctx.licenses.public(),
            "cloud": ctx.cloud.public(),
            "repos": len(ctx.repos.public().get("repos") or []),
        }

    @app.get("/api/license")
    def license_get():
        return {"license": ctx.licenses.public(),
                "catalog": brand_catalog(),
                "cloud": ctx.cloud.public(),
                "billing": billing.available()}

    @app.post("/api/license")
    def license_install(body: LicenseBody):
        try:
            if not body.attest:
                raise ValueError(
                    "accept the Kerf Personal Use License to unlock "
                    "(no commercial use, no redistribution). "
                    "For a commercial license, email accounts@kerf.software.")
            return ctx.licenses.attest()
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/api/license")
    def license_clear():
        ctx.licenses.clear()
        return ctx.licenses.public()

    @app.get("/api/billing/catalog")
    def billing_catalog():
        return {"plans": brand_catalog(), "billing": billing.available()}

    @app.post("/api/billing/config")
    def billing_config(body: BillingConfigBody):
        return billing.configure(body.model_dump())

    @app.post("/api/billing/enable")
    def billing_enable():
        try:
            return billing.enable()
        except Exception as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/billing/gift")
    def billing_gift(body: GiftBody):
        try:
            return billing.gift(email=body.email, plan=body.plan,
                                days=body.days, seats=body.seats)
        except Exception as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/billing/sales")
    def billing_sales():
        return {"issued": billing.ledger(), "billing": billing.available()}

    @app.post("/api/billing/tunnel")
    def billing_tunnel_start(request: Request):
        try:
            return billing.start_tunnel(str(request.base_url).rstrip("/"))
        except Exception as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/api/billing/tunnel")
    def billing_tunnel_stop():
        return billing.stop_tunnel()

    @app.get("/pay/{plan}")
    async def billing_pay(plan: str, request: Request):
        dest = str(request.base_url).rstrip("/")
        try:
            session = await billing.checkout(plan, return_url=dest)
        except Exception as exc:
            raise HTTPException(400, str(exc))
        return RedirectResponse(session["url"], status_code=303)

    @app.post("/api/billing/checkout")
    async def billing_checkout(body: CheckoutBody, request: Request):
        dest = body.return_url or str(request.base_url).rstrip("/")
        try:
            return await billing.checkout(body.plan, body.email, return_url=dest)
        except Exception as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/billing/claim")
    async def billing_claim(body: ClaimBody):
        try:
            store = ctx.licenses if body.install else None
            info = await billing.claim(body.session_id, store)
            key = info.get("key") or ""
            if body.install and key and not info.get("license"):
                ctx.licenses.install(key, attest=True)
                info["license"] = ctx.licenses.public()
            return info
        except Exception as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/billing/webhook")
    async def billing_webhook(request: Request):
        raw = await request.body()
        try:
            return await billing.handle_webhook(
                raw, request.headers.get("stripe-signature", ""))
        except Exception as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/cloud")
    def cloud_set(body: CloudBody):
        return ctx.cloud.configure(body.model_dump())

    @app.post("/api/team/pack")
    def team_pack(body: TeamPackBody):
        try:
            data = ctx.cloud.team_pack(ctx.projects, body.name)
        except PermissionError as exc:
            raise HTTPException(402, str(exc))
        except Exception as exc:
            raise HTTPException(400, str(exc))
        return Response(data, media_type="application/zip",
                        headers={"Content-Disposition":
                                 'attachment; filename="kerf-team.zip"'})

    @app.post("/api/team/vault")
    async def team_vault(body: TeamPackBody):
        try:
            return await ctx.cloud.vault_put(ctx.projects, body.name)
        except PermissionError as exc:
            raise HTTPException(402, str(exc))
        except Exception as exc:
            raise HTTPException(400, str(exc))

    # --------------------------------------------------------------- UI

    if UI_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")

    @app.get("/LICENSE", response_class=PlainTextResponse)
    def license_text():
        if not LICENSE_FILE.exists():
            raise HTTPException(404, "LICENSE file is missing")
        return LICENSE_FILE.read_text()

    @app.get("/", response_class=HTMLResponse)
    def index():
        idx = UI_DIR / "index.html"
        return idx.read_text() if idx.exists() else f"<h1>{NAME}</h1>"

    return app
