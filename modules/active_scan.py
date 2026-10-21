"""
Active-scan engine and the bundled attack checks.

The engine enforces scope, discovers insertion points, substitutes payloads,
schedules checks, and collects findings. It refuses to run until the operator
asserts an authorized scope: active scanning sends crafted requests to a target,
which is legitimate ONLY against systems you own or are explicitly authorized to
test. That gate is deliberate and is NOT removed by shipping checks.

Checks implement either:
  * `probe(base, point, send)`      — point-level checks (one insertion point)
  * `probe_request(base, send)`     — request-level checks (whole request)

A check sets `per_request = True` to be called once per request instead of once
per insertion point.
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid
import json
from urllib.parse import urlsplit, urlencode, parse_qsl

from core.http_message import HttpRequest, Flow
from modules import payloads


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

class InsertionPoint:
    """A place in a request where a check may substitute a payload."""

    def __init__(self, kind: str, name: str, value: str) -> None:
        self.kind = kind      # query, body-form, cookie, json, graphql-var, multipart, header
        self.name = name
        self.value = value

    def __repr__(self) -> str:  # pragma: no cover
        return f"InsertionPoint({self.kind}:{self.name})"


class ActiveFinding:
    def __init__(self, severity: str, title: str, detail: str, url: str,
                 check: str, *, confidence: str = "firm", issue_key: str = "",
                 point: str = "", evidence: str = "", payload: str = "") -> None:
        self.severity = severity
        self.title = title
        self.detail = detail
        self.url = url
        self.check = check
        self.confidence = confidence
        self.issue_key = issue_key
        self.point = point
        self.evidence = evidence
        self.payload = payload

    def to_dict(self) -> dict:
        return {
            "severity": self.severity, "title": self.title, "detail": self.detail,
            "url": self.url, "check": self.check, "confidence": self.confidence,
            "issue_key": self.issue_key, "point": self.point,
            "evidence": self.evidence, "payload": self.payload,
        }


class ActiveCheck:
    """Base class for an active check."""

    name = "unnamed-active-check"
    issue_key = ""
    per_request = False

    async def probe(self, base: HttpRequest, point: InsertionPoint, send) -> list:
        return []

    async def probe_request(self, base: HttpRequest, send) -> list:
        return []


# --------------------------------------------------------------------------- #
# Insertion points + payload substitution
# --------------------------------------------------------------------------- #

def _walk_json(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                yield from _walk_json(v, path)
            else:
                yield path, "" if v is None else str(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                yield from _walk_json(v, path)
            else:
                yield path, "" if v is None else str(v)


def _set_json(obj, path: str, value: str):
    segs = []
    buf = ""
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == ".":
            if buf:
                segs.append(buf)
                buf = ""
            i += 1
        elif ch == "[":
            if buf:
                segs.append(buf)
                buf = ""
            j = path.find("]", i)
            segs.append(int(path[i + 1:j]))
            i = j + 1
        else:
            buf += ch
            i += 1
    if buf:
        segs.append(buf)
    cur = obj
    for s in segs[:-1]:
        cur = cur[s]
    last = segs[-1]
    cur[last] = value


def _parse_multipart(ctype: str, body: bytes) -> list[tuple[str, str, bytes]]:
    if "boundary=" not in ctype:
        return []
    boundary = ctype.split("boundary=", 1)[1].split(";")[0].strip().strip('"')
    marker = ("--" + boundary).encode()
    parts = body.split(marker)
    out = []
    for part in parts:
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        head, _, pdata = part.partition(b"\r\n\r\n")
        if not pdata:
            head, _, pdata = part.partition(b"\n\n")
        name = ""
        for line in head.decode("latin-1", "replace").splitlines():
            if line.lower().startswith("content-disposition:"):
                m = re.search(r'name="([^"]+)"', line)
                if m:
                    name = m.group(1)
        if name:
            out.append((name, pdata.rstrip(b"\r\n").decode("latin-1", "replace"), pdata))
    return out


def discover_insertion_points(req: HttpRequest) -> list:
    points: list = []
    for k, v in req.query_params:
        points.append(InsertionPoint("query", k, v))
    ctype = (req.header("content-type") or "").lower()
    body_txt = req.body.decode("latin-1") if req.body else ""
    if "application/x-www-form-urlencoded" in ctype and req.body:
        for k, v in parse_qsl(body_txt, keep_blank_values=True):
            points.append(InsertionPoint("body-form", k, v))
    if "application/json" in ctype or "application/graphql" in ctype or (
            body_txt.lstrip().startswith("{") and "query" in body_txt[:200]):
        try:
            data = json.loads(req.body.decode("utf-8"))
        except Exception:
            data = None
        if isinstance(data, dict) and "query" in data and "variables" in data \
                and isinstance(data["variables"], dict):
            for k, v in data["variables"].items():
                if not isinstance(v, (dict, list)):
                    points.append(InsertionPoint("graphql-var", k, "" if v is None else str(v)))
        elif data is not None:
            for path, val in _walk_json(data):
                points.append(InsertionPoint("json", path, val))
    if "multipart/form-data" in ctype and req.body:
        for name, val, _ in _parse_multipart(ctype, req.body):
            points.append(InsertionPoint("multipart", name, val))
    cookie = req.header("cookie")
    if cookie:
        for pair in cookie.split(";"):
            if "=" in pair:
                k, _, v = pair.strip().partition("=")
                points.append(InsertionPoint("cookie", k, v))
    for k, v in req.headers:
        if k.lower() in ("authorization", "x-api-key", "x-csrf-token", "x-auth-token"):
            points.append(InsertionPoint("header", k, v))
    return points


def apply_payload(base: HttpRequest, point: InsertionPoint, payload: str,
                  *, mode: str = "replace") -> HttpRequest:
    """Return a copy of `base` with `payload` substituted at `point`."""
    new_value = (point.value + payload) if mode == "append" else payload
    req = HttpRequest(base.method, base.url, list(base.headers), base.body,
                      base.http_version)

    if point.kind == "query":
        params = [(k, new_value if k == point.name else v)
                  for k, v in base.query_params]
        return req.with_query_params(params)

    if point.kind == "body-form":
        pairs = parse_qsl(base.body.decode("latin-1"), keep_blank_values=True)
        pairs = [(k, new_value if k == point.name else v) for k, v in pairs]
        req.body = urlencode(pairs).encode("latin-1")
        req.set_header("Content-Length", str(len(req.body)))
        return req

    if point.kind == "cookie":
        cookie = base.header("cookie") or ""
        out = []
        for pair in cookie.split(";"):
            if "=" in pair:
                k, _, v = pair.strip().partition("=")
                out.append(f"{k}={new_value if k == point.name else v}")
            elif pair.strip():
                out.append(pair.strip())
        req.set_header("Cookie", "; ".join(out))
        return req

    if point.kind == "header":
        req.set_header(point.name, new_value)
        return req

    if point.kind == "json":
        try:
            data = json.loads(base.body.decode("utf-8") or "null")
            _set_json(data, point.name, new_value)
            req.body = json.dumps(data).encode("utf-8")
            req.set_header("Content-Length", str(len(req.body)))
        except Exception:
            pass
        return req

    if point.kind == "graphql-var":
        try:
            data = json.loads(base.body.decode("utf-8"))
            if isinstance(data.get("variables"), dict):
                data["variables"][point.name] = new_value
                req.body = json.dumps(data).encode("utf-8")
                req.set_header("Content-Length", str(len(req.body)))
        except Exception:
            pass
        return req

    if point.kind == "multipart":
        ctype = base.header("content-type") or ""
        if "boundary=" in ctype:
            boundary = ctype.split("boundary=", 1)[1].split(";")[0].strip().strip('"')
            marker = ("--" + boundary).encode()
            chunks = [b""]
            for name, val, raw in _parse_multipart(ctype, base.body):
                payload = new_value.encode("latin-1") if name == point.name else raw.rstrip(b"\r\n")
                disp = f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
                chunks.append(disp + payload + b"\r\n")
            body = marker.join(chunks) + marker + b"--\r\n"
            req.body = body
            req.set_header("Content-Length", str(len(req.body)))
        return req

    return req


# --------------------------------------------------------------------------- #
# Detection helpers
# --------------------------------------------------------------------------- #

_DB_ERRORS = re.compile(
    rb"(?i)(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|"
    rb"SQLSTATE|SQLite3?::|Unclosed quotation mark|"
    rb"quoted string not properly terminated|"
    rb"Microsoft (?:OLE DB|SQL Server)|ODBC .* Driver|"
    rb"Warning: (?:pg|mysqli?|oci)_)"
)

# Content that only appears if the server actually fetched the internal target.
# Deliberately excludes substrings of the payloads themselves (e.g. "meta-data/")
# so a page that merely reflects the payload is not mistaken for SSRF.
_SSRF_MARKERS = re.compile(
    rb"(?i)(root:[^:]*:0:0:|ami-id|instance-id|iam/security-credentials/|"
    rb"\"accessKeyId\"|for 16-bit app support|\[fonts\])"
)


def _resp_len(flow: Flow) -> int:
    return len(flow.response.body) if flow.response else 0


def _resp_body(flow: Flow) -> bytes:
    return flow.response.body if flow.response else b""


def _is_html(flow: Flow) -> bool:
    return bool(flow.response) and "html" in flow.response.content_type


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

class SqlInjectionCheck(ActiveCheck):
    name = "sqli"
    issue_key = "sqli"
    TIME_SECONDS = 3

    async def probe(self, base, point, send) -> list:
        findings = []
        base_flow = await send(apply_payload(base, point, point.value))
        base_body = _resp_body(base_flow)

        # Error-based: a payload that provokes a DB error the baseline lacks.
        for pl in payloads.SQLI_ERROR:
            flow = await send(apply_payload(base, point, pl))
            body = _resp_body(flow)
            m = _DB_ERRORS.search(body)
            if m and not _DB_ERRORS.search(base_body):
                findings.append(ActiveFinding(
                    "high", "SQL injection (error-based)",
                    f"Injecting into '{point.name}' triggered a database error "
                    f"that the baseline response did not contain.",
                    base.url, self.name, issue_key=self.issue_key,
                    point=f"{point.kind}:{point.name}", payload=pl,
                    evidence=m.group(0).decode("latin-1", "replace")))
                return findings  # one confirmation is enough for this point

        # Time-based blind: a sleep payload that measurably delays the response.
        baseline_ms = base_flow.duration_ms or 0.0
        for tpl in payloads.SQLI_TIME:
            pl = tpl.format(s=self.TIME_SECONDS)
            flow = await send(apply_payload(base, point, pl))
            delay = (flow.duration_ms or 0.0)
            if delay >= self.TIME_SECONDS * 1000 * 0.7 and delay > baseline_ms + 1500:
                # Confirm with a zero-delay control to rule out a slow endpoint.
                ctrl = await send(apply_payload(
                    base, point, tpl.format(s=0)))
                if (ctrl.duration_ms or 0.0) < delay * 0.5:
                    findings.append(ActiveFinding(
                        "high", "SQL injection (time-based blind)",
                        f"Injecting a {self.TIME_SECONDS}s time-delay payload into "
                        f"'{point.name}' delayed the response "
                        f"(~{delay:.0f}ms vs baseline ~{baseline_ms:.0f}ms).",
                        base.url, self.name, issue_key=self.issue_key,
                        point=f"{point.kind}:{point.name}", payload=pl,
                        evidence=f"{delay:.0f}ms response"))
                    return findings
        return findings


class XssReflectedCheck(ActiveCheck):
    name = "xss-reflected"
    issue_key = "xss"

    async def probe(self, base, point, send) -> list:
        for tpl in payloads.XSS:
            pl = tpl.format(canary=payloads.CANARY)
            flow = await send(apply_payload(base, point, pl))
            if not flow.response:
                continue
            body = _resp_body(flow)
            # Reflected verbatim (angle brackets intact) in an HTML response is
            # the signal: the payload survived without output encoding.
            if pl.encode("latin-1") in body and _is_html(flow):
                return [ActiveFinding(
                    "high", "Reflected cross-site scripting",
                    f"Input to '{point.name}' is reflected into an HTML response "
                    f"without output encoding; markup characters are preserved.",
                    base.url, self.name, issue_key=self.issue_key,
                    point=f"{point.kind}:{point.name}", payload=pl,
                    evidence=pl)]
            # Template-injection tell: 7*7 evaluated to 49 next to the canary.
            if (b"49" + payloads.CANARY.encode() in body
                    and b"{{7*7}}" + payloads.CANARY.encode() not in body):
                return [ActiveFinding(
                    "high", "Server-side template injection",
                    f"Input to '{point.name}' appears to be evaluated as a "
                    f"template expression (7*7 rendered as 49).",
                    base.url, self.name, confidence="firm", issue_key="xss",
                    point=f"{point.kind}:{point.name}", payload=pl,
                    evidence="49" + payloads.CANARY)]
        return []


class CommandInjectionCheck(ActiveCheck):
    name = "cmdi"
    issue_key = "cmdi"
    TIME_SECONDS = 3

    async def probe(self, base, point, send) -> list:
        base_flow = await send(apply_payload(base, point, point.value))
        baseline_ms = base_flow.duration_ms or 0.0
        for tpl in payloads.CMDI_TIME:
            pl = tpl.format(s=self.TIME_SECONDS, sp1=self.TIME_SECONDS + 1)
            flow = await send(apply_payload(base, point, pl, mode="append"))
            delay = (flow.duration_ms or 0.0)
            if delay >= self.TIME_SECONDS * 1000 * 0.7 and delay > baseline_ms + 1500:
                findings = [ActiveFinding(
                    "high", "OS command injection (time-based)",
                    f"Appending a shell time-delay to '{point.name}' delayed the "
                    f"response (~{delay:.0f}ms vs baseline ~{baseline_ms:.0f}ms).",
                    base.url, self.name, issue_key=self.issue_key,
                    point=f"{point.kind}:{point.name}", payload=pl,
                    evidence=f"{delay:.0f}ms response")]
                return findings
        return []


class SsrfCheck(ActiveCheck):
    name = "ssrf"
    issue_key = "ssrf"

    def __init__(self, collaborator: str | None = None) -> None:
        # Operators may set a canary URL they control; a request reaching it is
        # unambiguous proof. Without one we fall back to content signatures.
        self.collaborator = collaborator

    async def probe(self, base, point, send) -> list:
        # Only parameters that look like they carry a URL/host are worth probing.
        if not re.search(r"https?://|^/|localhost|\d+\.\d+\.\d+\.\d+",
                         point.value or "", re.I) and point.kind != "query":
            return []
        targets = list(payloads.SSRF)
        if self.collaborator:
            targets.insert(0, self.collaborator)
        for pl in targets:
            flow = await send(apply_payload(base, point, pl))
            body = _resp_body(flow)
            m = _SSRF_MARKERS.search(body)
            # Guard against reflection: if the marker is part of the payload we
            # sent, the page just echoed our input — not a server-side fetch.
            if m and m.group(0).decode("latin-1", "replace").lower() in pl.lower():
                m = None
            if m:
                return [ActiveFinding(
                    "high", "Server-side request forgery",
                    f"Parameter '{point.name}' caused the server to fetch an "
                    f"internal resource; the response contains internal content.",
                    base.url, self.name, issue_key=self.issue_key,
                    point=f"{point.kind}:{point.name}", payload=pl,
                    evidence=m.group(0).decode("latin-1", "replace"))]
        return []


class PathTraversalCheck(ActiveCheck):
    name = "path-traversal"
    issue_key = "lfi"
    PAT = re.compile(rb"(root:.*:0:0:|\[fonts\]|\[extensions\])")

    async def probe(self, base, point, send) -> list:
        for pl in payloads.PATH_TRAVERSAL:
            flow = await send(apply_payload(base, point, pl))
            m = self.PAT.search(_resp_body(flow))
            if m:
                return [ActiveFinding(
                    "high", "Path traversal / local file inclusion",
                    f"Parameter '{point.name}' returned the contents of a local "
                    f"system file.",
                    base.url, self.name, issue_key=self.issue_key,
                    point=f"{point.kind}:{point.name}", payload=pl,
                    evidence=m.group(0).decode("latin-1", "replace"))]
        return []


class AuthBypassCheck(ActiveCheck):
    name = "auth-bypass"
    issue_key = "auth-bypass"
    per_request = True

    def _strip_creds(self, base: HttpRequest) -> HttpRequest:
        headers = [(k, v) for k, v in base.headers
                   if k.lower() not in ("cookie", "authorization")]
        return HttpRequest(base.method, base.url, headers, base.body,
                           base.http_version)

    async def probe_request(self, base, send) -> list:
        findings = []
        had_creds = bool(base.header("cookie") or base.header("authorization"))
        base_flow = await send(base)
        if not base_flow.response:
            return []
        base_status = base_flow.response.status_code
        base_len = _resp_len(base_flow)

        # 1) Resource served identically with credentials stripped.
        if had_creds and base_status == 200:
            stripped = await send(self._strip_creds(base))
            if (stripped.response and stripped.response.status_code == 200
                    and abs(_resp_len(stripped) - base_len) <= max(16, base_len * 0.05)):
                findings.append(ActiveFinding(
                    "high", "Access control: resource served without credentials",
                    "Removing the Cookie/Authorization header returned the same "
                    "200 response, suggesting access control is not enforced.",
                    base.url, self.name, confidence="tentative",
                    issue_key=self.issue_key, evidence=f"status 200, ~{base_len}B"))

        # 2) A forbidden resource becomes reachable via a bypass header.
        if base_status in (401, 403):
            for hk, hv in payloads.AUTH_BYPASS_HEADERS:
                mut = HttpRequest(base.method, base.url, list(base.headers),
                                  base.body, base.http_version)
                mut.set_header(hk, hv)
                flow = await send(mut)
                if flow.response and flow.response.status_code == 200:
                    findings.append(ActiveFinding(
                        "high", "Authentication bypass via request header",
                        f"Adding '{hk}: {hv}' turned a {base_status} into a 200, "
                        f"indicating header-based access-control bypass.",
                        base.url, self.name, issue_key=self.issue_key,
                        payload=f"{hk}: {hv}", evidence="status 200"))
                    break
        return findings


DEFAULT_ACTIVE_CHECKS = [
    SqlInjectionCheck(),
    XssReflectedCheck(),
    CommandInjectionCheck(),
    SsrfCheck(),
    PathTraversalCheck(),
    AuthBypassCheck(),
]


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class ActiveScanEngine:
    def __init__(self, send_coro, *, scope_hosts: set | None = None,
                 max_concurrency: int = 8, authorized: bool = False) -> None:
        self._send = send_coro
        self._checks: list = []
        self.scope_hosts = scope_hosts or set()
        self._sem = asyncio.Semaphore(max_concurrency)
        self.findings: list = []
        self._seen: set = set()
        self.authorized = authorized
        # Lightweight progress state the UI can poll.
        self.last_scan = {"running": False, "url": "", "checks": 0,
                          "points": 0, "findings": 0}
        self.jobs: dict = {}

    # --------------------------------------------------------- registration

    def register(self, check: ActiveCheck) -> None:
        self._checks.append(check)

    def register_defaults(self) -> None:
        for c in DEFAULT_ACTIVE_CHECKS:
            self.register(c)

    @property
    def check_names(self) -> list:
        return [c.name for c in self._checks]

    # ------------------------------------------------------------- scope

    def authorize_scope(self, hosts: set) -> None:
        """Operator asserts authorization to actively test these hosts."""
        self.scope_hosts = set(h.strip() for h in hosts if h.strip())
        self.authorized = bool(self.scope_hosts)

    def revoke(self) -> None:
        self.authorized = False
        self.scope_hosts = set()

    def _in_scope(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        if not self.scope_hosts:
            return False
        return any(host == s or host.endswith("." + s) for s in self.scope_hosts)

    # --------------------------------------------------------------- scan

    async def scan_flow(self, flow: Flow) -> list:
        if not self.authorized:
            raise PermissionError(
                "Scan refused: no authorized scope set. Authorize the "
                "target host(s) first (you must be allowed to test them).")
        if not self._in_scope(flow.request.url):
            return []
        if not self._checks:
            return []

        base = flow.request
        points = discover_insertion_points(base)
        point_checks = [c for c in self._checks if not c.per_request]
        request_checks = [c for c in self._checks if c.per_request]

        self.last_scan = {"running": True, "url": base.url,
                          "checks": len(self._checks), "points": len(points),
                          "findings": 0}
        results: list = []

        async def run_point(check, point):
            async with self._sem:
                try:
                    return await check.probe(base, point, self._send)
                except Exception as exc:
                    print(f"[active] {check.name} error: {exc!r}")
                    return []

        async def run_request(check):
            async with self._sem:
                try:
                    return await check.probe_request(base, self._send)
                except Exception as exc:
                    print(f"[active] {check.name} error: {exc!r}")
                    return []

        tasks = [run_point(c, p) for c in point_checks for p in points]
        tasks += [run_request(c) for c in request_checks]
        for batch in await asyncio.gather(*tasks):
            for f in batch:
                key = (f.check, f.title, f.point, f.url)
                if key in self._seen:
                    continue
                self._seen.add(key)
                results.append(f)
                self.findings.append(f)

        self.last_scan["running"] = False
        self.last_scan["findings"] = len(results)
        return results

    # ---------------------------------------------------------- host jobs

    def start_job(self, host: str, flows: list) -> dict:
        if not self.authorized:
            raise PermissionError(
                "Scan refused: no authorized scope set.")
        host = host.strip().lower()
        if not any(host == s or host.endswith("." + s) for s in self.scope_hosts):
            raise PermissionError(f"{host} is not in the authorized active scope.")
        seen = set()
        queue = []
        for f in flows:
            key = (f.request.method, f.request.url)
            if key in seen:
                continue
            seen.add(key)
            queue.append(f)
        if not queue:
            raise ValueError(f"No captured requests for {host}. Browse it first.")
        job_id = uuid.uuid4().hex[:12]
        job = {
            "id": job_id, "host": host, "status": "running",
            "total": len(queue), "completed": 0, "current": "",
            "findings": 0, "error": None, "started": time.time(),
        }
        self.jobs[job_id] = job
        asyncio.create_task(self._run_job(job, queue))
        return dict(job)

    async def _run_job(self, job: dict, queue: list) -> None:
        try:
            for flow in queue:
                job["current"] = flow.request.url
                found = await self.scan_flow(flow)
                job["findings"] += len(found)
                job["completed"] += 1
            job["status"] = "done"
            job["current"] = ""
        except Exception as exc:
            job["status"] = "error"
            job["error"] = repr(exc)

    def job(self, job_id: str) -> dict | None:
        j = self.jobs.get(job_id)
        return dict(j) if j else None

    def list_jobs(self) -> list:
        return [dict(j) for j in sorted(
            self.jobs.values(), key=lambda x: x.get("started", 0), reverse=True)]

    # ------------------------------------------------------------- report

    def report(self) -> list:
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        return [f.to_dict() for f in sorted(
            self.findings, key=lambda f: order.get(f.severity, 9))]

    def clear(self) -> None:
        self.findings.clear()
        self._seen.clear()
