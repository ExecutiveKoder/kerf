"""
HAR import/export and copy-as helpers (curl, fetch, Python).
"""

from __future__ import annotations

import json
import shlex
import time
from urllib.parse import urlsplit

from core.http_message import Flow, HttpRequest, HttpResponse
from modules.repeater import Repeater


def _headers_from_raw(raw: str) -> list[tuple[str, str]]:
    raw = (raw or "").replace("\r\n", "\n")
    head, _, _ = raw.partition("\n\n")
    out = []
    for line in head.split("\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            out.append((k.strip(), v.strip()))
    return out


def copy_as_curl(req_raw: str, scheme: str = "https") -> str:
    req = Repeater.parse_raw(req_raw, scheme)
    parts = ["curl", "-i", "-sS", "-X", req.method]
    for k, v in req.headers:
        if k.lower() in ("content-length", "host"):
            continue
        parts += ["-H", f"{k}: {v}"]
    if req.body:
        parts += ["--data-binary", req.body.decode("latin-1")]
    parts.append(req.url)
    return " ".join(shlex.quote(p) for p in parts)


def copy_as_fetch(req_raw: str, scheme: str = "https") -> str:
    req = Repeater.parse_raw(req_raw, scheme)
    headers = {k: v for k, v in req.headers
               if k.lower() not in ("content-length",)}
    opts = {"method": req.method, "headers": headers}
    if req.body:
        opts["body"] = req.body.decode("latin-1")
    return (f"fetch({json.dumps(req.url)}, {json.dumps(opts, indent=2)});")


def copy_as_python(req_raw: str, scheme: str = "https") -> str:
    req = Repeater.parse_raw(req_raw, scheme)
    headers = {k: v for k, v in req.headers
               if k.lower() not in ("content-length",)}
    body = req.body.decode("latin-1")
    return (
        "import httpx\n\n"
        f"r = httpx.request({req.method!r}, {req.url!r},\n"
        f"    headers={headers!r},\n"
        f"    content={body!r})\n"
        "print(r.status_code)\nprint(r.text)\n"
    )


def flow_to_har_entry(row: dict) -> dict:
    url = row.get("url") or ""
    parts = urlsplit(url)
    req_raw = row.get("req_raw") or ""
    resp_raw = row.get("resp_raw") or ""
    req_headers = [{"name": k, "value": v} for k, v in _headers_from_raw(req_raw)]
    resp_headers = [{"name": k, "value": v} for k, v in _headers_from_raw(resp_raw)]
    req_body = req_raw.replace("\r\n", "\n").partition("\n\n")[2]
    resp_body = resp_raw.replace("\r\n", "\n").partition("\n\n")[2]
    started = time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                            time.gmtime(row.get("timestamp") or time.time()))
    return {
        "startedDateTime": started,
        "time": float(row.get("duration_ms") or 0),
        "request": {
            "method": row.get("method") or "GET",
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": req_headers,
            "queryString": [{"name": k, "value": v}
                            for k, v in (p.split("=", 1) if "=" in p else (p, "")
                                         for p in (parts.query.split("&") if parts.query else []))],
            "cookies": [],
            "headersSize": -1,
            "bodySize": len(req_body),
            "postData": {"mimeType": "", "text": req_body} if req_body else None,
        },
        "response": {
            "status": row.get("status") or 0,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": resp_headers,
            "cookies": [],
            "content": {
                "size": len(resp_body),
                "mimeType": row.get("mime") or "",
                "text": resp_body,
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(resp_body),
        },
        "cache": {},
        "timings": {"send": 0, "wait": float(row.get("duration_ms") or 0), "receive": 0},
    }


def export_har(rows: list[dict]) -> dict:
    entries = []
    for row in rows:
        entry = flow_to_har_entry(row)
        if entry["request"].get("postData") is None:
            entry["request"].pop("postData", None)
        entries.append(entry)
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "SureGuard", "version": "0.2"},
            "entries": entries,
        }
    }


def import_har(data: dict) -> list[Flow]:
    log = data.get("log") if isinstance(data, dict) else None
    entries = (log or {}).get("entries") or []
    flows = []
    for ent in entries:
        req = ent.get("request") or {}
        resp = ent.get("response") or {}
        url = req.get("url") or ""
        method = req.get("method") or "GET"
        headers = [(h.get("name", ""), h.get("value", ""))
                   for h in (req.get("headers") or [])]
        body = ((req.get("postData") or {}).get("text") or "").encode("latin-1")
        if not any(k.lower() == "host" for k, _ in headers) and urlsplit(url).netloc:
            headers.append(("Host", urlsplit(url).netloc))
        request = HttpRequest(method, url, headers, body)
        rh = [(h.get("name", ""), h.get("value", ""))
              for h in (resp.get("headers") or [])]
        content = (resp.get("content") or {}).get("text") or ""
        response = HttpResponse(int(resp.get("status") or 0),
                                resp.get("statusText") or "",
                                rh, content.encode("latin-1"))
        flow = Flow(request=request, response=response)
        flow.duration_ms = float(ent.get("time") or 0)
        flows.append(flow)
    return flows
