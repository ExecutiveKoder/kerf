"""
Match-and-replace plus intercept filter rules.

Rules rewrite headers, URLs, or bodies on the live proxy path. Filters decide
which requests the intercept queue actually holds. Both persist under ~/.dastday.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

from core.interceptor import BaseAddon
from core.http_message import Flow, HttpRequest, HttpResponse

CONFIG_DIR = Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))
RULES_PATH = CONFIG_DIR / "rules.json"

LOCATIONS = (
    "request-header", "request-body", "request-url",
    "response-header", "response-body",
)


def _default() -> dict:
    return {
        "rules": [],
        "filters": {
            "methods": [],
            "path_regex": "",
            "url_contains": "",
            "mime_contains": "",
            "in_scope_only": True,
        },
    }


class RuleEngine(BaseAddon):
    def __init__(self) -> None:
        self._data = self._load()

    def _load(self) -> dict:
        data = _default()
        try:
            if RULES_PATH.exists():
                raw = json.loads(RULES_PATH.read_text())
                if isinstance(raw, dict):
                    data["rules"] = list(raw.get("rules") or [])
                    filt = raw.get("filters") or {}
                    data["filters"].update({k: filt.get(k, v)
                                            for k, v in data["filters"].items()})
        except Exception as exc:
            print(f"[rules] load error: {exc!r}")
        return data

    def _save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        RULES_PATH.write_text(json.dumps(self._data, indent=2))

    def public(self) -> dict:
        return {
            "rules": list(self._data["rules"]),
            "filters": dict(self._data["filters"]),
            "locations": list(LOCATIONS),
        }

    def set_filters(self, patch: dict) -> dict:
        f = self._data["filters"]
        if "methods" in patch:
            f["methods"] = [str(m).upper() for m in (patch["methods"] or []) if m]
        if "path_regex" in patch:
            f["path_regex"] = str(patch["path_regex"] or "")
        if "url_contains" in patch:
            f["url_contains"] = str(patch["url_contains"] or "")
        if "mime_contains" in patch:
            f["mime_contains"] = str(patch["mime_contains"] or "")
        if "in_scope_only" in patch:
            f["in_scope_only"] = bool(patch["in_scope_only"])
        self._save()
        return self.public()

    def add_rule(self, rule: dict) -> dict:
        item = {
            "id": uuid.uuid4().hex[:10],
            "enabled": bool(rule.get("enabled", True)),
            "location": rule.get("location") if rule.get("location") in LOCATIONS
                        else "request-header",
            "match": str(rule.get("match") or ""),
            "replace": str(rule.get("replace") or ""),
            "regex": bool(rule.get("regex", False)),
            "header": str(rule.get("header") or ""),
            "hosts": [h.strip() for h in (rule.get("hosts") or []) if str(h).strip()],
            "comment": str(rule.get("comment") or ""),
        }
        if not item["match"]:
            raise ValueError("match text required")
        self._data["rules"].append(item)
        self._save()
        return item

    def update_rule(self, rule_id: str, patch: dict) -> dict:
        for item in self._data["rules"]:
            if item["id"] != rule_id:
                continue
            for k in ("enabled", "location", "match", "replace", "regex",
                      "header", "hosts", "comment"):
                if k in patch:
                    item[k] = patch[k]
            if item.get("location") not in LOCATIONS:
                item["location"] = "request-header"
            self._save()
            return item
        raise KeyError(rule_id)

    def delete_rule(self, rule_id: str) -> bool:
        before = len(self._data["rules"])
        self._data["rules"] = [r for r in self._data["rules"] if r["id"] != rule_id]
        if len(self._data["rules"]) == before:
            return False
        self._save()
        return True

    def filters_allow(self, req: HttpRequest, *, in_scope: bool,
                      mime: str = "") -> bool:
        f = self._data["filters"]
        if f.get("in_scope_only") and not in_scope:
            return False
        methods = f.get("methods") or []
        if methods and req.method.upper() not in methods:
            return False
        if f.get("url_contains") and f["url_contains"] not in req.url:
            return False
        if f.get("path_regex"):
            try:
                if not re.search(f["path_regex"], req.path or ""):
                    return False
            except re.error:
                return False
        if f.get("mime_contains") and mime and f["mime_contains"] not in mime:
            return False
        return True

    def _host_ok(self, rule: dict, host: str) -> bool:
        hosts = rule.get("hosts") or []
        if not hosts:
            return True
        h = (host or "").split(":")[0]
        return any(h == s or h.endswith("." + s) for s in hosts)

    def _sub(self, rule: dict, text: str) -> str:
        pat = rule.get("match") or ""
        repl = rule.get("replace") or ""
        if not pat:
            return text
        if rule.get("regex"):
            try:
                return re.sub(pat, repl, text)
            except re.error:
                return text
        return text.replace(pat, repl)

    async def on_request(self, flow: Flow) -> HttpRequest | None:
        req = flow.request
        changed = False
        for rule in self._data["rules"]:
            if not rule.get("enabled") or not self._host_ok(rule, req.host):
                continue
            loc = rule.get("location")
            if loc == "request-url":
                new = self._sub(rule, req.url)
                if new != req.url:
                    req.url = new
                    changed = True
            elif loc == "request-header":
                name = (rule.get("header") or "").strip()
                if name:
                    cur = req.header(name) or ""
                    new = self._sub(rule, cur)
                    if new != cur:
                        req.set_header(name, new)
                        changed = True
                else:
                    headers = []
                    for k, v in req.headers:
                        nv = self._sub(rule, v)
                        headers.append((k, nv))
                        if nv != v:
                            changed = True
                    req.headers = headers
            elif loc == "request-body" and req.body:
                text = req.body.decode("latin-1")
                new = self._sub(rule, text)
                if new != text:
                    req.body = new.encode("latin-1")
                    req.set_header("Content-Length", str(len(req.body)))
                    changed = True
        return req if changed else None

    async def on_response(self, flow: Flow) -> HttpResponse | None:
        resp = flow.response
        if not resp:
            return None
        host = flow.request.host
        changed = False
        for rule in self._data["rules"]:
            if not rule.get("enabled") or not self._host_ok(rule, host):
                continue
            loc = rule.get("location")
            if loc == "response-header":
                name = (rule.get("header") or "").strip()
                headers = []
                for k, v in resp.headers:
                    if name and k.lower() != name.lower():
                        headers.append((k, v))
                        continue
                    nv = self._sub(rule, v)
                    headers.append((k, nv))
                    if nv != v:
                        changed = True
                resp.headers = headers
            elif loc == "response-body" and resp.body:
                text = resp.body.decode("latin-1")
                new = self._sub(rule, text)
                if new != text:
                    resp.body = new.encode("latin-1")
                    low = {k.lower(): i for i, (k, _) in enumerate(resp.headers)}
                    if "content-length" in low:
                        i = low["content-length"]
                        resp.headers[i] = (resp.headers[i][0], str(len(resp.body)))
                    changed = True
        return resp if changed else None
