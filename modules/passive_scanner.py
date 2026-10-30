"""
Passive scanner.

Inspects flows that have ALREADY happened and reports defensive-posture and
information-disclosure issues. It never sends a request of its own and never
injects a payload. It is the web-security equivalent of a linter reading logs.

Each check looks at a completed Flow and may append Findings. Add your own
passive checks by subclassing PassiveCheck and registering it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.interceptor import BaseAddon
from core.http_message import Flow
from modules.components import ComponentInventory, finding_detail


@dataclass
class Finding:
    severity: str          # info | low | medium | high
    title: str
    detail: str
    flow_id: str
    url: str
    check: str
    extra: dict = field(default_factory=dict)


class PassiveCheck:
    name = "base"

    def run(self, flow: Flow) -> list[Finding]:
        raise NotImplementedError


# --------------------------------------------------------------- checks


class SecurityHeadersCheck(PassiveCheck):
    name = "security-headers"
    EXPECTED = {
        "strict-transport-security": ("medium", "HSTS header missing",
            "Responses over HTTPS should set Strict-Transport-Security."),
        "content-security-policy": ("medium", "Content-Security-Policy missing",
            "No CSP header; the page has no policy-based XSS mitigation."),
        "x-content-type-options": ("low", "X-Content-Type-Options missing",
            "Set 'nosniff' to stop MIME sniffing."),
        "x-frame-options": ("low", "Clickjacking protection missing",
            "No X-Frame-Options or frame-ancestors; page may be framable."),
        "referrer-policy": ("info", "Referrer-Policy missing",
            "No Referrer-Policy; referrers may leak to third parties."),
    }

    def run(self, flow: Flow) -> list[Finding]:
        resp = flow.response
        if not resp or "html" not in resp.content_type:
            return []
        present = {k.lower() for k, _ in resp.headers}
        out = []
        is_https = flow.request.url.startswith("https")
        for header, (sev, title, detail) in self.EXPECTED.items():
            if header == "strict-transport-security" and not is_https:
                continue
            if header not in present:
                out.append(Finding(sev, title, detail, flow.id, flow.request.url, self.name))
        return out


class CookieFlagsCheck(PassiveCheck):
    name = "cookie-flags"

    def run(self, flow: Flow) -> list[Finding]:
        resp = flow.response
        if not resp:
            return []
        out = []
        for k, v in resp.headers:
            if k.lower() != "set-cookie":
                continue
            low = v.lower()
            name = v.split("=", 1)[0].strip()
            if "httponly" not in low:
                out.append(Finding("medium", "Cookie without HttpOnly",
                    f"Cookie '{name}' is readable by JavaScript.",
                    flow.id, flow.request.url, self.name))
            if flow.request.url.startswith("https") and "secure" not in low:
                out.append(Finding("medium", "Cookie without Secure",
                    f"Cookie '{name}' may be sent over plain HTTP.",
                    flow.id, flow.request.url, self.name))
            if "samesite" not in low:
                out.append(Finding("low", "Cookie without SameSite",
                    f"Cookie '{name}' has no SameSite attribute (CSRF exposure).",
                    flow.id, flow.request.url, self.name))
        return out


class InfoDisclosureCheck(PassiveCheck):
    name = "info-disclosure"
    HEADER_LEAKS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")
    BODY_PATTERNS = [
        (re.compile(rb"(?i)stack trace|traceback \(most recent"), "Stack trace in response"),
        (re.compile(rb"(?i)SQL syntax|ORA-\d{5}|SQLSTATE"), "Database error in response"),
        (re.compile(rb"(?i)-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Private key in response"),
    ]

    def run(self, flow: Flow) -> list[Finding]:
        resp = flow.response
        if not resp:
            return []
        out = []
        for h in self.HEADER_LEAKS:
            val = resp.header(h)
            if val:
                out.append(Finding("info", f"Technology disclosed via {h}",
                    f"Header reveals: {val}", flow.id, flow.request.url, self.name))
        for pat, title in self.BODY_PATTERNS:
            if pat.search(resp.body or b""):
                out.append(Finding("medium", title,
                    "Response body leaks sensitive diagnostic content.",
                    flow.id, flow.request.url, self.name))
        return out


class MixedContentCheck(PassiveCheck):
    name = "mixed-content"
    PAT = re.compile(rb"""(?:src|href)\s*=\s*['"]http://""", re.I)

    def run(self, flow: Flow) -> list[Finding]:
        resp = flow.response
        if not resp or not flow.request.url.startswith("https"):
            return []
        if "html" not in resp.content_type:
            return []
        if self.PAT.search(resp.body or b""):
            return [Finding("low", "Mixed content",
                "HTTPS page references plain-HTTP subresources.",
                flow.id, flow.request.url, self.name)]
        return []


DEFAULT_CHECKS: list[PassiveCheck] = [
    SecurityHeadersCheck(),
    CookieFlagsCheck(),
    InfoDisclosureCheck(),
    MixedContentCheck(),
]


class PassiveScanner(BaseAddon):
    """Runs passive checks on every completed flow; collects findings."""

    def __init__(self, checks: list[PassiveCheck] | None = None, *,
                 lookups: bool = True, inventory_path=None, events=None) -> None:
        self.checks = checks if checks is not None else list(DEFAULT_CHECKS)
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()  # dedupe by (check,title,host)
        # Versioned software (PHP, Node.js, nginx, jQuery…) is looked up against
        # public advisories; only product + version leave the machine.
        self.components = ComponentInventory(
            self._component_finding, lookups=lookups, path=inventory_path, events=events)

    def _add(self, f: Finding, host: str, flow: Flow | None = None) -> None:
        key = (f.check, f.title, host)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(f)
        if flow is not None:
            flow.notes.append(f"{f.severity}: {f.title}")

    def _component_finding(self, item: dict, host: str, url: str, flow_id: str) -> None:
        """(Re)place the finding for one component on one host. A re-check can
        change the title or clear the issue, so the old one is dropped first."""
        keep = []
        for f in self.findings:
            if (f.check == "vulnerable-component"
                    and f.extra.get("component") == item["id"]
                    and f.extra.get("host") == host):
                self._seen.discard((f.check, f.title, host))
            else:
                keep.append(f)
        self.findings = keep
        res = item["result"]
        if res.get("status") != "vulnerable":
            return
        top = (res.get("cves") or [{}])[0]
        self._add(Finding(
            res["severity"], res["title"], finding_detail(res), flow_id, url,
            "vulnerable-component",
            extra={"cvss": res.get("max_cvss"), "cve": top.get("id", ""),
                   "kev": res.get("kev"), "epss": res.get("max_epss"),
                   "evidence": item["evidence"], "component": item["id"],
                   "host": host},
        ), host)

    async def on_flow_complete(self, flow: Flow) -> None:
        for check in self.checks:
            try:
                for f in check.run(flow):
                    self._add(f, flow.request.host, flow)
            except Exception as exc:
                print(f"[passive] check {check.name} error: {exc!r}")
        try:
            self.components.observe(flow)
        except Exception as exc:
            print(f"[passive] component fingerprint error: {exc!r}")

    def report(self) -> list[dict]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return [
            {
                "severity": f.severity, "title": f.title, "detail": f.detail,
                "url": f.url, "check": f.check, "flow_id": f.flow_id, **f.extra,
            }
            # Exploited now (KEV), likely soon (EPSS), then severity and CVSS.
            for f in sorted(self.findings, key=lambda f: (
                0 if f.extra.get("kev") else
                1 if (f.extra.get("epss") or 0) >= 0.1 else 2,
                order.get(f.severity, 9), -(f.extra.get("cvss") or 0)))
        ]
