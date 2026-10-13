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


@dataclass
class Finding:
    severity: str          # info | low | medium | high
    title: str
    detail: str
    flow_id: str
    url: str
    check: str


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

    def __init__(self, checks: list[PassiveCheck] | None = None) -> None:
        self.checks = checks if checks is not None else list(DEFAULT_CHECKS)
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()  # dedupe by (check,title,host)

    async def on_flow_complete(self, flow: Flow) -> None:
        for check in self.checks:
            try:
                for f in check.run(flow):
                    key = (f.check, f.title, flow.request.host)
                    if key in self._seen:
                        continue
                    self._seen.add(key)
                    self.findings.append(f)
                    flow.notes.append(f"{f.severity}: {f.title}")
            except Exception as exc:
                print(f"[passive] check {check.name} error: {exc!r}")

    def report(self) -> list[dict]:
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        return [
            {
                "severity": f.severity, "title": f.title, "detail": f.detail,
                "url": f.url, "check": f.check, "flow_id": f.flow_id,
            }
            for f in sorted(self.findings, key=lambda f: order.get(f.severity, 9))
        ]
