"""
Active-scan engine — SCAFFOLD ONLY.

================================================================================
IMPORTANT: THIS FILE SHIPS WITH NO ATTACK CHECKS AND NO PAYLOADS.
================================================================================

Active scanning sends crafted requests to a target to probe for vulnerabilities.
That is a legitimate activity ONLY against systems you own or are explicitly
authorized to test. Because the code behaves identically against an authorized
and an unauthorized target, this project does not bundle offensive payloads or
vulnerability-confirmation logic.

What this file provides:
  - the engine that enforces scope, discovers insertion points, schedules checks,
    rate-limits, and collects results;
  - the ActiveCheck interface a check must implement;
  - a required authorization gate the operator must satisfy before any active
    check will run.

What this file deliberately does NOT provide:
  - SQLi / XSS / SSRF / command-injection / auth-bypass payloads;
  - detection heuristics that confirm exploitability.

To use active scanning, YOU (the operator / project contributors) write
ActiveCheck subclasses for the vulnerability classes you are authorized to test,
place them in the extensions directory, and register them via the ExtensionAPI.
See docs/WRITING_ACTIVE_CHECKS.md and extensions/example_passive_check.py for the
pattern. Keep your checks for authorized engagements only.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from core.http_message import HttpRequest, Flow


@dataclass
class InsertionPoint:
    """A place in a request where a check may substitute a payload."""
    kind: str          # "query", "body-form", "header", "cookie"
    name: str
    value: str


@dataclass
class ActiveFinding:
    severity: str
    title: str
    detail: str
    url: str
    check: str
    confidence: str = "firm"


class ActiveCheck:
    """Interface for an operator-supplied active check.

    Implement `probe` to return findings. You receive the base request, a single
    insertion point, and a `send` coroutine to issue requests. You are
    responsible for ensuring you are authorized to test the target.
    """

    name = "unnamed-active-check"
    severity = "info"

    async def probe(self, base: HttpRequest, point: InsertionPoint, send) -> list[ActiveFinding]:
        raise NotImplementedError(
            "No active checks ship with this tool. Supply your own for "
            "authorized targets. See docs/WRITING_ACTIVE_CHECKS.md."
        )


def discover_insertion_points(req: HttpRequest) -> list[InsertionPoint]:
    """Enumerate candidate insertion points. This is inert on its own: it just
    lists where parameters are; it does not modify anything."""
    points: list[InsertionPoint] = []
    for k, v in req.query_params:
        points.append(InsertionPoint("query", k, v))
    ctype = (req.header("content-type") or "").lower()
    if "application/x-www-form-urlencoded" in ctype and req.body:
        from urllib.parse import parse_qsl
        for k, v in parse_qsl(req.body.decode("latin-1"), keep_blank_values=True):
            points.append(InsertionPoint("body-form", k, v))
    cookie = req.header("cookie")
    if cookie:
        for pair in cookie.split(";"):
            if "=" in pair:
                k, _, v = pair.strip().partition("=")
                points.append(InsertionPoint("cookie", k, v))
    return points


class ActiveScanEngine:
    def __init__(self, send_coro, *, scope_hosts: set[str] | None = None,
                 max_concurrency: int = 4, authorized: bool = False) -> None:
        self._send = send_coro
        self._checks: list[ActiveCheck] = []
        self.scope_hosts = scope_hosts or set()
        self._sem = asyncio.Semaphore(max_concurrency)
        self.findings: list[ActiveFinding] = []
        # Hard gate: active scanning refuses to run until the operator asserts
        # authorization for the target scope.
        self.authorized = authorized

    def register(self, check: ActiveCheck) -> None:
        self._checks.append(check)

    def authorize_scope(self, hosts: set[str]) -> None:
        """Operator asserts they are authorized to actively test these hosts."""
        self.scope_hosts = set(hosts)
        self.authorized = True

    def _in_scope(self, url: str) -> bool:
        host = urlsplit(url).hostname or ""
        if not self.scope_hosts:
            return False  # empty scope = nothing is in scope, by design
        return any(host == s or host.endswith("." + s) for s in self.scope_hosts)

    async def scan_flow(self, flow: Flow) -> list[ActiveFinding]:
        if not self.authorized:
            raise PermissionError(
                "Active scan refused: no authorized scope set. Call "
                "authorize_scope({...}) to assert you may test these hosts."
            )
        if not self._in_scope(flow.request.url):
            return []
        if not self._checks:
            # Nothing to run: no checks are bundled. This is expected.
            return []

        points = discover_insertion_points(flow.request)
        results: list[ActiveFinding] = []
        for check in self._checks:
            for point in points:
                async with self._sem:
                    try:
                        found = await check.probe(flow.request, point, self._send)
                        results.extend(found)
                    except NotImplementedError:
                        pass
                    except Exception as exc:
                        print(f"[active] {check.name} error: {exc!r}")
        self.findings.extend(results)
        return results
