"""
Parsed HTTP request/response model used across all modules.

Deliberately simple and framework-free so the proxy, history, repeater,
intruder, scanner and UI all speak the same objects.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = "HTTP/1.1"

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def set_header(self, name: str, value: str) -> None:
        low = name.lower()
        for i, (k, _) in enumerate(self.headers):
            if k.lower() == low:
                self.headers[i] = (k, value)
                return
        self.headers.append((name, value))

    @property
    def host(self) -> str:
        return urlsplit(self.url).netloc

    @property
    def path(self) -> str:
        parts = urlsplit(self.url)
        return urlunsplit(("", "", parts.path or "/", parts.query, ""))

    @property
    def query_params(self) -> list[tuple[str, str]]:
        return parse_qsl(urlsplit(self.url).query, keep_blank_values=True)

    def with_query_params(self, params: list[tuple[str, str]]) -> "HttpRequest":
        parts = urlsplit(self.url)
        new = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(params), parts.fragment)
        )
        return HttpRequest(self.method, new, list(self.headers), self.body, self.http_version)

    def raw(self) -> bytes:
        """Serialize to an over-the-wire HTTP/1.1 request (origin form)."""
        parts = urlsplit(self.url)
        target = urlunsplit(("", "", parts.path or "/", parts.query, "")) or "/"
        lines = [f"{self.method} {target} {self.http_version}"]
        for k, v in self.headers:
            lines.append(f"{k}: {v}")
        head = "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n"
        return head + self.body


@dataclass
class HttpResponse:
    status_code: int
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = "HTTP/1.1"

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    def raw(self) -> bytes:
        lines = [f"{self.http_version} {self.status_code} {self.reason}"]
        for k, v in self.headers:
            lines.append(f"{k}: {v}")
        head = "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n"
        return head + self.body


@dataclass
class Flow:
    """A request paired with its response (response may be None until received)."""

    request: HttpRequest
    response: HttpResponse | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    duration_ms: float | None = None
    # Populated by passive scanner and tags.
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "id": self.id,
            "method": self.request.method,
            "host": self.request.host,
            "path": self.request.path,
            "status": self.response.status_code if self.response else None,
            "length": len(self.response.body) if self.response else 0,
            "mime": self.response.content_type if self.response else "",
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
            "notes": self.notes,
        }
