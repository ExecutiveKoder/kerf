"""
In-scope crawler and JS URL extraction.

Follows links already seen in captured HTML/JS, plus a short list of mapping
paths (robots.txt, openapi.json, health). Refuses to run without a scope so it
cannot wander off the authorized host list.
"""

from __future__ import annotations

import asyncio
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from core.http_message import HttpRequest, Flow

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/192.168.1.5 Safari/537.36")

MAP_PATHS = (
    "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/graphql", "/.well-known/security.txt",
    "/health", "/ready", "/status",
)

_HREF = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"]+)['"]""", re.I)
_JS_URL = re.compile(
    r"""['"]((?:https?:)?//[^'"\s]+|/[/A-Za-z0-9._~!$&'()*+,;=:@%\-]+(?:\?[^'"\s]*)?)['"]"""
)
_ABS = re.compile(r"^https?://", re.I)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        ad = {k: v for k, v in attrs}
        for key in ("href", "src", "action"):
            if ad.get(key):
                self.links.append(ad[key])


def extract_urls(base: str, body: str, *, mime: str = "") -> list[str]:
    found: list[str] = []
    if "html" in (mime or "") or "<" in body[:400]:
        try:
            p = _LinkParser()
            p.feed(body)
            found.extend(p.links)
        except Exception:
            found.extend(_HREF.findall(body))
    found.extend(_JS_URL.findall(body))
    out = []
    seen = set()
    for raw in found:
        raw = raw.strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "data:", "#")):
            continue
        absu = raw if _ABS.match(raw) else urljoin(base, raw)
        if absu not in seen:
            seen.add(absu)
            out.append(absu)
    return out


class Crawler:
    def __init__(self, *, send, interceptor, history, events=None) -> None:
        self._send = send
        self._scope = interceptor
        self.history = history
        self._events = events
        self._jobs: dict = {}

    def _in_scope(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").split(":")[0]
        return bool(host) and self._scope.in_scope(host)

    def start(self, seed: str, *, max_pages: int = 40,
              map_paths: bool = True) -> dict:
        if not self._scope.scope_hosts:
            raise PermissionError(
                "Crawler refused: set an in-scope host list first.")
        seed = seed.strip()
        if not seed.startswith("http"):
            seed = "https://" + seed
        if not self._in_scope(seed):
            raise PermissionError("Crawler refused: seed host is out of scope.")
        job_id = str(int(time.time() * 1000))[-10:]
        state = {
            "id": job_id, "seed": seed, "status": "running",
            "queued": 0, "visited": 0, "found": 0, "error": None,
            "urls": [], "started": time.time(),
        }
        self._jobs[job_id] = state
        asyncio.create_task(self._run(state, seed, max_pages, map_paths))
        return dict(state)

    def list_jobs(self) -> list:
        return [dict(j) for j in self._jobs.values()]

    async def _run(self, state, seed, max_pages, map_paths):
        queue = [seed]
        seen = set()
        if map_paths:
            parts = urlsplit(seed)
            origin = f"{parts.scheme}://{parts.netloc}"
            for path in MAP_PATHS:
                queue.append(origin + path)
        try:
            while queue and state["visited"] < max_pages:
                url = queue.pop(0)
                if url in seen or not self._in_scope(url):
                    continue
                seen.add(url)
                state["queued"] = len(queue)
                req = HttpRequest("GET", url, [
                    ("Host", urlsplit(url).netloc),
                    ("User-Agent", UA),
                    ("Accept", "*/*"),
                ])
                try:
                    flow = await self._send(req)
                except Exception as exc:
                    if self._events:
                        self._events.add("crawler", f"error {url}: {exc}")
                    continue
                if self.history:
                    self.history.record(flow)
                state["visited"] += 1
                state["urls"].append({
                    "url": url,
                    "status": flow.response.status_code if flow.response else 0,
                })
                body = (flow.response.body if flow.response else b"").decode(
                    "latin-1", "replace")
                mime = flow.response.content_type if flow.response else ""
                for nxt in extract_urls(url, body, mime=mime):
                    if nxt not in seen and self._in_scope(nxt):
                        queue.append(nxt)
                        state["found"] += 1
            state["status"] = "done"
        except Exception as exc:
            state["status"] = "error"
            state["error"] = repr(exc)
        if self._events:
            self._events.add("crawler", f"{state['status']} {state['visited']} pages")
