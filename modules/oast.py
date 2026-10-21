"""
Local out-of-band listener.

Records HTTP callbacks on a port you choose. Useful when an authorized target
can reach this machine (or a tunnel you run). This is a callback log, not a
public hosted callback network and not an exploit recipe.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import deque
from urllib.parse import urlsplit


class OastListener:
    def __init__(self, events=None) -> None:
        self._server: asyncio.AbstractServer | None = None
        self.host = "127.0.0.1"
        self.port = 0
        self.hits: deque = deque(maxlen=500)
        self._events = events
        self.token = uuid.uuid4().hex[:12]

    def public(self) -> dict:
        listening = self._server is not None
        url = f"http://{self.host}:{self.port}/{self.token}" if listening else ""
        return {
            "listening": listening,
            "host": self.host,
            "port": self.port,
            "token": self.token,
            "url": url,
            "hits": list(self.hits),
        }

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> dict:
        await self.stop()
        self.host = host or "127.0.0.1"
        self.token = uuid.uuid4().hex[:12]
        self._server = await asyncio.start_server(self._handle, self.host, port)
        sock = self._server.sockets[0]
        self.port = sock.getsockname()[1]
        if self._events:
            self._events.add("oast", f"listening on {self.host}:{self.port}")
        return self.public()

    async def stop(self) -> dict:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        return self.public()

    def clear(self) -> dict:
        self.hits.clear()
        return self.public()

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            peer = writer.get_extra_info("peername")
            req_line = line.decode("latin-1", "replace").strip()
            headers = []
            while True:
                h = await asyncio.wait_for(reader.readline(), timeout=2)
                if h in (b"\r\n", b"\n", b""):
                    break
                headers.append(h.decode("latin-1", "replace").rstrip())
            path = req_line.split(" ")[1] if " " in req_line else "/"
            hit = {
                "ts": time.time(),
                "peer": f"{peer[0]}:{peer[1]}" if peer else "",
                "request_line": req_line,
                "path": path,
                "matched_token": self.token in path,
                "headers": headers[:20],
            }
            self.hits.appendleft(hit)
            if self._events:
                self._events.add("oast", f"hit {req_line}", peer=hit["peer"])
            body = (b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 3\r\n"
                    b"Connection: close\r\n\r\n"
                    b"ok\n")
            writer.write(body)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


def collaborator_url_from_status(status: dict) -> str:
    return status.get("url") or ""
