"""
HTTP/2 send/receive using the h2 library.

The proxy still stores flows as HTTP/1.1-shaped objects. This module is the
codec between those objects and HTTP/2 frames.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from core.http_message import HttpRequest, HttpResponse

try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        RequestReceived, ResponseReceived, DataReceived, StreamEnded,
        ConnectionTerminated, WindowUpdated,
    )
    from h2.exceptions import ProtocolError
    HAVE_H2 = True
except ImportError:  # pragma: no cover
    HAVE_H2 = False
    H2Connection = None  # type: ignore


def _b(v) -> str:
    if isinstance(v, bytes):
        return v.decode("latin-1")
    return str(v)


class H2Client:
    def __init__(self) -> None:
        if not HAVE_H2:
            raise RuntimeError("h2 package is not installed")
        self.conn = H2Connection(config=H2Configuration(client_side=True))
        self.conn.initiate_connection()

    def request_bytes(self, req: HttpRequest) -> bytes:
        parts = urlsplit(req.url)
        path = urlunsplit(("", "", parts.path or "/", parts.query, "")) or "/"
        headers = [
            (":method", req.method),
            (":scheme", parts.scheme or "https"),
            (":authority", parts.netloc),
            (":path", path),
        ]
        skip = {"host", "connection", "transfer-encoding", "upgrade",
                "keep-alive", "proxy-connection", "te"}
        for k, v in req.headers:
            if k.lower() in skip:
                continue
            headers.append((k.lower(), v))
        sid = self.conn.get_next_available_stream_id()
        self.conn.send_headers(sid, headers, end_stream=not req.body)
        if req.body:
            self.conn.send_data(sid, req.body, end_stream=True)
        return bytes(self.conn.data_to_send())

    def feed(self, data: bytes) -> HttpResponse | None:
        events = self.conn.receive_data(data)
        status = None
        headers: list[tuple[str, str]] = []
        body = bytearray()
        ended = False
        for ev in events:
            if isinstance(ev, ResponseReceived):
                for k, v in ev.headers:
                    ks, vs = _b(k), _b(v)
                    if ks == ":status":
                        status = int(vs)
                    elif not ks.startswith(":"):
                        headers.append((ks, vs))
            elif isinstance(ev, DataReceived):
                body += ev.data
                self.conn.acknowledge_received_data(
                    ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, StreamEnded):
                ended = True
            elif isinstance(ev, ConnectionTerminated):
                ended = True
        if ended and status is not None:
            return HttpResponse(status, "", headers, bytes(body), "HTTP/2")
        return None


class H2Server:
    def __init__(self) -> None:
        if not HAVE_H2:
            raise RuntimeError("h2 package is not installed")
        self.conn = H2Connection(config=H2Configuration(client_side=False))
        self.conn.initiate_connection()
        self._bodies: dict[int, bytearray] = {}
        self._heads: dict[int, list] = {}

    def pending(self) -> bytes:
        return bytes(self.conn.data_to_send())

    def feed_requests(self, data: bytes, scheme_host: str) -> list[tuple[int, HttpRequest]]:
        out = []
        try:
            events = self.conn.receive_data(data)
        except ProtocolError:
            return out
        for ev in events:
            if isinstance(ev, RequestReceived):
                self._heads[ev.stream_id] = list(ev.headers)
                self._bodies.setdefault(ev.stream_id, bytearray())
            elif isinstance(ev, DataReceived):
                self._bodies.setdefault(ev.stream_id, bytearray()).extend(ev.data)
                self.conn.acknowledge_received_data(
                    ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, StreamEnded):
                req = self._to_request(ev.stream_id, scheme_host)
                if req:
                    out.append((ev.stream_id, req))
            elif isinstance(ev, WindowUpdated):
                pass
        return out

    def _to_request(self, stream_id: int, scheme_host: str) -> HttpRequest | None:
        headers = self._heads.pop(stream_id, None)
        body = bytes(self._bodies.pop(stream_id, b""))
        if not headers:
            return None
        method = path = authority = ""
        hdrs = []
        for k, v in headers:
            ks, vs = _b(k), _b(v)
            if ks == ":method":
                method = vs
            elif ks == ":path":
                path = vs
            elif ks == ":authority":
                authority = vs
            elif not ks.startswith(":"):
                hdrs.append((ks, vs))
        if authority and not any(k.lower() == "host" for k, _ in hdrs):
            hdrs.append(("Host", authority))
        url = scheme_host.rstrip("/") + (path or "/")
        return HttpRequest(method or "GET", url, hdrs, body, "HTTP/2")

    def send_response(self, stream_id: int, resp: HttpResponse) -> bytes:
        headers = [(":status", str(resp.status_code))]
        skip = {"connection", "transfer-encoding", "keep-alive"}
        for k, v in resp.headers:
            if k.lower() in skip:
                continue
            headers.append((k.lower(), v))
        self.conn.send_headers(stream_id, headers, end_stream=not resp.body)
        if resp.body:
            self.conn.send_data(stream_id, resp.body, end_stream=True)
        else:
            pass
        return bytes(self.conn.data_to_send())
