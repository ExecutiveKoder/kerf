"""
Clean-room async intercepting HTTP/HTTPS proxy.

Design
------
- A single asyncio server listens on the proxy port.
- Plain HTTP: parse the absolute-form request line, forward upstream, relay back.
- HTTPS: client sends CONNECT host:port; we answer 200, then do a TLS handshake
  *as* that host using a leaf cert minted by our CA, read the real request on the
  now-decrypted stream, and forward it upstream over our own TLS client socket.

Every flow passes through the Interceptor (addon chain) so other modules and the
UI can observe, pause, or mutate requests and responses. This is our own code;
it is not a wrapper around another proxy.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from urllib.parse import urlsplit

from .ca import CertificateAuthority
from .http_message import Flow, HttpRequest, HttpResponse
from .http2 import HAVE_H2, H2Client, H2Server
from .interceptor import Interceptor
from .websocket import drain_frames, is_websocket

MAX_HEADER = 256 * 1024
MAX_BODY = 50 * 1024 * 1024


def tls_summary(sslobj) -> dict:
    if not sslobj:
        return {}
    try:
        cert = sslobj.getpeercert() or {}
    except Exception:
        cert = {}
    subject = {}
    for tup in cert.get("subject") or []:
        for k, v in tup:
            subject[k] = v
    issuer = {}
    for tup in cert.get("issuer") or []:
        for k, v in tup:
            issuer[k] = v
    cipher = sslobj.cipher() or (None, None, None)
    return {
        "alpn": sslobj.selected_alpn_protocol(),
        "version": sslobj.version(),
        "cipher": cipher[0],
        "subject": subject,
        "issuer": issuer,
        "san": [v for k, v in cert.get("subjectAltName", [])],
        "notAfter": cert.get("notAfter"),
    }


class ProxyServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 interceptor: Interceptor | None = None) -> None:
        self.host = host
        self.port = port
        self.ca = CertificateAuthority()
        self.interceptor = interceptor or Interceptor()
        self.upstream = None
        self.events = None
        self.gate = None  # optional callable: False → refuse traffic
        self.ws_log: list[dict] = []
        self._last_tls: dict | None = None
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        addr = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        print(f"[proxy] listening on {addr}")

    async def serve_forever(self) -> None:
        await self.start()
        async with self._server:
            await self._server.serve_forever()

    # -------------------------------------------------------------- client

    async def _write_locked(self, writer) -> None:
        body = (
            "Kerf is locked. Attest personal, non-commercial use in the UI. "
            "For commercial use, email accounts@kerf.software."
        ).encode()
        writer.write(
            (
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode() + body
        )
        await writer.drain()

    def _unlocked(self) -> bool:
        gate = self.gate
        if gate is None:
            return True
        try:
            return bool(gate())
        except Exception:
            return False

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        try:
            if not self._unlocked():
                await self._write_locked(writer)
                return
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return
            parts = request_line.decode("latin-1").strip().split(" ")
            if len(parts) < 3:
                writer.close()
                return
            method, target, version = parts[0], parts[1], parts[2]

            if method.upper() == "CONNECT":
                await self._handle_connect(target, reader, writer)
            else:
                await self._handle_plain(method, target, version, reader, writer)
        except (ConnectionResetError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        except Exception as exc:  # keep one bad flow from killing the server
            print(f"[proxy] client error: {exc!r}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # ---------------------------------------------------------- plain HTTP

    async def _handle_plain(self, method, target, version, reader, writer,
                            scheme_host: str | None = None) -> None:
        headers = await self._read_headers(reader)
        body = await self._read_body(reader, headers)

        if scheme_host:  # came off a decrypted TLS tunnel; target is origin-form
            url = scheme_host.rstrip("/") + target
        elif target.startswith("http://") or target.startswith("https://"):
            url = target  # normal absolute-form request from a configured proxy client
        else:
            # Origin-form request straight to the proxy port. This means the client
            # is NOT using us as a proxy (e.g. someone opened the proxy address in a
            # browser). Rebuild from Host if it points somewhere real; if it points
            # back at us or is missing, show a help page instead of dialing nowhere.
            host_hdr = next((v for k, v in headers if k.lower() == "host"), "").strip()
            own = {f"127.0.0.1:{self.port}", f"localhost:{self.port}",
                   f"[::1]:{self.port}", f"{self.host}:{self.port}"}
            if not host_hdr or host_hdr in own:
                await self._write_help(writer)
                return
            url = f"http://{host_hdr}{target}"

        req = HttpRequest(method, url, headers, body, version)
        await self._proxy_and_relay(req, reader, writer)

    async def _write_help(self, writer) -> None:
        body = (
            "<!doctype html><meta charset=utf-8>"
            "<title>Kerf proxy</title>"
            "<body style='font-family:system-ui;max-width:640px;margin:48px auto;"
            "color:#1a2234;line-height:1.5'>"
            "<h2>This is the Kerf proxy port</h2>"
            "<p>You reached the proxy directly. It's meant to be set as your browser's "
            "<b>HTTP/HTTPS proxy</b>, not opened in the address bar.</p>"
            "<ol><li>Open the <b>web UI</b> on the UI port (default "
            "<code>127.0.0.1:8000</code>).</li>"
            "<li>In your browser/OS network settings, set the HTTP and HTTPS proxy to "
            f"<code>{self.host}:{self.port}</code>.</li>"
            "<li>Install the Kerf CA from the UI's Setup tab so HTTPS validates.</li>"
            "<li>Browse normally; traffic appears under History.</li></ol>"
            "</body>")
        resp = (
            "HTTP/1.1 421 Misdirected Request\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            "Connection: close\r\n\r\n" + body)
        writer.write(resp.encode())
        await writer.drain()

    # ------------------------------------------------------------ CONNECT

    async def _handle_connect(self, target, reader, writer) -> None:
        host, _, port_s = target.partition(":")
        port = int(port_s or 443)

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        cert_pem, key_pem = self.ca.cert_for_host(host)
        import tempfile, os
        cf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        kf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        try:
            cf.write(cert_pem); cf.close()
            kf.write(key_pem); kf.close()
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cf.name, kf.name)
            if HAVE_H2:
                try:
                    server_ctx.set_alpn_protocols(["h2", "http/1.1"])
                except NotImplementedError:
                    pass
        finally:
            os.unlink(cf.name)
            os.unlink(kf.name)

        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()
        # Upgrade the client socket to TLS, presenting our leaf cert.
        try:
            new_transport = await loop.start_tls(
                transport, protocol, server_ctx, server_side=True
            )
        except ssl.SSLError:
            return
        tls_reader = asyncio.StreamReader()
        tls_reader.set_transport(new_transport)
        protocol._stream_reader = tls_reader  # rebind reader to decrypted stream
        tls_writer = asyncio.StreamWriter(new_transport, protocol, tls_reader, loop)

        if self.events:
            self.events.add("connect", f"CONNECT {host}:{port}")
        scheme_host = f"https://{host}:{port}" if port != 443 else f"https://{host}"
        sslobj = new_transport.get_extra_info("ssl_object")
        alpn = sslobj.selected_alpn_protocol() if sslobj else None
        if alpn == "h2" and HAVE_H2:
            await self._handle_h2_tunnel(tls_reader, tls_writer, scheme_host)
            return
        while True:
            line = await tls_reader.readline()
            if not line:
                break
            p = line.decode("latin-1").strip().split(" ")
            if len(p) < 3:
                break
            await self._handle_plain(p[0], p[1], p[2], tls_reader, tls_writer,
                                     scheme_host=scheme_host)

    # ------------------------------------------------------------- upstream

    async def _process_flow(self, req: HttpRequest) -> HttpResponse | None:
        from modules.intercept import FlowDropped
        flow = Flow(request=req)
        try:
            req = await self.interceptor.on_request(flow)
        except FlowDropped:
            if self.events:
                self.events.add("drop", f"dropped request {req.method} {req.url}")
            return None

        started = time.perf_counter()
        resp = await self._send_upstream(req)
        flow.duration_ms = (time.perf_counter() - started) * 1000
        flow.response = resp
        flow.tls = self._last_tls
        if req.http_version == "HTTP/2" or (resp and resp.http_version == "HTTP/2"):
            flow.protocol = "http/2"
        if self._last_tls and self._last_tls.get("alpn"):
            flow.protocol = self._last_tls.get("alpn") or flow.protocol

        try:
            resp = await self.interceptor.on_response(flow)
        except FlowDropped:
            if self.events:
                self.events.add("drop", f"dropped response {req.method} {req.url}")
            return None
        flow.response = resp
        await self.interceptor.on_flow_complete(flow)
        return resp

    async def _proxy_and_relay(self, req: HttpRequest, reader, writer) -> None:
        if is_websocket(req):
            await self._handle_websocket(req, reader, writer)
            return
        resp = await self._process_flow(req)
        if resp is None:
            await self._write_dropped(writer, "request")
            return
        writer.write(resp.raw())
        await writer.drain()

    async def _handle_h2_tunnel(self, reader, writer, scheme_host: str) -> None:
        srv = H2Server()
        writer.write(srv.pending())
        await writer.drain()
        while True:
            data = await reader.read(65535)
            if not data:
                break
            for sid, req in srv.feed_requests(data, scheme_host):
                req.http_version = "HTTP/2"
                resp = await self._process_flow(req)
                if resp is None:
                    resp = HttpResponse(403, "Forbidden",
                                        [("Content-Type", "text/plain")],
                                        b"Kerf: dropped by intercept.\n",
                                        "HTTP/2")
                writer.write(srv.send_response(sid, resp))
                await writer.drain()
            extra = srv.pending()
            if extra:
                writer.write(extra)
                await writer.drain()

    async def _handle_websocket(self, req: HttpRequest, client_reader, client_writer):
        from modules.intercept import FlowDropped
        flow = Flow(request=req, protocol="websocket")
        try:
            req = await self.interceptor.on_request(flow)
        except FlowDropped:
            await self._write_dropped(client_writer, "request")
            return
        up_reader, up_writer, _tls = await self._open_upstream(req, close_hint=False)
        if up_reader is None:
            client_writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
            return
        up_writer.write(req.raw())
        await up_writer.drain()
        resp = await self._read_response(up_reader)
        flow.response = resp
        try:
            await self.interceptor.on_response(flow)
        except FlowDropped:
            await self._write_dropped(client_writer, "response")
            return
        await self.interceptor.on_flow_complete(flow)
        client_writer.write(resp.raw())
        await client_writer.drain()
        if resp.status_code != 101:
            up_writer.close()
            return
        conv = {"url": req.url, "frames": [], "started": time.time()}
        self.ws_log.append(conv)
        if self.events:
            self.events.add("websocket", f"upgrade {req.url}")

        async def pump(src, dst, direction):
            buf = bytearray()
            try:
                while True:
                    chunk = await src.read(65535)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    for fr in drain_frames(buf):
                        fr["dir"] = direction
                        fr["ts"] = time.time()
                        conv["frames"].append(fr)
                        if self.events:
                            self.events.add("websocket",
                                            f"{direction} {fr['opcode']} {fr['length']}B")
                    dst.write(chunk)
                    await dst.drain()
            except Exception:
                pass

        await asyncio.gather(
            pump(client_reader, up_writer, "in"),
            pump(up_reader, client_writer, "out"),
        )
        try:
            up_writer.close()
        except Exception:
            pass

    async def _write_dropped(self, writer, kind: str) -> None:
        body = f"Kerf: {kind} dropped by intercept.\n".encode()
        writer.write(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n" + body
        )
        try:
            await writer.drain()
        except Exception:
            pass

    async def _open_upstream(self, req: HttpRequest, *, close_hint: bool = True):
        parts = urlsplit(req.url)
        host = parts.hostname or ""
        if not host:
            return None, None, None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ssl_ctx = None
        if parts.scheme == "https":
            ssl_ctx = ssl.create_default_context()
            if HAVE_H2:
                try:
                    ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])
                except NotImplementedError:
                    pass
            if self.upstream and hasattr(self.upstream, "client_cert_paths"):
                pair = self.upstream.client_cert_paths()
                if pair:
                    try:
                        ssl_ctx.load_cert_chain(pair[0], pair[1])
                    except Exception as exc:
                        if self.events:
                            self.events.add("tls", f"client cert failed: {exc}")
        try:
            if self.upstream:
                up_reader, up_writer = await self.upstream.open(host, port, ssl_ctx=ssl_ctx)
            else:
                up_reader, up_writer = await asyncio.open_connection(
                    host, port, ssl=ssl_ctx,
                    server_hostname=host if ssl_ctx else None)
        except Exception as exc:
            if self.events:
                self.events.add("error", f"upstream {host}:{port} {exc}")
            return None, None, exc
        sslobj = up_writer.get_extra_info("ssl_object")
        tls = tls_summary(sslobj) if sslobj else None
        self._last_tls = tls
        if close_hint:
            req.set_header("Accept-Encoding", "identity")
            req.set_header("Connection", "close")
        return up_reader, up_writer, tls

    async def _send_upstream(self, req: HttpRequest) -> HttpResponse:
        parts = urlsplit(req.url)
        host = parts.hostname or ""
        if not host:
            return HttpResponse(400, "Bad Request",
                                [("Content-Type", "text/plain")],
                                (b"Kerf: no target host in the request. If you are "
                                 b"using Replay, include a 'Host:' header. If this came "
                                 b"from a browser, set Kerf as the proxy rather than "
                                 b"connecting to it directly."))
        up_reader, up_writer, err = await self._open_upstream(req)
        if up_reader is None:
            detail = f"Kerf upstream error: {err}" if err else "Kerf upstream error"
            return HttpResponse(502, "Bad Gateway",
                                [("Content-Type", "text/plain")],
                                detail.encode())
        alpn = (self._last_tls or {}).get("alpn")
        try:
            if alpn == "h2" and HAVE_H2:
                return await self._send_h2(up_reader, up_writer, req)
            up_writer.write(req.raw())
            await up_writer.drain()
            return await self._read_response(up_reader)
        finally:
            try:
                up_writer.close()
            except Exception:
                pass

    async def _send_h2(self, reader, writer, req: HttpRequest) -> HttpResponse:
        client = H2Client()
        writer.write(client.request_bytes(req))
        await writer.drain()
        while True:
            data = await reader.read(65535)
            if not data:
                break
            extra = client.conn.data_to_send()
            resp = client.feed(data)
            extra += client.conn.data_to_send()
            if extra:
                writer.write(extra)
                await writer.drain()
            if resp:
                return resp
        return HttpResponse(502, "Bad Gateway",
                            [("Content-Type", "text/plain")],
                            b"HTTP/2 stream ended without a response")

    # --------------------------------------------------------------- parse

    async def _read_headers(self, reader) -> list[tuple[str, str]]:
        headers = []
        size = 0
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            size += len(line)
            if size > MAX_HEADER:
                raise ValueError("header too large")
            k, _, v = line.decode("latin-1").partition(":")
            headers.append((k.strip(), v.strip()))
        return headers

    async def _read_body(self, reader, headers) -> bytes:
        hd = {k.lower(): v for k, v in headers}
        if "content-length" in hd:
            n = min(int(hd["content-length"]), MAX_BODY)
            return await reader.readexactly(n) if n else b""
        if hd.get("transfer-encoding", "").lower() == "chunked":
            return await self._read_chunked(reader)
        return b""

    async def _read_chunked(self, reader) -> bytes:
        out = bytearray()
        while True:
            size_line = await reader.readline()
            if not size_line:
                break
            size = int(size_line.strip().split(b";")[0] or b"0", 16)
            if size == 0:
                await reader.readline()  # trailing CRLF
                break
            out += await reader.readexactly(size)
            await reader.readline()
            if len(out) > MAX_BODY:
                break
        return bytes(out)

    async def _read_response(self, reader) -> HttpResponse:
        status_line = await reader.readline()
        parts = status_line.decode("latin-1").strip().split(" ", 2)
        version = parts[0] if parts else "HTTP/1.1"
        code = int(parts[1]) if len(parts) > 1 else 502
        reason = parts[2] if len(parts) > 2 else ""
        headers = await self._read_headers(reader)
        body = await self._read_body_response(reader, headers)
        return HttpResponse(code, reason, headers, body, version)

    async def _read_body_response(self, reader, headers) -> bytes:
        hd = {k.lower(): v for k, v in headers}
        if hd.get("transfer-encoding", "").lower() == "chunked":
            return await self._read_chunked(reader)
        if "content-length" in hd:
            n = min(int(hd["content-length"]), MAX_BODY)
            return await reader.readexactly(n) if n else b""
        # No length and not chunked: read until EOF (Connection: close).
        try:
            return await reader.read(MAX_BODY)
        except asyncio.IncompleteReadError as e:
            return e.partial
