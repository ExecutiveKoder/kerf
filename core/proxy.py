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
from .interceptor import Interceptor

MAX_HEADER = 256 * 1024
MAX_BODY = 50 * 1024 * 1024


class ProxyServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 interceptor: Interceptor | None = None) -> None:
        self.host = host
        self.port = port
        self.ca = CertificateAuthority()
        self.interceptor = interceptor or Interceptor()
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

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        try:
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
        await self._proxy_and_relay(req, writer)

    async def _write_help(self, writer) -> None:
        body = (
            "<!doctype html><meta charset=utf-8>"
            "<title>DastDay proxy</title>"
            "<body style='font-family:system-ui;max-width:640px;margin:48px auto;"
            "color:#1a2234;line-height:1.5'>"
            "<h2>This is the DastDay proxy port</h2>"
            "<p>You reached the proxy directly. It's meant to be set as your browser's "
            "<b>HTTP/HTTPS proxy</b>, not opened in the address bar.</p>"
            "<ol><li>Open the <b>web UI</b> on the UI port (default "
            "<code>127.0.0.1:8000</code>).</li>"
            "<li>In your browser/OS network settings, set the HTTP and HTTPS proxy to "
            f"<code>{self.host}:{self.port}</code>.</li>"
            "<li>Install the DastDay CA from the UI's Setup tab so HTTPS validates.</li>"
            "<li>Browse normally; traffic appears under Proxy history.</li></ol>"
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

        # Now read origin-form requests off the decrypted tunnel, keep-alive.
        scheme_host = f"https://{host}:{port}" if port != 443 else f"https://{host}"
        while True:
            line = await tls_reader.readline()
            if not line:
                break
            p = line.decode("latin-1").strip().split(" ")
            if len(p) < 3:
                break
            await self._handle_plain(p[0], p[1], p[2], tls_reader, tls_writer,
                                     scheme_host=scheme_host)
            # crude keep-alive: loop for the next request on the same tunnel

    # ------------------------------------------------------------- upstream

    async def _proxy_and_relay(self, req: HttpRequest, writer) -> None:
        flow = Flow(request=req)
        # Let addons mutate/observe the request before it leaves.
        req = await self.interceptor.on_request(flow)

        started = time.perf_counter()
        resp = await self._send_upstream(req)
        flow.duration_ms = (time.perf_counter() - started) * 1000
        flow.response = resp

        resp = await self.interceptor.on_response(flow)
        flow.response = resp
        await self.interceptor.on_flow_complete(flow)

        writer.write(resp.raw())
        await writer.drain()

    async def _send_upstream(self, req: HttpRequest) -> HttpResponse:
        parts = urlsplit(req.url)
        host = parts.hostname or ""
        if not host:
            return HttpResponse(400, "Bad Request",
                                [("Content-Type", "text/plain")],
                                (b"DastDay: no target host in the request. If you are "
                                 b"using Repeater, include a 'Host:' header. If this came "
                                 b"from a browser, set DastDay as the proxy rather than "
                                 b"connecting to it directly."))
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ssl_ctx = None
        if parts.scheme == "https":
            ssl_ctx = ssl.create_default_context()
            # We validate upstream normally; this proxy is not a MITM of real CAs.

        try:
            up_reader, up_writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
        except (OSError, ssl.SSLError) as exc:
            return HttpResponse(502, "Bad Gateway",
                                [("Content-Type", "text/plain")],
                                f"DastDay upstream error: {exc}".encode())

        # Force no compression/keep-alive we can't handle, keep it simple+correct.
        req.set_header("Accept-Encoding", "identity")
        req.set_header("Connection", "close")
        up_writer.write(req.raw())
        await up_writer.drain()

        resp = await self._read_response(up_reader)
        up_writer.close()
        return resp

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
