"""
Optional outbound hop after Kerf decrypts a request.

Browser → Kerf → (this proxy) → target.

Typical use is Tor (SOCKS5 on 127.0.0.1:9050 or Tor Browser on 9150).
Also accepts a plain HTTP CONNECT proxy. Direct is the default.
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))
SETTINGS_PATH = CONFIG_DIR / "upstream.json"

PRESETS = {
    "direct": {"label": "Direct — no outbound proxy", "kind": "direct",
               "host": "", "port": 0},
    "tor": {"label": "Tor (SOCKS5 · 9050)", "kind": "socks5",
            "host": "127.0.0.1", "port": 9050},
    "tor-browser": {"label": "Tor Browser (SOCKS5 · 9150)", "kind": "socks5",
                    "host": "127.0.0.1", "port": 9150},
    "custom": {"label": "Custom HTTP or SOCKS5", "kind": "socks5",
               "host": "127.0.0.1", "port": 9050},
}


def default_settings() -> dict:
    return {
        "enabled": False,
        "preset": "direct",
        "kind": "direct",
        "host": "127.0.0.1",
        "port": 9050,
        "username": "",
        "password": "",
        "client_cert": "",
        "client_key": "",
    }


class UpstreamRoute:
    def __init__(self) -> None:
        self._settings = self._load()

    def _load(self) -> dict:
        s = default_settings()
        try:
            if SETTINGS_PATH.exists():
                data = json.loads(SETTINGS_PATH.read_text())
                if isinstance(data, dict):
                    s.update({k: data.get(k, s[k]) for k in s})
        except Exception as exc:
            print(f"[upstream] settings load error: {exc!r}")
        return s

    def _save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(json.dumps(self._settings, indent=2))

    def public(self) -> dict:
        s = dict(self._settings)
        pw = s.get("password") or ""
        s["password_set"] = bool(pw)
        s["password"] = "••••" if pw else ""
        s["presets"] = [{"id": k, **{kk: vv for kk, vv in v.items()}}
                        for k, v in PRESETS.items()]
        s["active"] = bool(s.get("enabled") and s.get("kind") != "direct")
        s["client_cert_set"] = bool(s.get("client_cert"))
        return s

    def configure(self, patch: dict) -> dict:
        allowed = set(default_settings())
        for k, v in (patch or {}).items():
            if k not in allowed:
                continue
            if k == "password" and isinstance(v, str) and "•" in v:
                continue
            if k == "port":
                try:
                    v = int(v or 0)
                except (TypeError, ValueError):
                    continue
            if k == "enabled":
                v = bool(v)
            self._settings[k] = v
        preset = self._settings.get("preset") or "direct"
        if preset in PRESETS and preset != "custom":
            meta = PRESETS[preset]
            self._settings["kind"] = meta["kind"]
            if meta["host"]:
                self._settings["host"] = meta["host"]
            if meta["port"]:
                self._settings["port"] = meta["port"]
        if self._settings.get("kind") == "direct":
            self._settings["enabled"] = False
        self._save()
        return self.public()

    def _url(self) -> str | None:
        s = self._settings
        if not s.get("enabled") or s.get("kind") in ("", "direct"):
            return None
        kind = (s.get("kind") or "socks5").lower()
        if kind not in ("socks5", "socks4", "http"):
            kind = "socks5"
        host = (s.get("host") or "").strip()
        port = int(s.get("port") or 0)
        if not host or not port:
            return None
        user = (s.get("username") or "").strip()
        pw = s.get("password") or ""
        auth = f"{user}:{pw}@" if user else ""
        return f"{kind}://{auth}{host}:{port}"

    def client_cert_paths(self) -> tuple[str, str] | None:
        cert = (self._settings.get("client_cert") or "").strip()
        key = (self._settings.get("client_key") or "").strip()
        if cert and key:
            return cert, key
        return None

    async def open(self, dest_host: str, dest_port: int, *,
                   ssl_ctx: ssl.SSLContext | None = None):
        url = self._url()
        if not url:
            return await asyncio.open_connection(
                dest_host, dest_port, ssl=ssl_ctx,
                server_hostname=dest_host if ssl_ctx else None)
        from python_socks.async_.asyncio import Proxy
        proxy = Proxy.from_url(url)
        sock = await proxy.connect(dest_host=dest_host, dest_port=dest_port)
        return await asyncio.open_connection(
            sock=sock, ssl=ssl_ctx,
            server_hostname=dest_host if ssl_ctx else None)

    async def test(self) -> dict:
        s = self._settings
        kind = s.get("kind") or "direct"
        if kind == "direct" or not s.get("enabled"):
            return {"ok": True, "detail": "Direct — no outbound proxy."}
        host = (s.get("host") or "").strip()
        port = int(s.get("port") or 0)
        if not host or not port:
            return {"ok": False, "detail": "Host and port required."}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5)
        except Exception as exc:
            hint = ""
            if port in (9050, 9150):
                hint = " Start Tor (`tor`) or Tor Browser first."
            return {"ok": False, "detail": f"Cannot reach {host}:{port} — {exc}.{hint}"}
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {"ok": True,
                "detail": f"Reached {kind} {host}:{port}. Outbound hop is ready."}
