"""
Cookie jar and session-handling rules.

Keeps cookies per host, optionally injects them on the way out, and can replay
a stored login request when a response comes back 401. Authorization-gated
macros only fire against in-scope hosts.
"""

from __future__ import annotations

import json
import os
import time
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

from core.interceptor import BaseAddon
from core.http_message import Flow, HttpRequest

CONFIG_DIR = Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))
SETTINGS_PATH = CONFIG_DIR / "session.json"


def _default() -> dict:
    return {
        "inject": True,
        "update": True,
        "retry_on_401": False,
        "login_raw": "",
        "login_scheme": "https",
    }


class SessionHandler(BaseAddon):
    def __init__(self, *, send_raw=None) -> None:
        self._settings = self._load()
        self._jar: dict[str, dict[str, str]] = {}
        self._send_raw = send_raw
        self._retrying = False

    def _load(self) -> dict:
        s = _default()
        try:
            if SETTINGS_PATH.exists():
                data = json.loads(SETTINGS_PATH.read_text())
                if isinstance(data, dict):
                    s.update({k: data.get(k, s[k]) for k in s})
        except Exception as exc:
            print(f"[session] load error: {exc!r}")
        return s

    def _save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(json.dumps(self._settings, indent=2))

    def public(self) -> dict:
        cookies = []
        for host, jar in sorted(self._jar.items()):
            for name, value in jar.items():
                cookies.append({"host": host, "name": name, "value": value})
        return {**self._settings, "cookies": cookies, "hosts": sorted(self._jar)}

    def configure(self, patch: dict) -> dict:
        for k in _default():
            if k in patch and patch[k] is not None:
                self._settings[k] = patch[k]
        self._save()
        return self.public()

    def set_cookie(self, host: str, name: str, value: str) -> dict:
        host = host.split(":")[0]
        self._jar.setdefault(host, {})[name] = value
        return self.public()

    def delete_cookie(self, host: str, name: str) -> dict:
        host = host.split(":")[0]
        jar = self._jar.get(host) or {}
        jar.pop(name, None)
        if not jar:
            self._jar.pop(host, None)
        return self.public()

    def clear(self) -> dict:
        self._jar.clear()
        return self.public()

    def cookie_header(self, host: str) -> str:
        host = host.split(":")[0]
        jar = {}
        for h, items in self._jar.items():
            if host == h or host.endswith("." + h):
                jar.update(items)
        return "; ".join(f"{k}={v}" for k, v in jar.items())

    def _ingest(self, host: str, set_cookie: str) -> None:
        host = host.split(":")[0]
        parsed = SimpleCookie()
        try:
            parsed.load(set_cookie)
        except Exception:
            if "=" in set_cookie:
                name, _, val = set_cookie.partition(";")[0].partition("=")
                self._jar.setdefault(host, {})[name.strip()] = val.strip()
            return
        jar = self._jar.setdefault(host, {})
        for name, morsel in parsed.items():
            jar[name] = morsel.value

    async def on_request(self, flow: Flow) -> HttpRequest | None:
        if not self._settings.get("inject"):
            return None
        req = flow.request
        extra = self.cookie_header(req.host)
        if not extra:
            return None
        existing = req.header("Cookie") or ""
        names = {p.split("=", 1)[0].strip() for p in existing.split(";") if "=" in p}
        add = []
        for pair in extra.split("; "):
            name = pair.split("=", 1)[0]
            if name not in names:
                add.append(pair)
        if not add:
            return None
        merged = "; ".join([p for p in [existing] + add if p])
        req.set_header("Cookie", merged)
        return req

    async def on_response(self, flow: Flow):
        resp = flow.response
        if not resp:
            return None
        if self._settings.get("update"):
            for k, v in resp.headers:
                if k.lower() == "set-cookie":
                    self._ingest(flow.request.host, v)
        if (self._settings.get("retry_on_401") and resp.status_code == 401
                and self._settings.get("login_raw") and self._send_raw
                and not self._retrying):
            self._retrying = True
            try:
                await self._send_raw(
                    self._settings["login_raw"],
                    self._settings.get("login_scheme") or "https")
            except Exception as exc:
                print(f"[session] login replay failed: {exc!r}")
            finally:
                self._retrying = False
        return None
