"""
Burp-style browser: an isolated Chromium already pointed at the proxy.

It never touches the operator's everyday Chrome profile or OS proxy settings.
First choice is Playwright's bundled Chromium; if that is not installed yet we
fall back to a system Chrome/Chromium/Edge launched with a private user-data-dir.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))
PROFILE_DIR = CONFIG_DIR / "chromium-profile"


def _system_browsers() -> list[Path]:
    home = Path.home()
    names = [
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
        home / "Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files\Chromium\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path("/usr/bin/google-chrome"),
        Path("/usr/bin/google-chrome-stable"),
        Path("/usr/bin/chromium"),
        Path("/usr/bin/chromium-browser"),
        Path("/snap/bin/chromium"),
    ]
    found = [p for p in names if p.exists()]
    for cmd in ("google-chrome", "google-chrome-stable", "chromium",
                "chromium-browser", "chrome"):
        which = shutil.which(cmd)
        if which:
            p = Path(which)
            if p not in found:
                found.append(p)
    return found


def _playwright_roots() -> list[Path]:
    roots: list[Path] = []
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env and env != "0":
        roots.append(Path(env))
    roots.append(Path.home() / "Library/Caches/ms-playwright")
    roots.append(Path.home() / ".cache/ms-playwright")
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(Path(local) / "ms-playwright")
    return roots


def _playwright_chromium() -> Path | None:
    patterns = (
        "chromium-*/chrome-mac-*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        "chromium-*/chrome-linux/chrome",
        "chromium-*/chrome-win64/chrome.exe",
        "chromium-*/chrome-win/chrome.exe",
    )
    for root in _playwright_roots():
        if not root.exists():
            continue
        for pat in patterns:
            hits = sorted(root.glob(pat))
            if hits:
                return hits[-1]
    return None


class EmbeddedBrowser:
    def __init__(self) -> None:
        self._proc: asyncio.subprocess.Process | None = None
        self._installing = False
        self._install_error = ""
        self._via = ""

    def _alive(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    def status(self) -> dict:
        exe = _playwright_chromium()
        return {
            "running": self._alive(),
            "ready": bool(exe or _system_browsers()),
            "has_chromium": bool(exe),
            "installing": self._installing,
            "install_error": self._install_error,
            "via": self._via if self._alive() else "",
        }

    async def ensure_chromium(self) -> Path | None:
        exe = _playwright_chromium()
        if exe:
            return exe
        if self._installing:
            return None
        self._installing = True
        self._install_error = ""
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "playwright", "install", "chromium",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out, _ = await proc.communicate()
            if proc.returncode != 0:
                self._install_error = (out or b"").decode("utf-8", "replace")[-400]
                return None
            return _playwright_chromium()
        except Exception as exc:
            self._install_error = repr(exc)
            return None
        finally:
            self._installing = False

    def _args(self, exe: Path, proxy_host: str, proxy_port: int) -> list[str]:
        PROFILE_DIR.mkdir(parents=True, exist_ok=True)
        return [
            str(exe),
            f"--user-data-dir={PROFILE_DIR}",
            f"--proxy-server=http://{proxy_host}:{proxy_port}",
            "--proxy-bypass-list=<-loopback>",
            "--ignore-certificate-errors",
            "--allow-insecure-localhost",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-sync",
            "--disable-features=HttpsFirstBalancedModeAutoEnable,HttpsUpgrades",
            "--disable-infobars",
            "about:blank",
        ]

    async def open(self, proxy_host: str, proxy_port: int) -> dict:
        if self._alive():
            return {**self.status(), "ok": True, "opened": False}

        exe = _playwright_chromium()
        via = "chromium"
        if not exe:
            sys_b = _system_browsers()
            if sys_b:
                exe = sys_b[0]
                via = "isolated-chrome"
            else:
                asyncio.create_task(self.ensure_chromium())
                return {
                    **self.status(),
                    "ok": False,
                    "installing": True,
                    "error": "Downloading Chromium. Click Open browser again in a minute.",
                }

        self._proc = await asyncio.create_subprocess_exec(
            *self._args(exe, proxy_host, proxy_port),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
        self._via = via
        return {**self.status(), "ok": True, "opened": True}

    def stop(self) -> None:
        if self._alive() and self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        self._proc = None
        self._via = ""
