"""Isolated Chromium launcher helpers."""

from pathlib import Path

from modules import browser as br


def test_proxy_target_rewrites_wildcard_bind():
    assert br._proxy_target("0.0.0.0") == "127.0.0.1"
    assert br._proxy_target("::") == "127.0.0.1"
    assert br._proxy_target("127.0.0.1") == "127.0.0.1"
    assert br._proxy_target("192.168.1.10") == "192.168.1.10"


def test_view_url_empty_outside_container(monkeypatch):
    monkeypatch.delenv("KERF_DOCKER", raising=False)
    assert br._view_url() == ""


def test_view_url_uses_browser_port(monkeypatch):
    monkeypatch.setenv("KERF_DOCKER", "1")
    monkeypatch.delenv("KERF_BROWSER_VIEW", raising=False)
    monkeypatch.setenv("KERF_BROWSER_PORT", "6081")
    assert br._view_url() == "http://127.0.0.1:6081/vnc.html?autoconnect=1&resize=scale"


def test_playwright_finds_linux_arm64(monkeypatch, tmp_path):
    root = tmp_path / "ms-playwright" / "chromium-1248" / "chrome-linux-arm64"
    root.mkdir(parents=True)
    exe = root / "chrome"
    exe.write_text("")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "ms-playwright"))
    assert br._playwright_chromium() == exe


def test_container_args_use_loopback_and_no_sandbox(monkeypatch, tmp_path):
    monkeypatch.setenv("KERF_DOCKER", "1")
    monkeypatch.setattr(br, "PROFILE_DIR", tmp_path / "profile")
    args = br.EmbeddedBrowser()._args(Path("/ms-playwright/chrome"), "0.0.0.0", 8080)
    assert "--no-sandbox" in args
    assert "--disable-dev-shm-usage" in args
    assert "--proxy-server=http://127.0.0.1:8080" in args
    assert "about:blank" in args
