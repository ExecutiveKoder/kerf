"""Unit tests for the non-network modules and the proxy's parsing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.http_message import HttpRequest, HttpResponse, Flow
from modules import decoder, comparer, sequencer
from modules.history import HistoryStore
from modules.passive_scanner import (
    PassiveScanner, SecurityHeadersCheck, CookieFlagsCheck, InfoDisclosureCheck,
)
from modules.repeater import Repeater
from modules.active_scan import ActiveScanEngine, discover_insertion_points


# ------------------------------------------------------------- http model

def test_request_roundtrip_headers():
    r = HttpRequest("GET", "https://x.test/a?b=1", [("Host", "x.test")])
    assert r.host == "x.test"
    assert r.header("host") == "x.test"
    assert r.query_params == [("b", "1")]
    assert b"GET /a?b=1 HTTP/1.1" in r.raw()


def test_response_content_type():
    resp = HttpResponse(200, "OK", [("Content-Type", "text/html; charset=utf-8")])
    assert resp.content_type == "text/html"


# --------------------------------------------------------------- decoder

def test_decoder_base64_roundtrip():
    assert decoder.apply("base64-decode", decoder.apply("base64-encode", "hello")) == "hello"

def test_decoder_url():
    assert decoder.apply("url-encode", "a b&c") == "a%20b%26c"
    assert decoder.apply("url-decode", "a%20b%26c") == "a b&c"

def test_decoder_sha256_known():
    assert decoder.apply("sha256", "abc").startswith("ba7816bf")

def test_smart_decode():
    out = decoder.smart_decode("YWJj")  # 'abc'
    assert out.get("base64-decode") == "abc"


# -------------------------------------------------------------- comparer

def test_comparer_identical():
    s = comparer.stats("same text", "same text")
    assert s["identical"] and s["ratio"] == 1.0

def test_comparer_word_diff():
    d = comparer.word_diff("the quick fox", "the slow fox")
    ops = {seg["op"] for seg in d}
    assert "delete" in ops and "insert" in ops


# ------------------------------------------------------------- sequencer

def test_sequencer_detects_low_entropy():
    weak = ["AAAA0001", "AAAA0002", "AAAA0003", "AAAA0004"]
    res = sequencer.analyze(weak)
    assert res["verdict"] == "weak"
    # First 4 positions are fixed → zero entropy.
    assert res["position_entropy"][0] == 0.0

def test_sequencer_strong():
    import secrets
    strong = [secrets.token_hex(32) for _ in range(50)]
    res = sequencer.analyze(strong)
    assert res["verdict"] in ("strong", "moderate")


# --------------------------------------------------------------- history

def test_history_record_and_query():
    h = HistoryStore(":memory:")
    req = HttpRequest("GET", "https://a.test/x", [("Host", "a.test")])
    resp = HttpResponse(200, "OK", [("Content-Type", "text/html")], b"hi")
    h.record(Flow(request=req, response=resp))
    rows = h.list()
    assert len(rows) == 1 and rows[0]["host"] == "a.test"
    assert h.list(host="a.test") and not h.list(host="zzz")


# -------------------------------------------------------- passive scanner

def _flow(headers, body=b"", url="https://t.test/", status=200):
    req = HttpRequest("GET", url, [("Host", "t.test")])
    resp = HttpResponse(status, "OK", headers, body)
    return Flow(request=req, response=resp)

def test_security_headers_flags_missing():
    f = _flow([("Content-Type", "text/html")])
    findings = SecurityHeadersCheck().run(f)
    titles = {x.title for x in findings}
    assert "HSTS header missing" in titles
    assert "Content-Security-Policy missing" in titles

def test_cookie_flags():
    f = _flow([("Content-Type","text/html"), ("Set-Cookie","sid=1; Path=/")])
    findings = CookieFlagsCheck().run(f)
    titles = {x.title for x in findings}
    assert "Cookie without HttpOnly" in titles
    assert "Cookie without Secure" in titles

def test_info_disclosure_header_and_body():
    f = _flow([("Content-Type","text/html"), ("Server","nginx/1.1")],
              body=b"You have an error in your SQL syntax near")
    findings = InfoDisclosureCheck().run(f)
    titles = {x.title for x in findings}
    assert any("disclosed" in t for t in titles)
    assert "Database error in response" in titles


# ----------------------------------------------------------- active scan

def test_active_scan_refuses_without_authorization():
    import asyncio
    eng = ActiveScanEngine(send_coro=None, authorized=False)
    f = _flow([("Content-Type","text/html")])
    try:
        asyncio.run(eng.scan_flow(f))
        assert False, "should have refused"
    except PermissionError:
        pass

def test_active_scan_no_bundled_checks():
    eng = ActiveScanEngine(send_coro=None)
    eng.authorize_scope({"t.test"})
    assert eng._checks == []  # ships empty by design

def test_insertion_point_discovery_is_inert():
    req = HttpRequest("GET", "https://t.test/s?q=1&p=2", [("Host","t.test")])
    pts = discover_insertion_points(req)
    names = {p.name for p in pts}
    assert names == {"q", "p"}


# --------------------------------------------------------------- repeater

def test_repeater_parse_raw():
    raw = "POST /login HTTP/1.1\nHost: t.test\nContent-Type: text/plain\n\nbody"
    req = Repeater.parse_raw(raw)
    assert req.method == "POST"
    assert req.url == "https://t.test/login"
    assert req.body == b"body"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
