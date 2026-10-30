"""Vulnerable-component detection: fingerprints, version maths, NVD matching.
All offline; advisory lookups are exercised with canned payloads."""

import asyncio
import gzip
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.http_message import HttpRequest, HttpResponse, Flow
from modules import components, sca
from modules.passive_scanner import PassiveScanner


def _flow(headers, body=b"", url="https://app.test/"):
    return Flow(request=HttpRequest("GET", url, [("Host", "app.test")]),
                response=HttpResponse(200, "OK", headers, body))


def _keys(hits):
    return {(h["key"], h["version"]) for h in hits}


# ---------------------------------------------------------- fingerprints

def test_server_header_with_several_products():
    hits = components.fingerprint(_flow([
        ("Server", "Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3"),
    ]))
    assert _keys(hits) == {("apache", "2.4.49"), ("openssl", "1.1.1k"), ("php", "7.4.3")}


def test_x_powered_by_php_with_distro_suffix_flags_backport():
    hits = components.fingerprint(_flow([("X-Powered-By", "PHP/8.1.2-1ubuntu2.14")]))
    assert _keys(hits) == {("php", "8.1.2")}
    assert hits[0]["backport"] is True


def test_versionless_express_is_recorded():
    hits = components.fingerprint(_flow([("X-Powered-By", "Express")]))
    assert _keys(hits) == {("express", "")}


def test_script_urls_and_banners():
    html = (b'<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>'
            b'<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js"></script>'
            b'<script src="/static/lodash-4.17.15.min.js"></script>'
            b'<meta name="generator" content="WordPress 6.2.1" />')
    hits = components.fingerprint(_flow([("Content-Type", "text/html")], html))
    assert {("jquery", "3.4.1"), ("bootstrap", "4.3.1"), ("lodash", "4.17.15"),
            ("wordpress", "6.2.1")} <= _keys(hits)


def test_gzipped_js_banner():
    body = gzip.compress(b"/*! jQuery v1.12.4 | (c) jQuery Foundation */ ...")
    hits = components.fingerprint(_flow(
        [("Content-Type", "application/javascript"), ("Content-Encoding", "gzip")], body))
    assert ("jquery", "1.12.4") in _keys(hits)


# --------------------------------------------------------------- versions

def test_version_ordering_handles_letter_suffix():
    assert components.vkey("1.1.1k") < components.vkey("1.1.1w")
    assert components.vkey("8.1.2") < components.vkey("8.1.31")
    assert components.vkey("v18.12.0") == components.vkey("18.12")


CYCLES = [
    {"cycle": "8.4", "eol": "2099-12-31", "latest": "8.4.27"},
    {"cycle": "8.1", "eol": "2025-12-31", "latest": "8.1.33"},
    {"cycle": "8.0", "eol": "2023-11-26", "latest": "8.0.30"},
]


def test_lifecycle_eol_and_latest():
    life = components.lifecycle(CYCLES, "8.1.2")
    assert life["cycle"] == "8.1" and life["eol"] is True
    assert life["outdated"] is True and life["latest"] == "8.1.33"
    assert life["supported_cycle"] == "8.4"
    assert components.lifecycle(CYCLES, "8.4.27")["outdated"] is False
    # Bare major/minor is a moving tag: EOL matters, "outdated" doesn't.
    assert components.lifecycle(CYCLES, "8.4")["outdated"] is False


# --------------------------------------------------------------- NVD

def _nvd_item(cve, match, score=9.8):
    return {"cve": {
        "id": cve,
        "descriptions": [{"lang": "en", "value": "bad thing"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score,
                    "vectorString": "CVSS:3.1/AV:N"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [match]}]}],
    }}


def test_nvd_rows_respects_ranges_and_vulnerable_flag():
    payload = {"vulnerabilities": [
        _nvd_item("CVE-1", {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.3"}),
        _nvd_item("CVE-2", {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "8.1.0"}),
        # PHP is only the platform here, not the vulnerable thing.
        _nvd_item("CVE-3", {"vulnerable": False, "criteria": "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*"}),
        _nvd_item("CVE-4", {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*"}),
    ]}
    rows = components.nvd_rows(payload, "php:php", "8.1.2")
    assert [r["id"] for r in rows] == ["CVE-1", "CVE-4"]
    assert rows[0]["severity"] == "critical"


def test_summarize_gives_upgrade_advice():
    res = components.summarize({
        "key": "php", "label": "PHP", "version": "8.1.2",
        "lifecycle": components.lifecycle(CYCLES, "8.1.2"),
        "cves": [{"id": "CVE-1", "cvss": 9.8, "summary": "x"}],
    })
    assert res["status"] == "vulnerable" and res["severity"] == "critical"
    assert "end of life" in res["title"]
    assert "8.4" in res["fix"]


# --------------------------------------------------------- integration

def test_passive_scanner_turns_assessment_into_finding(monkeypatch):
    async def fake_assess(key, version, *, backport=False):
        return components.summarize({
            "key": key, "label": "PHP", "version": version,
            "lifecycle": components.lifecycle(CYCLES, version),
            "cves": [{"id": "CVE-2024-4577", "cvss": 9.8, "summary": "CGI arg injection"}],
        }, backport=backport)

    monkeypatch.setattr(components, "assess", fake_assess)
    scanner = PassiveScanner(checks=[])

    async def go():
        await scanner.on_flow_complete(_flow([("X-Powered-By", "PHP/8.1.2")]))
        await scanner.components.wait()

    asyncio.run(go())
    rep = scanner.report()
    assert len(rep) == 1
    assert rep[0]["check"] == "vulnerable-component"
    assert rep[0]["cve"] == "CVE-2024-4577" and rep[0]["cvss"] == 9.8
    inv = scanner.components.public()
    assert inv[0]["status"] == "vulnerable" and inv[0]["hosts"] == ["app.test"]


def test_offline_mode_skips_lookups(monkeypatch):
    monkeypatch.setenv("KERF_OFFLINE", "1")
    scanner = PassiveScanner(checks=[])
    asyncio.run(scanner.on_flow_complete(_flow([("Server", "nginx/1.18.0")])))
    assert scanner.components.public()[0]["status"] == "offline"


# ------------------------------------------------------------ repo files

def test_runtime_hints_from_repo_files():
    docker = "FROM node:16.20.0-alpine AS build\nFROM php:7.4-fpm\nFROM nginx:latest\n"
    hits = components.runtime_hints("api/Dockerfile", docker)
    assert _keys(hits) == {("nodejs", "16.20.0"), ("php", "7.4")}
    assert components.runtime_hints(".nvmrc", "v14.17.0\n")[0]["version"] == "14.17.0"
    pkg = '{"engines": {"node": "^16.0.0"}}'
    assert components.runtime_hints("package.json", pkg)[0]["version"] == "16.0.0"
    # Open-ended constraints say nothing about what actually runs.
    assert components.runtime_hints("package.json", '{"engines": {"node": ">=14"}}') == []
    comp = '{"require": {"php": "^7.2|^8.0"}}'
    assert components.runtime_hints("composer.json", comp)[0]["version"] == "8.0"


def test_composer_lock_parses_packagist():
    text = ('{"content-hash": "x", "packages": [{"name": "laravel/framework", "version": "v8.0.0"}],'
            ' "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}')
    rows = sca.parse_any("composer.lock", text)
    assert rows[0] == {"ecosystem": "Packagist", "name": "laravel/framework", "version": "8.0.0"}
    assert rows[1]["dev"] is True
