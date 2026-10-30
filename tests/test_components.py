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
    async def fake_assess(key, version, *, backport=False, **_):
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


# ------------------------------------------------------------- CISA KEV

KEV_CAT = {"CVE-2024-4577": {"name": "PHP-CGI OS Command Injection", "date_added": "2024-06-12",
                             "due": "2024-07-03", "ransomware": True, "action": ""}}


def test_tag_kev_matches_any_cve_alias():
    rows = [{"id": "GHSA-xxxx-yyyy-zzzz", "cves": ["CVE-2024-4577"]},
            {"id": "CVE-2020-0001"}]
    sca.tag_kev(rows, KEV_CAT)
    assert rows[0]["kev"]["ransomware"] is True and "CISA KEV" in rows[0]["sources"]
    assert "kev" not in rows[1]


def test_kev_sorts_ahead_of_higher_cvss():
    from modules import cvss as cvsslib
    rows = [{"id": "CVE-A", "cvss": 9.8}, {"id": "CVE-B", "cvss": 6.1, "kev": {"name": "x"}}]
    rows.sort(key=cvsslib.sort_key)
    assert rows[0]["id"] == "CVE-B"


def test_summarize_flags_exploited_cves_and_raises_severity():
    cves = [{"id": "CVE-2024-4577", "cvss": 5.0, "kev": KEV_CAT["CVE-2024-4577"]}]
    res = components.summarize({"key": "php", "label": "PHP", "version": "8.4.1",
                                "lifecycle": {}, "cves": cves})
    assert res["severity"] == "high"  # medium CVSS, but exploited in the wild
    assert res["kev_count"] == 1 and "actively exploited (CISA KEV)" in res["title"]
    assert res["fix"].startswith("Patch first: CVE-2024-4577")
    assert "ransomware" in res["fix"]
    assert "[CISA KEV: exploited, ransomware]" in components.finding_detail(res)



# ------------------------------------------------------------ lockfiles

def test_yarn_v1_and_berry_lockfiles():
    v1 = ('"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":\n'
          '  version "7.12.13"\n  dependencies:\n    "@babel/highlight" "^7.12.13"\n\n'
          'lodash@^4.17.15:\n  version "4.17.15"\n')
    rows = sca.parse_any("yarn.lock", v1)
    assert [(r["name"], r["version"]) for r in rows] == [
        ("@babel/code-frame", "7.12.13"), ("lodash", "4.17.15")]
    berry = ('__metadata:\n  version: 6\n\n"lodash@npm:^4.17.15":\n  version: 4.17.15\n\n'
             '"app@workspace:.":\n  version: 0.0.0-use.local\n')
    assert [(r["name"], r["version"]) for r in sca.parse_any("yarn.lock", berry)] == [
        ("lodash", "4.17.15")]


def test_pnpm_lockfile_versions_5_6_and_9():
    v5 = "lockfileVersion: 5.4\npackages:\n  /@babel/core/7.0.0_supports-color@5.5.0:\n    dev: true\n"
    v6 = "lockfileVersion: '6.0'\npackages:\n  /@babel/core@7.0.0(supports-color@5.5.0):\n    dev: false\n"
    v9 = "lockfileVersion: '9.0'\npackages:\n  '@babel/core@7.0.0':\n    resolution: {integrity: x}\n"
    for text in (v5, v6, v9):
        rows = sca.parse_any("pnpm-lock.yaml", text)
        assert [(r["name"], r["version"]) for r in rows] == [("@babel/core", "7.0.0")]
    assert sca.parse_any("pnpm-lock.yaml", v5)[0]["dev"] is True


# --------------------------------------------------------------- distro

def test_distro_package_detection():
    assert components.distro_package("php", "8.1.2-1ubuntu2.14") == {
        "ecosystem": "Ubuntu", "package": "php8.1", "version": "8.1.2-1ubuntu2.14"}
    assert components.distro_package("php", "7.4.33-1+deb11u5")["ecosystem"] == "Debian"
    assert components.distro_package("nginx", "1.22.1-9+deb12u1")["package"] == "nginx"
    # Upstream builds and third-party PPAs aren't in the distro trackers.
    assert components.distro_package("php", "8.1.2") is None
    assert components.distro_package("php", "8.2.7-1+ubuntu22.04.1+deb.sury.org+1") is None


def test_fingerprint_keeps_full_distro_build():
    hits = components.fingerprint(_flow([("X-Powered-By", "PHP/8.1.2-1ubuntu2.14")]))
    assert hits[0]["version"] == "8.1.2"
    assert hits[0]["distro"]["version"] == "8.1.2-1ubuntu2.14"


def test_distro_build_is_not_escalated_for_upstream_eol():
    res = components.summarize({
        "key": "php", "label": "PHP", "version": "8.1.2",
        "distro": {"ecosystem": "Ubuntu", "package": "php8.1", "version": "8.1.2-1ubuntu2.14"},
        "lifecycle": components.lifecycle(CYCLES, "8.1.2"),
        "cves": [{"id": "CVE-2024-0001", "cvss": 5.3}],
    })
    assert res["severity"] == "medium"
    assert "Ubuntu's tracker" in res["title"] and "8.1.2-1ubuntu2.14" in res["title"]
    assert "apt-get install --only-upgrade 'php8.1*'" in res["fix"]
    assert "backports" not in res["fix"]


# ----------------------------------------------------------------- EPSS

def test_epss_tags_and_ranks_ahead_of_cvss():
    from modules import cvss as cvsslib
    rows = [{"id": "CVE-2022-0001", "cvss": 9.8}, {"id": "CVE-2020-11022", "cvss": 6.1}]
    sca.tag_epss(rows, {"CVE-2020-11022": {"epss": 0.92, "percentile": 0.99}})
    assert rows[1]["epss"] == 0.92 and "epss" not in rows[0]
    rows.sort(key=cvsslib.sort_key)
    assert rows[0]["id"] == "CVE-2020-11022"
    res = components.summarize({"key": "jquery", "label": "jQuery", "version": "3.4.1",
                                "lifecycle": {}, "cves": rows})
    assert res["likely_count"] == 1 and "EPSS" in res["title"]
    assert "[EPSS 92%]" in components.finding_detail(res)


# ------------------------------------------------- inventory + alerts

def _res(version, cves, kev=()):
    return components.summarize({
        "key": "php", "label": "PHP", "version": version, "lifecycle": {},
        "cves": [{"id": c, "cvss": 7.5, **({"kev": {"name": "x"}} if c in kev else {})}
                 for c in cves]})


def test_inventory_persists_and_alerts_on_new_kev(tmp_path, monkeypatch):
    calls = {"n": 0}

    async def fake_assess(key, version, **_):
        calls["n"] += 1
        if calls["n"] == 1:
            return _res(version, ["CVE-1"])
        return _res(version, ["CVE-1", "CVE-2"], kev={"CVE-1"})

    monkeypatch.setattr(components, "assess", fake_assess)
    path = tmp_path / "components.json"
    scanner = PassiveScanner(checks=[], inventory_path=path)

    async def go():
        await scanner.on_flow_complete(_flow([("X-Powered-By", "PHP/8.1.2")]))
        await scanner.components.wait()
        assert len(scanner.report()) == 1
        await scanner.components.recheck()

    asyncio.run(go())
    inv = scanner.components
    assert len(inv.alerts) == 1
    alert = inv.alerts[0]
    assert alert["new_kev"] == ["CVE-1"] and alert["new_cves"] == ["CVE-2"]
    assert alert["severity"] == "critical" and alert["hosts"] == ["app.test"]
    # The re-check replaced the finding instead of adding a second one.
    rep = scanner.report()
    assert len(rep) == 1 and rep[0]["kev"]
    # A fresh process sees the same inventory and alerts.
    again = components.ComponentInventory(path=path, lookups=False)
    assert list(again.items) == list(inv.items) and len(again.alerts) == 1
    assert again.last_check > 0


def test_recheck_clears_finding_when_fixed(monkeypatch):
    results = iter([_res("8.1.2", ["CVE-1"]), _res("8.1.2", [])])

    async def fake_assess(key, version, **_):
        return next(results)

    monkeypatch.setattr(components, "assess", fake_assess)
    scanner = PassiveScanner(checks=[])

    async def go():
        await scanner.on_flow_complete(_flow([("X-Powered-By", "PHP/8.1.2")]))
        await scanner.components.wait()
        assert len(scanner.report()) == 1
        await scanner.components.recheck()

    asyncio.run(go())
    assert scanner.report() == []


# --------------------------------------------------------------- report

def test_report_includes_component_patch_list(monkeypatch):
    from modules import reporting
    from modules.history import HistoryStore

    async def fake_assess(key, version, **_):
        return _res(version, ["CVE-2024-4577"], kev={"CVE-2024-4577"})

    monkeypatch.setattr(components, "assess", fake_assess)
    scanner = PassiveScanner(checks=[])

    async def go():
        await scanner.on_flow_complete(_flow([("X-Powered-By", "PHP/8.1.2")]))
        await scanner.components.wait()

    asyncio.run(go())

    class _Active:
        scope_hosts = set()
        def report(self):
            return []

    class _Ix:
        scope_hosts = set()

    data = reporting.build_report(history=HistoryStore(":memory:"), passive=scanner,
                                  active=_Active(), interceptor=_Ix())
    assert data["totals"]["components_to_patch"] == 1
    assert data["components"][0]["label"] == "PHP"
    html = reporting.render_html(data)
    assert "Components to patch" in html and "EXPLOITED" in html


def test_distro_osv_records_map_to_upstream_cve():
    row = sca._osv_row({"ecosystem": "Ubuntu", "name": "php8.1", "version": "8.1.2-1ubuntu2.14"},
                       {"id": "UBUNTU-CVE-2022-31628", "upstream": ["CVE-2022-31628"]})
    assert row["cve"] == "CVE-2022-31628"
    row = sca._osv_row({"ecosystem": "Debian", "name": "php8.2", "version": "8.2.7-1~deb12u1"},
                       {"id": "DEBIAN-CVE-2023-3823"})
    assert row["cve"] == "CVE-2023-3823"
