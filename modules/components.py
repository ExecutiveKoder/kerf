"""
Vulnerable component detection.

Spots server software and front-end libraries by version, then asks public
advisory sources whether that version has known vulnerabilities or is end of
life, so the owner knows what to patch:

  * fingerprints  — headers (Server, X-Powered-By), HTML generator tags,
                    script URLs and JS banners. Pure parsing of traffic that
                    already happened; nothing is sent to the target.
  * endoflife.date — is the release branch still supported, and what is the
                    latest patch in it.
  * NVD (by CPE)  — CVEs for runtimes and servers (PHP, Node.js, nginx…).
  * OSV           — CVEs for npm / Packagist packages (jQuery, Express…).
  * OSV distro    — for Ubuntu / Debian builds (PHP/8.1.2-1ubuntu2.14), the
                    distro's own tracker, which knows about backported fixes.
  * CISA KEV      — which of those CVEs are being exploited in the wild.
  * FIRST EPSS    — how likely each CVE is to be exploited in the next 30 days.

Only the product name and version leave the machine. Never the host or URL.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import re
import time
import zlib
from pathlib import Path

import httpx

from modules import cvss as cvsslib
from modules import sca

EOL_API = "https://endoflife.date/api"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# key → label, endoflife.date slug, NVD CPE vendor:product list, OSV package.
PRODUCTS: dict[str, dict] = {
    "php": {"label": "PHP", "eol": "php", "cpe": ["php:php"]},
    "nodejs": {"label": "Node.js", "eol": "nodejs", "cpe": ["nodejs:node.js"]},
    "nginx": {"label": "nginx", "eol": "nginx", "cpe": ["f5:nginx", "nginx:nginx"]},
    "apache": {"label": "Apache httpd", "eol": "apache-http-server",
               "cpe": ["apache:http_server"]},
    "openssl": {"label": "OpenSSL", "eol": "openssl", "cpe": ["openssl:openssl"]},
    "tomcat": {"label": "Apache Tomcat", "eol": "tomcat", "cpe": ["apache:tomcat"]},
    "wordpress": {"label": "WordPress", "eol": "wordpress",
                  "cpe": ["wordpress:wordpress"]},
    "drupal": {"label": "Drupal", "eol": "drupal", "osv": ("Packagist", "drupal/core")},
    "express": {"label": "Express", "eol": "express", "osv": ("npm", "express")},
    "next": {"label": "Next.js", "eol": "nextjs", "osv": ("npm", "next")},
    "jquery": {"label": "jQuery", "eol": "jquery", "osv": ("npm", "jquery")},
    "jquery-ui": {"label": "jQuery UI", "osv": ("npm", "jquery-ui")},
    "bootstrap": {"label": "Bootstrap", "eol": "bootstrap", "osv": ("npm", "bootstrap")},
    "angularjs": {"label": "AngularJS", "eol": "angularjs", "osv": ("npm", "angular")},
    "lodash": {"label": "Lodash", "osv": ("npm", "lodash")},
    "moment": {"label": "Moment.js", "osv": ("npm", "moment")},
}

# Product tokens as they appear in Server / X-Powered-By headers.
HEADER_TOKENS = {
    "php": "php", "apache": "apache", "nginx": "nginx", "openssl": "openssl",
    "node": "nodejs", "node.js": "nodejs", "nodejs": "nodejs",
    "express": "express", "next.js": "next", "wordpress": "wordpress",
}

# Names used in CDN paths (cdnjs, jsdelivr, unpkg) and file names.
LIB_NAMES = {
    "jquery": "jquery", "jqueryui": "jquery-ui", "jquery-ui": "jquery-ui",
    "bootstrap": "bootstrap", "twitter-bootstrap": "bootstrap",
    "angular.js": "angularjs", "angularjs": "angularjs", "angular": "angularjs",
    "lodash": "lodash", "lodash.js": "lodash", "moment": "moment",
    "moment.js": "moment",
}

VER = r"v?(\d+(?:\.\d+){1,3}[a-z]?)"
HEADER_PAT = re.compile(r"([A-Za-z][\w.\-]*)(?:/|\s+)" + VER + r"\b")
DISTRO_PAT = re.compile(
    r"(?i)ubuntu|debian|centos|red ?hat|rhel|\bel[6-9]\b|amzn|\+deb\d+|fedora|suse")

LIB_PATS = [
    # cdnjs: /ajax/libs/jquery/3.4.1/…   jsdelivr/unpkg: jquery@3.4.1
    re.compile(rb"/ajax/libs/([\w.\-]+)/" + VER.encode() + rb"/", re.I),
    re.compile(rb"/(?:npm/)?((?:@[\w.\-]+/)?[\w.\-]+)@" + VER.encode() + rb"[/\"']", re.I),
    # jquery-3.4.1.min.js, bootstrap.4.3.1.js
    re.compile(rb"/(jquery(?:-ui)?|bootstrap|angular|lodash|moment)[-.]"
               + VER.encode() + rb"(?:\.slim)?(?:\.min)?\.js", re.I),
]
BANNERS = [
    ("jquery", re.compile(rb"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)")),
    ("jquery-ui", re.compile(rb"jQuery UI - v(\d+\.\d+\.\d+)")),
    ("bootstrap", re.compile(rb"Bootstrap v(\d+\.\d+\.\d+)")),
    ("angularjs", re.compile(rb"AngularJS v(\d+\.\d+\.\d+)")),
    ("moment", re.compile(rb"//! version : (\d+\.\d+\.\d+)")),
    ("tomcat", re.compile(rb"Apache Tomcat/(\d+\.\d+\.\d+)")),
]
LODASH_PAT = re.compile(rb"var VERSION = '(\d+\.\d+\.\d+)'")
GENERATOR_PAT = re.compile(
    rb"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.I)

MAX_SCAN = 512_000

# Debian/Ubuntu source package per product. PHP is versioned: php8.1.
DISTRO_PKG = {"nginx": "nginx", "apache": "apache2", "openssl": "openssl",
              "nodejs": "nodejs"}


# ------------------------------------------------------------- versions


def vkey(version: str) -> tuple:
    """Comparable key: '1.1.1k' → ((1,''),(1,''),(1,'k'))."""
    out = []
    for part in re.split(r"[.\-+]", (version or "").lstrip("vV")):
        m = re.match(r"(\d+)([a-z]*)", part)
        if not m:
            break
        out.append((int(m.group(1)), m.group(2)))
    while len(out) < 4:
        out.append((0, ""))
    return tuple(out)


def clean_version(raw: str) -> str:
    m = re.match(r"v?(\d+(?:\.\d+)*[a-z]?)", (raw or "").strip())
    return m.group(1) if m else ""


def _parts(version: str) -> int:
    return len(version.split("."))


# ---------------------------------------------------------- fingerprints


def _body(resp) -> bytes:
    body = (resp.body or b"")[:MAX_SCAN * 4]
    enc = (resp.header("content-encoding") or "").lower()
    try:
        if "gzip" in enc or "deflate" in enc:
            d = zlib.decompressobj(zlib.MAX_WBITS | 32)
            body = d.decompress(body, MAX_SCAN)
        elif "br" in enc:
            import brotli  # optional
            body = brotli.decompress(body)
    except Exception:
        return b""
    return body[:MAX_SCAN]


def _hit(key: str, version: str, evidence: str, backport: bool = False) -> dict:
    return {"key": key, "version": version, "evidence": evidence[:160],
            "backport": backport, "distro": None}


def distro_package(key: str, raw: str) -> dict | None:
    """Ubuntu/Debian package for a full build string such as
    '8.1.2-1ubuntu2.14' or '8.2.7-1~deb12u1'. None for upstream or PPA builds,
    which the distro trackers don't cover."""
    low = raw.lower()
    if "-" not in raw or "sury" in low:
        return None
    if "ubuntu" in low:
        eco = "Ubuntu"
    elif re.search(r"[~+]deb\d+u\d+|\+deb\d+", low):
        eco = "Debian"
    else:
        return None
    if key == "php":
        m = re.match(r"(\d+)\.(\d+)", raw)
        if not m:
            return None
        pkg = f"php{m.group(1)}.{m.group(2)}"
    else:
        pkg = DISTRO_PKG.get(key)
    if not pkg:
        return None
    return {"ecosystem": eco, "package": pkg, "version": raw}


def from_headers(headers) -> list[dict]:
    out = []
    for name, value in headers:
        low = name.lower()
        if low not in ("server", "x-powered-by", "x-generator"):
            continue
        backport = bool(DISTRO_PAT.search(value))
        found = set()
        for m in HEADER_PAT.finditer(value):
            key = HEADER_TOKENS.get(m.group(1).lower())
            if key:
                found.add(key)
                hit = _hit(key, m.group(2), f"{name}: {value}", backport)
                raw = re.match(r"[^\s(),;]+", value[m.start(2):]).group(0)
                hit["distro"] = distro_package(key, raw)
                out.append(hit)
        # Versionless tokens, e.g. "X-Powered-By: Express".
        for tok in re.split(r"[\s,;/]+", value):
            key = HEADER_TOKENS.get(tok.lower())
            if key and key not in found:
                found.add(key)
                out.append(_hit(key, "", f"{name}: {value}"))
    return out


def from_body(body: bytes, content_type: str) -> list[dict]:
    out = []
    if not body:
        return out
    if "html" in content_type:
        for m in GENERATOR_PAT.finditer(body):
            gen = m.group(1).decode("latin-1")
            g = re.match(r"(WordPress|Drupal)\s+" + VER, gen, re.I)
            if g:
                out.append(_hit(g.group(1).lower(), g.group(2), f"generator: {gen}"))
    if "html" in content_type or "javascript" in content_type:
        for pat in LIB_PATS:
            for m in pat.finditer(body):
                key = LIB_NAMES.get(m.group(1).decode("latin-1").lower())
                if key:
                    out.append(_hit(key, m.group(2).decode(), m.group(0).decode("latin-1")))
    for key, pat in BANNERS:
        m = pat.search(body)
        if m:
            out.append(_hit(key, m.group(1).decode(), m.group(0).decode("latin-1")))
    if b"lodash" in body[:4000].lower():
        m = LODASH_PAT.search(body)
        if m:
            out.append(_hit("lodash", m.group(1).decode(), m.group(0).decode()))
    return out


def fingerprint(flow) -> list[dict]:
    resp = flow.response
    if not resp:
        return []
    hits = from_headers(resp.headers)
    hits += from_body(_body(resp), resp.content_type or "")
    seen, out = set(), []
    for h in hits:
        h["version"] = clean_version(h["version"])
        k = (h["key"], h["version"], (h["distro"] or {}).get("version", ""))
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out


# ------------------------------------------------- repo / file hints


DOCKER_FROM = re.compile(
    r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/)?(?:library/)?"
    r"(php|node|nginx|httpd|tomcat|wordpress|drupal)(?::([\w.\-]+))?")
DOCKER_KEYS = {"node": "nodejs", "httpd": "apache"}


def _constraint_floor(spec: str) -> str:
    """Highest floor in a version constraint, or '' when it is open-ended
    (e.g. '>=14'), since then the running version can be anything newer."""
    best = ""
    for alt in re.split(r"\|\|?", spec or ""):
        alt = alt.strip()
        if not alt or alt in ("*", "x"):
            return ""
        if alt.startswith(">") and "<" not in alt:
            return ""
        m = re.search(r"(\d+(?:\.\d+)*)", alt)
        if m and (not best or vkey(m.group(1)) > vkey(best)):
            best = m.group(1)
    return best


def runtime_hints(path: str, text: str) -> list[dict]:
    """Runtime versions a repo pins: Dockerfile FROM, .nvmrc, engines, composer."""
    name = Path(path).name.lower()
    out = []
    if name == "dockerfile" or name.endswith(".dockerfile"):
        for m in DOCKER_FROM.finditer(text):
            ver = clean_version(m.group(2) or "")
            if ver:
                key = DOCKER_KEYS.get(m.group(1).lower(), m.group(1).lower())
                line = text.count("\n", 0, m.start()) + 1
                out.append({**_hit(key, ver, m.group(0).strip()), "path": path, "line": line})
    elif name in (".nvmrc", ".node-version"):
        ver = clean_version(text.strip().splitlines()[0] if text.strip() else "")
        if ver:
            out.append({**_hit("nodejs", ver, text.strip()[:40]), "path": path, "line": 1})
    elif name in ("package.json", "composer.json"):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return out
        if name == "package.json":
            spec = ((data.get("engines") or {}).get("node") or "")
            key, label = "nodejs", "engines.node"
        else:
            spec = ((data.get("require") or {}).get("php") or "")
            key, label = "php", "require.php"
        ver = _constraint_floor(str(spec))
        if ver:
            out.append({**_hit(key, ver, f'{label}: "{spec}"'), "path": path, "line": 0,
                        "declared": True})
    return out


# ------------------------------------------------------- advisory lookups


def _cache_file() -> Path:
    from modules.home import kerf_home
    home = kerf_home()
    return home / "component-cache.json"


class _Cache:
    TTL = 12 * 3600

    def __init__(self) -> None:
        self._data: dict | None = None

    def _load(self) -> dict:
        if self._data is None:
            try:
                self._data = json.loads(_cache_file().read_text())
            except Exception:
                self._data = {}
        return self._data

    def get(self, key: str):
        row = self._load().get(key)
        if row and time.time() - row.get("t", 0) < self.TTL:
            return row.get("v")
        return None

    def put(self, key: str, value) -> None:
        self._load()[key] = {"t": time.time(), "v": value}
        try:
            path = _cache_file()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self._data))
        except Exception:
            pass


_cache = _Cache()
_nvd_locks: dict = {}


def _nvd_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    if loop not in _nvd_locks:
        _nvd_locks.clear()
        _nvd_locks[loop] = asyncio.Lock()
    return _nvd_locks[loop]


def _past(date) -> bool:
    if date is True:
        return True
    if not date or date is False:
        return False
    try:
        return dt.date.fromisoformat(str(date)) <= dt.date.today()
    except ValueError:
        return False


def match_cycle(cycles: list[dict], version: str) -> dict | None:
    """Longest release cycle that prefixes the version: 8.1.2 → '8.1'."""
    best = None
    want = version.split(".")
    for c in cycles:
        cyc = str(c.get("cycle") or "").split(".")
        if cyc == want[:len(cyc)] and (best is None or len(cyc) > len(best[0])):
            best = (cyc, c)
    return best[1] if best else None


def lifecycle(cycles: list[dict], version: str) -> dict:
    c = match_cycle(cycles, version)
    supported = [x for x in cycles if not _past(x.get("eol"))]
    newest = supported[0] if supported else None
    if not c:
        return {}
    latest = str(c.get("latest") or "")
    eol = _past(c.get("eol"))
    out = {
        "cycle": str(c.get("cycle")),
        "eol": eol,
        "eol_date": c.get("eol") if isinstance(c.get("eol"), str) else "",
        "latest": latest,
        "outdated": bool(latest) and _parts(version) >= _parts(latest)
                    and vkey(version) < vkey(latest),
    }
    if newest:
        out["supported_cycle"] = str(newest.get("cycle"))
        out["supported_latest"] = str(newest.get("latest") or "")
    return out


async def _eol_cycles(client: httpx.AsyncClient, slug: str,
                      fresh: bool = False) -> list[dict]:
    hit = None if fresh else _cache.get("eol:" + slug)
    if hit is not None:
        return hit
    r = await client.get(f"{EOL_API}/{slug}.json")
    r.raise_for_status()
    data = r.json() if isinstance(r.json(), list) else []
    _cache.put("eol:" + slug, data)
    return data


def _affects(m: dict, cpe: str, version: str) -> bool:
    if not m.get("vulnerable"):
        return False
    parts = (m.get("criteria") or "").split(":")
    if len(parts) < 7 or ":".join(parts[3:5]) != cpe:
        return False
    if parts[6] not in ("*", "-"):
        return False  # pre-release specific (rc1, beta…)
    v = vkey(version)
    if parts[5] not in ("*", "-"):
        return vkey(parts[5]) == v
    lo_in, lo_ex = m.get("versionStartIncluding"), m.get("versionStartExcluding")
    hi_in, hi_ex = m.get("versionEndIncluding"), m.get("versionEndExcluding")
    if not any((lo_in, lo_ex, hi_in, hi_ex)):
        return False  # "every version" entries are too noisy to trust
    if lo_in and v < vkey(lo_in):
        return False
    if lo_ex and v <= vkey(lo_ex):
        return False
    if hi_in and v > vkey(hi_in):
        return False
    if hi_ex and v >= vkey(hi_ex):
        return False
    return True


def _walk_matches(nodes):
    for node in nodes or []:
        yield from node.get("cpeMatch") or []
        yield from _walk_matches(node.get("children"))


def nvd_rows(payload: dict, cpe: str, version: str) -> list[dict]:
    rows = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        hit = any(_affects(m, cpe, version)
                  for conf in cve.get("configurations") or []
                  for m in _walk_matches(conf.get("nodes")))
        if not hit:
            continue
        score, vector = None, ""
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            if metrics.get(key):
                data = metrics[key][0].get("cvssData") or {}
                score = cvsslib.parse_score(data.get("baseScore"))
                vector = str(data.get("vectorString") or "")
                break
        desc = next((d.get("value") for d in cve.get("descriptions") or []
                     if d.get("lang") == "en"), "")
        rows.append({"id": cve.get("id"), "cvss": score, "cvss_vector": vector,
                     "severity": cvsslib.bucket(score), "summary": desc[:300]})
    return rows


async def _nvd(client: httpx.AsyncClient, cpe: str, version: str,
               fresh: bool = False) -> list[dict]:
    ck = f"nvd:{cpe}:{version}"
    hit = None if fresh else _cache.get(ck)
    if hit is not None:
        return hit
    key = (os.environ.get("NVD_API_KEY") or "").strip()
    headers = {"User-Agent": "Kerf"}
    if key:
        headers["apiKey"] = key
    params = {"virtualMatchString": f"cpe:2.3:a:{cpe}:{version}",
              "resultsPerPage": 2000}
    # Public NVD allows ~5 requests / 30s without a key; space them out.
    async with _nvd_lock():
        r = await client.get(NVD, params=params, headers=headers)
        if r.status_code in (403, 429, 503):
            await asyncio.sleep(8)
            r = await client.get(NVD, params=params, headers=headers)
        if not key:
            await asyncio.sleep(6)
    r.raise_for_status()
    rows = nvd_rows(r.json(), cpe, version)
    _cache.put(ck, rows)
    return rows


async def _osv(ecosystem: str, name: str, version: str,
               fresh: bool = False) -> list[dict]:
    ck = f"osv:{ecosystem}:{name}:{version}"
    hit = None if fresh else _cache.get(ck)
    if hit is not None:
        return hit
    found = await sca.query_osv(
        [{"ecosystem": ecosystem, "name": name, "version": version}])
    rows = [{"id": f.get("cve") or f.get("id"), "cves": f.get("cves") or [],
             "cvss": f.get("cvss"), "cvss_vector": f.get("cvss_vector") or "",
             "severity": f.get("severity") or "unknown",
             "summary": (f.get("summary") or "")[:300]} for f in found]
    _cache.put(ck, rows)
    return rows


SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}


async def assess(key: str, version: str, *, backport: bool = False,
                 distro: dict | None = None, fresh: bool = False) -> dict:
    """Lifecycle + known CVEs for one product version.

    With `distro` (a Debian/Ubuntu build), CVEs come from that distro's
    tracker for the exact package revision instead of upstream ranges."""
    meta = PRODUCTS.get(key) or {}
    label = meta.get("label") or key
    out = {"key": key, "label": label, "version": version, "cves": [],
           "lifecycle": {}, "errors": [], "distro": distro}
    async with httpx.AsyncClient(timeout=40) as client:
        if meta.get("eol"):
            try:
                out["lifecycle"] = lifecycle(
                    await _eol_cycles(client, meta["eol"], fresh), version)
            except Exception as exc:
                out["errors"].append(f"endoflife.date: {exc}")
        rows: dict[str, dict] = {}
        if distro:
            try:
                for r in await _osv(distro["ecosystem"], distro["package"],
                                    distro["version"], fresh):
                    rows.setdefault(r["id"], r)
            except Exception as exc:
                out["errors"].append(f"OSV {distro['ecosystem']}: {exc}")
        # A bare major ("node:18") is a moving tag; only lifecycle applies.
        elif _parts(version) >= 2 or key == "wordpress":
            for cpe in meta.get("cpe") or []:
                try:
                    for r in await _nvd(client, cpe, version, fresh):
                        rows.setdefault(r["id"], r)
                except Exception as exc:
                    out["errors"].append(f"NVD: {exc}")
            if meta.get("osv"):
                try:
                    for r in await _osv(*meta["osv"], version, fresh):
                        rows.setdefault(r["id"], r)
                except Exception as exc:
                    out["errors"].append(f"OSV: {exc}")
        if rows:
            try:
                sca.tag_kev(list(rows.values()), await sca.kev_catalog(client))
            except Exception as exc:
                out["errors"].append(f"CISA KEV: {exc}")
            try:
                sca.tag_epss(list(rows.values()), await sca.epss_scores(
                    [c for r in rows.values() for c in [r["id"], *(r.get("cves") or [])]],
                    client))
            except Exception as exc:
                out["errors"].append(f"EPSS: {exc}")
        out["cves"] = sorted(rows.values(), key=cvsslib.sort_key)
    return summarize(out, backport=backport)


def summarize(res: dict, *, backport: bool = False) -> dict:
    """Severity, title and the concrete upgrade advice for an assessment."""
    label, version = res["label"], res["version"]
    life, cves = res.get("lifecycle") or {}, res.get("cves") or []
    distro = res.get("distro")
    if distro:
        # The distro patches its own package; upstream "latest" doesn't apply.
        life = {**life, "outdated": False}
        version = distro["version"]
    scores = [c["cvss"] for c in cves if c.get("cvss") is not None]
    top = max(scores) if scores else None
    kev = [c for c in cves if c.get("kev")]
    likely = [c for c in cves if not c.get("kev")
              and (c.get("epss") or 0) >= sca.EPSS_LIKELY]
    epss = max((c.get("epss") or 0 for c in cves), default=0) or None
    sev = cvsslib.bucket(top) if top is not None else ("medium" if cves else "")
    # Exploited in the wild, or no longer patched at all: never below high.
    # A distro may still patch a branch upstream has dropped, so EOL alone
    # doesn't escalate a distro build.
    eol_hard = life.get("eol") and not distro
    if (kev or eol_hard) and SEV_RANK.get(sev, 0) < SEV_RANK["high"]:
        sev = "high"
    if not sev and life.get("outdated"):
        sev = "low"

    bits = []
    if kev:
        bits.append(f"{len(kev)} actively exploited (CISA KEV)")
    if likely:
        bits.append(f"{len(likely)} likely to be exploited soon (EPSS ≥{sca.EPSS_LIKELY:.0%})")
    if cves:
        where = f" in {distro['ecosystem']}'s tracker" if distro else ""
        bits.append(f"{len(cves)} open CVE{'s' if len(cves) != 1 else ''}{where}"
                    + (f", worst CVSS {top:.1f}" if top is not None else ""))
    if eol_hard:
        bits.append(f"branch {life['cycle']} is end of life"
                    + (f" since {life['eol_date']}" if life.get("eol_date") else ""))
    elif life.get("outdated"):
        bits.append(f"behind the latest {life['cycle']}.x patch ({life['latest']})")

    fix = []
    if distro and cves:
        tool = "apt-get install --only-upgrade"
        fix.append(f"Update the {distro['ecosystem']} {distro['package']} packages "
                   f"(`{tool} '{distro['package']}*'`) and restart the service. "
                   "Some listed issues may not have a distro fix yet.")
        if life.get("eol"):
            fix.append(f"Upstream {label} {life['cycle']} is end of life, so fixes now "
                       f"depend on {distro['ecosystem']} support for this release; plan a "
                       f"move to {life.get('supported_cycle') or 'a supported branch'}.")
    elif life.get("eol") and life.get("supported_cycle"):
        fix.append(f"Upgrade to a supported {label} branch "
                   f"(e.g. {life['supported_cycle']} → {life['supported_latest']}).")
    elif life.get("latest") and (cves or life.get("outdated")):
        fix.append(f"Patch to {label} {life['latest']} (latest {life['cycle']}.x).")
    elif cves:
        fix.append(f"Upgrade {label} past the fixed versions listed in the advisories.")
    if kev:
        ids = ", ".join(c["id"] for c in kev[:3])
        ransom = any(c["kev"].get("ransomware") for c in kev)
        fix.insert(0, f"Patch first: {ids} {'is' if len(kev) == 1 else 'are'} "
                   "being exploited in the wild"
                   + (", including by ransomware groups." if ransom else "."))
    if backport and cves and not distro:
        fix.append("The banner names a Linux distro, which often backports fixes "
                   "without bumping the version. Confirm against the distro's "
                   "security tracker before treating these as open.")

    res.update({
        "severity": sev or "none",
        "max_cvss": top,
        "cve_count": len(cves),
        "kev_count": len(kev),
        "kev": kev[0]["kev"] if kev else None,
        "likely_count": len(likely),
        "max_epss": epss,
        "title": f"{label} {version}: " + "; ".join(bits) if bits else "",
        "fix": " ".join(fix),
        "backport": backport,
        "status": "vulnerable" if sev else "ok",
    })
    return res


def finding_detail(res: dict, limit: int = 5) -> str:
    lines = []
    if res.get("fix"):
        lines.append(res["fix"])
    for c in (res.get("cves") or [])[:limit]:
        score = f" ({c['cvss']:.1f})" if c.get("cvss") is not None else ""
        tag = ""
        if c.get("kev"):
            tag = " [CISA KEV: exploited" + (", ransomware" if c["kev"].get("ransomware") else "") + "]"
        elif (c.get("epss") or 0) >= sca.EPSS_LIKELY:
            tag = f" [EPSS {c['epss']:.0%}]"
        lines.append(f"• {c['id']}{score}{tag}: {c.get('summary') or ''}"[:260])
    extra = len(res.get("cves") or []) - limit
    if extra > 0:
        lines.append(f"…and {extra} more.")
    return "\n".join(lines)


# ------------------------------------------------------------- inventory


class ComponentInventory:
    """Everything fingerprinted from traffic, with its assessment.

    Saved to `path` (when given) so it survives restarts. `watch()` re-checks
    every component daily and records an alert when one picks up a new CVE or
    a new CISA KEV entry, since that is when something you already run becomes
    urgent.

    `on_result(item, host, url, flow_id)` is called for each host a component
    is seen on whenever its assessment changes."""

    INTERVAL = 24 * 3600
    MAX_ALERTS = 200

    def __init__(self, on_result=None, *, lookups: bool = True,
                 path: str | Path | None = None, events=None) -> None:
        self.items: dict[str, dict] = {}
        self.alerts: list[dict] = []
        self.last_check = 0.0
        self.on_result = on_result
        self.events = events
        self.path = Path(path) if path else None
        self.lookups = lookups and os.environ.get("KERF_OFFLINE") != "1"
        self._tasks: set[asyncio.Task] = set()
        self._load()

    # ---- persistence

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
        except Exception:
            return
        for item in data.get("items") or []:
            if item.get("status") in ("checking", "pending"):
                item["status"] = "pending"
            self.items[item["id"]] = item
        self.alerts = data.get("alerts") or []
        self.last_check = float(data.get("last_check") or 0)

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({
                "items": list(self.items.values()), "alerts": self.alerts,
                "last_check": self.last_check}))
            tmp.replace(self.path)
        except Exception as exc:
            print(f"[components] save failed: {exc!r}")

    # ---- observing traffic

    def observe(self, flow) -> list[dict]:
        host = flow.request.host
        url = flow.request.url
        new = []
        changed = False
        for hit in fingerprint(flow):
            distro = hit.get("distro")
            cid = ":".join([hit["key"], hit["version"], (distro or {}).get("version", "")])
            item = self.items.get(cid)
            if item is None:
                meta = PRODUCTS.get(hit["key"]) or {}
                item = self.items[cid] = {
                    "id": cid, "key": hit["key"], "label": meta.get("label") or hit["key"],
                    "version": hit["version"], "distro": distro,
                    "evidence": hit["evidence"], "backport": hit["backport"],
                    "hosts": {}, "first_seen": time.time(), "checked_at": 0,
                    "status": "pending" if hit["version"] else "unversioned",
                    "result": None,
                }
                new.append(item)
                changed = True
                if hit["version"]:
                    self._schedule(item)
            elif item["status"] == "pending" and not self._busy(item):
                self._schedule(item)  # loaded from disk mid-check
            if host not in item["hosts"]:
                item["hosts"][host] = {"url": url, "flow_id": flow.id}
                changed = True
                if item["result"]:
                    self._emit(item, host)
        if changed:
            self.save()
        return new

    def _busy(self, item: dict) -> bool:
        return item.get("status") == "checking"

    def _schedule(self, item: dict, fresh: bool = False) -> None:
        if not self.lookups:
            item["status"] = "offline"
            return
        try:
            task = asyncio.get_running_loop().create_task(self._run(item, fresh=fresh))
        except RuntimeError:
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run(self, item: dict, *, fresh: bool = False, alert: bool = False) -> None:
        item["status"] = "checking"
        before = item.get("result") or {}
        try:
            res = await assess(item["key"], item["version"], backport=item["backport"],
                               distro=item.get("distro"), fresh=fresh)
        except Exception as exc:
            item["status"] = "error"
            item["error"] = str(exc)
            return
        item["result"] = res
        item["checked_at"] = time.time()
        item["status"] = res["status"]
        item["error"] = ""
        if res.get("errors") and res["status"] == "ok":
            item["status"] = "error"
            item["error"] = "; ".join(res["errors"])
        if alert and before:
            self._diff_alert(item, before, res)
        for host in list(item["hosts"]):
            self._emit(item, host)
        self.save()

    def _emit(self, item: dict, host: str) -> None:
        if not self.on_result or not item.get("result"):
            return
        seen = item["hosts"][host]
        self.on_result(item, host, seen["url"], seen["flow_id"])

    # ---- daily re-check + alerts

    def _diff_alert(self, item: dict, before: dict, after: dict) -> None:
        old_ids = {c["id"] for c in before.get("cves") or []}
        old_kev = {c["id"] for c in before.get("cves") or [] if c.get("kev")}
        new_cves = [c["id"] for c in after.get("cves") or [] if c["id"] not in old_ids]
        new_kev = [c["id"] for c in after.get("cves") or []
                   if c.get("kev") and c["id"] not in old_kev]
        went_eol = (after.get("lifecycle") or {}).get("eol") and not \
            (before.get("lifecycle") or {}).get("eol")
        if not (new_cves or new_kev or went_eol):
            return
        name = f"{item['label']} {(item.get('distro') or {}).get('version') or item['version']}"
        parts = []
        if new_kev:
            parts.append(f"now actively exploited: {', '.join(new_kev[:5])}")
        if new_cves:
            parts.append(f"{len(new_cves)} new CVE{'s' if len(new_cves) != 1 else ''}")
        if went_eol:
            parts.append("its branch just reached end of life")
        alert = {
            "id": f"{item['id']}@{int(time.time())}", "ts": time.time(),
            "component": item["id"], "label": name,
            "severity": "critical" if new_kev else after.get("severity") or "medium",
            "message": f"{name}: " + "; ".join(parts),
            "new_kev": new_kev, "new_cves": new_cves[:50],
            "hosts": sorted(item["hosts"]), "fix": after.get("fix", ""),
        }
        self.alerts.insert(0, alert)
        del self.alerts[self.MAX_ALERTS:]
        if self.events is not None:
            self.events.add("component-alert", alert["message"],
                            hosts=alert["hosts"], severity=alert["severity"])
        print(f"[components] ALERT {alert['message']}")

    async def recheck(self, *, alert: bool = True) -> None:
        """Re-assess everything with fresh data, recording alerts for changes."""
        items = [i for i in self.items.values() if i["version"]]
        if not self.lookups:
            return
        for item in items:
            await self._run(item, fresh=True, alert=alert)
        self.last_check = time.time()
        self.save()

    async def watch(self, interval: float | None = None) -> None:
        """Background loop: re-check daily (and soon after start if overdue)."""
        interval = interval or self.INTERVAL
        while True:
            due = self.last_check + interval - time.time()
            await asyncio.sleep(max(120.0, due))
            try:
                await self.recheck()
            except Exception as exc:
                print(f"[components] daily re-check failed: {exc!r}")
                self.last_check = time.time()

    def dismiss_alerts(self) -> None:
        self.alerts = []
        self.save()

    async def wait(self) -> None:
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    def public(self) -> list[dict]:
        out = []
        for item in self.items.values():
            res = item.get("result") or {}
            distro = item.get("distro") or {}
            out.append({
                "id": item["id"], "key": item["key"], "label": item["label"],
                "version": item["version"], "distro": distro or None,
                "display_version": distro.get("version") or item["version"],
                "evidence": item["evidence"], "status": item["status"],
                "hosts": sorted(item["hosts"]), "error": item.get("error", ""),
                "severity": res.get("severity", ""), "max_cvss": res.get("max_cvss"),
                "cve_count": res.get("cve_count", 0), "fix": res.get("fix", ""),
                "kev_count": res.get("kev_count", 0),
                "likely_count": res.get("likely_count", 0),
                "max_epss": res.get("max_epss"),
                "lifecycle": res.get("lifecycle") or {},
                "cves": (res.get("cves") or [])[:25], "backport": item["backport"],
                "checked_at": item.get("checked_at") or 0,
            })
        rank = {"vulnerable": 0, "checking": 1, "pending": 1, "error": 2,
                "ok": 3, "offline": 3, "unversioned": 4}
        out.sort(key=lambda r: (rank.get(r["status"], 9), -r["kev_count"],
                                -r["likely_count"], -(r["max_cvss"] or 0), r["label"]))
        return out

    def summary(self) -> dict:
        return {"items": self.public(), "alerts": self.alerts,
                "last_check": self.last_check, "lookups": self.lookups}
