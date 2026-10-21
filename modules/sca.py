"""
Software composition analysis.

Lockfiles are looked up in several public advisory sources:
  * OSV (package → known vuln)
  * GitHub Advisory (GHSA → CVE / CVSS)
  * NVD (CVE → official CVSS)

Results are sorted by CVSS, high to low.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path

import httpx

from modules import cvss as cvsslib

OSV = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns"
PYPI = "https://pypi.org/pypi"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GH_ADV = "https://api.github.com/advisories"

ECO = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
    "maven": "Maven",
}


def _pkg(eco: str, name: str, version: str) -> dict:
    return {"ecosystem": ECO[eco], "name": name, "version": version}


def parse_requirements(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        m = re.match(
            r"([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(===|==|>=|<=|~=|!=|<|>)?\s*"
            r"([A-Za-z0-9_.+\-]*)",
            line,
        )
        if m and m.group(1):
            op = m.group(2) or ""
            ver = m.group(3) or ""
            row = _pkg("pypi", m.group(1), ver or "0")
            row["op"] = op
            row["pinned"] = op in ("==", "===")
            row["spec"] = f"{op}{ver}" if op else (ver or m.group(1))
            out.append(row)
    return out


def parse_package_lock(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    packages = data.get("packages") or {}
    for key, meta in packages.items():
        if not key or key == "":
            continue
        name = key.split("node_modules/")[-1]
        ver = meta.get("version")
        if name and ver:
            row = _pkg("npm", name, ver)
            if meta.get("dev"):
                row["dev"] = True
            out.append(row)
    if not out:
        deps = data.get("dependencies") or {}
        for name, meta in deps.items():
            ver = (meta or {}).get("version")
            if name and ver:
                out.append(_pkg("npm", name, ver))
    return out


def parse_go_mod(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z0-9./_\-]+)\s+v([0-9][^\s]+)", line)
        if m and not line.strip().startswith("module"):
            out.append(_pkg("go", m.group(1), "v" + m.group(2)))
    return out


def parse_cargo_lock(text: str) -> list[dict]:
    out = []
    name = ver = None
    for line in text.splitlines():
        if line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and name:
            ver = line.split("=", 1)[1].strip().strip('"')
            out.append(_pkg("cargo", name, ver))
            name = ver = None
    return out


def parse_gemfile_lock(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = re.match(r"\s{4}([A-Za-z0-9_\-]+)\s+\(([^)]+)\)", line)
        if m:
            out.append(_pkg("rubygems", m.group(1), m.group(2)))
    return out


def parse_any(path: str, text: str) -> list[dict]:
    name = Path(path).name.lower()
    if name in ("requirements.txt", "requirements-dev.txt"):
        return parse_requirements(text)
    if name == "package-lock.json":
        return parse_package_lock(text)
    if name == "go.mod":
        return parse_go_mod(text)
    if name == "cargo.lock":
        return parse_cargo_lock(text)
    if name == "gemfile.lock":
        return parse_gemfile_lock(text)
    if name.endswith(".txt") and "==" in text:
        return parse_requirements(text)
    if text.lstrip().startswith("{"):
        return parse_package_lock(text)
    return []


def parse_path(path: str) -> list[dict]:
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(path)
    return parse_any(str(p), p.read_text(errors="replace"))


def _best_score(*candidates) -> tuple[float | None, str]:
    best = None
    vector = ""
    for raw in candidates:
        if isinstance(raw, dict):
            raw = raw.get("score") or raw.get("vector_string") or raw.get("vectorString")
        n = cvsslib.parse_score(raw)
        if n is None:
            continue
        if best is None or n > best:
            best = n
            text = str(raw).strip() if raw is not None else ""
            vector = text if text.upper().startswith("CVSS:") else vector
    return best, vector


def _osv_cvss(vuln: dict) -> tuple[float | None, str]:
    extras = []
    for sev in vuln.get("severity") or []:
        extras.append((sev or {}).get("score"))
    ds = vuln.get("database_specific") or {}
    extras.append(ds.get("cvss_score"))
    extras.append(ds.get("cvss"))
    return _best_score(*extras)


def _osv_row(pkg: dict, vuln: dict) -> dict:
    aliases = vuln.get("aliases") or []
    ids = [vuln.get("id"), *aliases]
    cves = cvsslib.cves_of(ids)
    score, vector = _osv_cvss(vuln)
    refs = [r.get("url") for r in (vuln.get("references") or []) if r.get("url")]
    summary = (vuln.get("summary") or "").strip()
    if not summary:
        details = (vuln.get("details") or "").strip()
        summary = details.split("\n\n", 1)[0][:400]
    row = {
        "ecosystem": pkg["ecosystem"],
        "name": pkg["name"],
        "version": pkg["version"],
        "id": vuln.get("id") or "",
        "aliases": aliases,
        "cve": cves[0] if cves else "",
        "cves": cves,
        "cvss": score,
        "cvss_vector": vector,
        "cvss_source": "OSV" if score is not None else "",
        "severity": cvsslib.bucket(score),
        "summary": summary,
        "sources": ["OSV"],
        "refs": refs[:8],
    }
    if pkg.get("requested"):
        row["requested"] = pkg["requested"]
    return row


def _cache_path() -> Path:
    home = Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))
    return home / "advisory-cache.json"


def _cache_get() -> dict:
    try:
        path = _cache_path()
        if path.exists():
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _cache_put(cache: dict) -> None:
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache))


async def _github_advisory(client: httpx.AsyncClient, ghsa: str,
                           token: str) -> dict | None:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "Kerf"}
    if token:
        headers["Authorization"] = "Bearer " + token
    r = await client.get(f"{GH_ADV}/{ghsa}", headers=headers)
    if r.status_code != 200:
        return None
    data = r.json()
    sev = data.get("cvss_severities") or {}
    score, vector = _best_score(
        sev.get("cvss_v3"), data.get("cvss"), sev.get("cvss_v4"))
    cves = []
    for ident in data.get("identifiers") or []:
        if (ident or {}).get("type") == "CVE":
            cves.extend(cvsslib.cves_of([(ident or {}).get("value")]))
    cves.extend(cvsslib.cves_of([data.get("cve_id")]))
    return {
        "cvss": score,
        "vector": vector,
        "cves": list(dict.fromkeys(cves)),
        "source": "GitHub Advisory",
    }


async def _nvd_cve(client: httpx.AsyncClient, cve: str) -> dict | None:
    headers = {"User-Agent": "Kerf-sca"}
    key = (os.environ.get("NVD_API_KEY") or "").strip()
    params = {"cveId": cve}
    if key:
        headers["apiKey"] = key
    r = await client.get(NVD, headers=headers, params=params)
    if r.status_code != 200:
        return None
    items = r.json().get("vulnerabilities") or []
    if not items:
        return None
    metrics = ((items[0].get("cve") or {}).get("metrics") or {})
    score = None
    vector = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        data = (rows[0].get("cvssData") or {})
        score, vector = _best_score(data.get("baseScore"), data.get("vectorString"))
        if score is not None:
            if not vector:
                vector = str(data.get("vectorString") or "")
            break
    return {"cvss": score, "vector": vector, "cves": [cve], "source": "NVD"}


def _apply_hit(finding: dict, hit: dict, *, prefer: bool = False) -> None:
    if not hit:
        return
    if hit.get("cves"):
        finding["cves"] = list(dict.fromkeys((finding.get("cves") or []) + hit["cves"]))
        if not finding.get("cve"):
            finding["cve"] = finding["cves"][0]
    src = hit.get("source")
    if src and src not in finding["sources"]:
        finding["sources"].append(src)
    score = hit.get("cvss")
    if score is None:
        return
    if finding.get("cvss") is None or prefer:
        finding["cvss"] = score
        finding["cvss_source"] = src or finding.get("cvss_source") or ""
        if hit.get("vector"):
            finding["cvss_vector"] = hit["vector"]


async def _enrich(findings: list[dict], *, github_token: str = "") -> list[dict]:
    token = github_token or (os.environ.get("GITHUB_TOKEN") or "").strip()
    cache = _cache_get()
    ghsas, cves = set(), set()
    for f in findings:
        keys = [f.get("id"), *(f.get("aliases") or []), *(f.get("cves") or []), f.get("cve")]
        ghsas.update(cvsslib.ghsas_of(keys))
        cves.update(cvsslib.cves_of(keys))

    async with httpx.AsyncClient(timeout=20) as client:
        async def gh(ghsa: str) -> None:
            if ghsa in cache:
                return
            cache[ghsa] = await _github_advisory(client, ghsa, token) or {}

        await asyncio.gather(*(gh(g) for g in sorted(ghsas)))
        for f in findings:
            for ghsa in cvsslib.ghsas_of(
                    [f.get("id"), *(f.get("aliases") or [])]):
                _apply_hit(f, cache.get(ghsa) or {})
            cves.update(f.get("cves") or [])
            if f.get("cve"):
                cves.add(f["cve"])

        need = {cve for f in findings if f.get("cvss") is None
                for cve in ([f.get("cve")] if f.get("cve") else (f.get("cves") or []))}
        sem = asyncio.Semaphore(3)

        async def nvd(cve: str) -> None:
            if cve in cache:
                return
            async with sem:
                cache[cve] = await _nvd_cve(client, cve) or {}

        await asyncio.gather(*(nvd(c) for c in sorted(need)))
        for f in findings:
            for cve in ([f.get("cve")] if f.get("cve") else []) + (f.get("cves") or []):
                hit = cache.get(cve) or {}
                _apply_hit(f, hit, prefer=hit.get("source") == "NVD")
            f["severity"] = cvsslib.bucket(f.get("cvss"))
    _cache_put(cache)
    findings.sort(key=cvsslib.sort_key)
    return findings


def _cluster_keys(f: dict) -> set[tuple]:
    eco = f.get("ecosystem") or ""
    name = (f.get("name") or "").lower()
    ver = f.get("version") or ""
    keys = set()
    ids = [f.get("id"), f.get("cve"), *(f.get("cves") or []), *(f.get("aliases") or [])]
    for cve in cvsslib.cves_of(ids):
        keys.add((eco, name, ver, "cve", cve))
    for ghsa in cvsslib.ghsas_of(ids):
        keys.add((eco, name, ver, "ghsa", ghsa.lower()))
    if not keys and f.get("id"):
        keys.add((eco, name, ver, "id", str(f["id"]).upper()))
    return keys


def _id_rank(fid: str) -> int:
    u = (fid or "").upper()
    if u.startswith("CVE-"):
        return 0
    if u.startswith("GHSA-"):
        return 1
    if u.startswith("PYSEC-"):
        return 3
    return 2


def _merge_osv_group(rows: list[dict]) -> dict:
    rows = sorted(rows, key=lambda f: (
        0 if f.get("cvss") is not None else 1,
        _id_rank(f.get("id") or ""),
        -(f.get("cvss") or 0),
    ))
    out = dict(rows[0])
    aliases, cves, refs, sources = set(), set(), [], []
    for f in rows:
        aliases.update(x for x in (f.get("aliases") or []) if x)
        if f.get("id"):
            aliases.add(f["id"])
        cves.update(f.get("cves") or [])
        if f.get("cve"):
            cves.add(f["cve"])
        for url in f.get("refs") or []:
            if url not in refs:
                refs.append(url)
        for src in f.get("sources") or []:
            if src not in sources:
                sources.append(src)
        if not (out.get("summary") or "").strip() and f.get("summary"):
            out["summary"] = f["summary"]
        if out.get("cvss") is None and f.get("cvss") is not None:
            out["cvss"] = f["cvss"]
            out["cvss_vector"] = f.get("cvss_vector") or ""
            out["cvss_source"] = f.get("cvss_source") or ""
    out["aliases"] = sorted(aliases)
    out["cves"] = cvsslib.cves_of(list(cves) + list(aliases) + [out.get("id")])
    out["cve"] = out["cves"][0] if out["cves"] else (out.get("cve") or "")
    ghsa = cvsslib.ghsas_of([out.get("id"), *aliases])
    if (out.get("id") or "").upper().startswith("PYSEC-"):
        out["id"] = out["cve"] or (ghsa[0] if ghsa else out.get("id"))
    out["refs"] = refs[:8]
    out["sources"] = sources or ["OSV"]
    out["severity"] = cvsslib.bucket(out.get("cvss"))
    return out


def dedupe_osv(findings: list[dict]) -> list[dict]:
    """Collapse GHSA + PYSEC (+ extra aliases) for the same package CVE."""
    if not findings:
        return []
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    seen: dict[tuple, int] = {}
    for i, f in enumerate(findings):
        for key in _cluster_keys(f):
            if key in seen:
                union(i, seen[key])
            else:
                seen[key] = i
    buckets: dict[int, list[dict]] = {}
    for i, f in enumerate(findings):
        buckets.setdefault(find(i), []).append(f)
    out = [_merge_osv_group(rows) for rows in buckets.values()]
    out.sort(key=cvsslib.sort_key)
    return out


async def _resolve_unpinned(packages: list[dict], client: httpx.AsyncClient) -> None:
    """Use the latest PyPI release for unpinned / range pins so we don't
    treat `cryptography>=42.0` as a lock on 42.0."""
    sem = asyncio.Semaphore(8)

    async def one(pkg: dict) -> None:
        if (pkg.get("ecosystem") or "") != "PyPI":
            return
        if pkg.get("pinned") or pkg.get("op") in ("==", "==="):
            return
        async with sem:
            try:
                r = await client.get(f"{PYPI}/{pkg['name']}/json")
            except Exception:
                return
        if r.status_code != 200:
            return
        latest = ((r.json() or {}).get("info") or {}).get("version")
        if not latest:
            return
        spec = pkg.get("spec") or pkg.get("op", "") + (pkg.get("version") or "")
        pkg["requested"] = spec or pkg.get("version")
        pkg["version"] = latest

    await asyncio.gather(*(one(p) for p in packages))


async def query_osv(packages: list[dict], *, github_token: str = "") -> list[dict]:
    if not packages:
        return []
    seen = set()
    uniq = []
    pairs: list[tuple[dict, str]] = []
    async with httpx.AsyncClient(timeout=30) as client:
        await _resolve_unpinned(packages, client)
        for p in packages:
            key = (p["ecosystem"], p["name"], p["version"])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(p)
        queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                    "version": p["version"]} for p in uniq]
        for i in range(0, len(queries), 80):
            batch = queries[i:i + 80]
            r = await client.post(OSV, json={"queries": batch})
            r.raise_for_status()
            results = r.json().get("results") or []
            for pkg, res in zip(uniq[i:i + 80], results):
                for v in res.get("vulns") or []:
                    vid = (v or {}).get("id") or ""
                    if vid:
                        pairs.append((pkg, vid))
        ids = list(dict.fromkeys(vid for _, vid in pairs))
        hydrated: dict[str, dict] = {}
        sem = asyncio.Semaphore(8)

        async def load(vid: str) -> None:
            async with sem:
                r = await client.get(f"{OSV_VULN}/{vid}")
                hydrated[vid] = r.json() if r.status_code == 200 else {"id": vid}

        await asyncio.gather(*(load(vid) for vid in ids))
    findings = [_osv_row(pkg, hydrated.get(vid) or {"id": vid})
                for pkg, vid in pairs]
    return dedupe_osv(await _enrich(findings, github_token=github_token))


def cyclonedx(packages: list[dict], findings: list[dict]) -> dict:
    comps = []
    for p in packages:
        comps.append({
            "type": "library",
            "name": p["name"],
            "version": p["version"],
            "bom-ref": f"{p['ecosystem']}:{p['name']}@{p['version']}",
        })
    vulns = []
    for f in findings:
        vulns.append({
            "id": f["id"],
            "description": f.get("summary") or "",
            "ratings": [{
                "method": "CVSSv31" if (f.get("cvss_vector") or "").startswith("CVSS:3")
                else "other",
                "score": f.get("cvss"),
                "severity": f["severity"],
                "vector": f.get("cvss_vector") or "",
            }],
            "affects": [{"ref": f"{f['ecosystem']}:{f['name']}@{f['version']}"}],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": [{"name": "Kerf", "version": "0.2"}]},
        "components": comps,
        "vulnerabilities": vulns,
    }
