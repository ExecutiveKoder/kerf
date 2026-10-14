"""
Software composition analysis via the public OSV API.

Reads lockfiles you already have (requirements, package-lock, go.mod, …) and
lists known vulnerabilities. This is the Sonatype Lifecycle-shaped job —
dependency risk — not a clone of Nexus repository hosting.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

OSV = "https://api.osv.dev/v1/querybatch"

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
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.+\-]+)", line)
        if m:
            out.append(_pkg("pypi", m.group(1), m.group(2)))
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
        if name and ver and not meta.get("dev"):
            out.append(_pkg("npm", name, ver))
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


def _sev(vuln: dict) -> str:
    for sev in vuln.get("severity") or []:
        score = str(sev.get("score") or "")
        try:
            n = float(score.split("/")[0])
            if n >= 9:
                return "critical"
            if n >= 7:
                return "high"
            if n >= 4:
                return "medium"
            return "low"
        except ValueError:
            pass
    return "medium"


async def query_osv(packages: list[dict]) -> list[dict]:
    if not packages:
        return []
    # de-dupe
    seen = set()
    uniq = []
    for p in packages:
        key = (p["ecosystem"], p["name"], p["version"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)
    queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                "version": p["version"]} for p in uniq]
    findings = []
    async with httpx.AsyncClient(timeout=30) as client:
        for i in range(0, len(queries), 80):
            batch = queries[i:i + 80]
            r = await client.post(OSV, json={"queries": batch})
            r.raise_for_status()
            results = r.json().get("results") or []
            for pkg, res in zip(uniq[i:i + 80], results):
                for v in res.get("vulns") or []:
                    aliases = v.get("aliases") or []
                    findings.append({
                        "ecosystem": pkg["ecosystem"],
                        "name": pkg["name"],
                        "version": pkg["version"],
                        "id": v.get("id"),
                        "aliases": aliases,
                        "summary": v.get("summary") or "",
                        "severity": _sev(v),
                        "refs": [r.get("url") for r in (v.get("references") or [])
                                 if r.get("url")][:6],
                    })
    findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2,
                                 "low": 3}.get(f["severity"], 9))
    return findings


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
            "ratings": [{"severity": f["severity"]}],
            "affects": [{"ref": f"{f['ecosystem']}:{f['name']}@{f['version']}"}],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": [{"name": "SureGuard", "version": "0.2"}]},
        "components": comps,
        "vulnerabilities": vulns,
    }
