"""CVSS 3.x base-score helper. Used to sort and label dependency findings."""

from __future__ import annotations

import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}


def _roundup(n: float) -> float:
    return math.ceil(n * 10 - 1e-9) / 10


def score_v3(vector: str) -> float | None:
    """Base score from a CVSS:3.0/3.1 vector, or None if it is not parseable."""
    raw = (vector or "").strip()
    if not raw.upper().startswith("CVSS:3"):
        return None
    parts = dict(re.findall(r"/([A-Z]{1,2}):([A-Z])", "/" + raw.split("/", 1)[-1]
                            if "/" in raw else raw))
    try:
        av, ac, pr, ui = parts["AV"], parts["AC"], parts["PR"], parts["UI"]
        scope, c, i, a = parts["S"], parts["C"], parts["I"], parts["A"]
        iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])
        if iss <= 0:
            return 0.0
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exploit = 8.22 * _AV[av] * _AC[ac] * _PR[scope][pr] * _UI[ui]
        if scope == "U":
            score = min(10.0, _roundup(impact + exploit))
        else:
            score = min(10.0, _roundup(1.08 * (impact + exploit)))
        return score
    except (KeyError, ValueError):
        return None


def parse_score(value) -> float | None:
    """Accept a number, '9.8', or a CVSS:3 vector."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text.upper().startswith("CVSS:3"):
        return score_v3(text)
    try:
        return float(text.split("/")[0])
    except ValueError:
        return None


def bucket(score: float | None) -> str:
    """NVD qualitative labels from a real base score. No score → unknown."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def cves_of(aliases) -> list[str]:
    out = []
    for item in aliases or []:
        text = str(item).strip().upper()
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", text):
            out.append(text)
    return out


def ghsas_of(aliases) -> list[str]:
    out = []
    for item in aliases or []:
        text = str(item).strip()
        if re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", text, re.I):
            out.append(text)
    return out


def sort_key(finding: dict) -> tuple:
    """Highest real CVSS first. Local (unscored) findings use a stand-in rank only."""
    cvss = finding.get("cvss")
    scored = cvss is not None
    if not scored:
        cvss = {"critical": 9.5, "high": 7.5, "medium": 5.0,
                "low": 2.0, "info": 0.0, "unknown": 0.0}.get(
                    finding.get("severity") or "", 0.0)
    return (0 if scored else 1, -float(cvss),
            finding.get("cve") or finding.get("id") or "")
