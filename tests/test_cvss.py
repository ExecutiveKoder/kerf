"""Real CVSS 3.x scores drive critical / high / medium / low."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import cvss as cvsslib
from modules import sca


def test_known_vectors():
    assert cvsslib.score_v3(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvsslib.score_v3(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvsslib.score_v3(
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 6.5
    assert cvsslib.score_v3(
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H") == 7.8


def test_bucket_from_real_score():
    assert cvsslib.bucket(10.0) == "critical"
    assert cvsslib.bucket(9.0) == "critical"
    assert cvsslib.bucket(8.8) == "high"
    assert cvsslib.bucket(7.0) == "high"
    assert cvsslib.bucket(6.5) == "medium"
    assert cvsslib.bucket(4.0) == "medium"
    assert cvsslib.bucket(3.9) == "low"
    assert cvsslib.bucket(None) == "unknown"


def test_osv_row_uses_vector_not_guess():
    row = sca._osv_row(
        {"ecosystem": "PyPI", "name": "log4j", "version": "2.14.1"},
        {
            "id": "GHSA-jfh8-c2jp-5v3q",
            "aliases": ["CVE-2021-44228"],
            "summary": "Log4Shell",
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            }],
        },
    )
    assert row["cvss"] == 10.0
    assert row["severity"] == "critical"
    assert row["cve"] == "CVE-2021-44228"
    assert row["cvss_source"] == "OSV"


def test_sort_real_cvss_first():
    rows = [
        {"id": "b", "cvss": 6.5, "severity": "medium"},
        {"id": "a", "cvss": 9.8, "severity": "critical"},
        {"id": "secret", "cvss": None, "severity": "high"},
    ]
    rows.sort(key=cvsslib.sort_key)
    assert [r["id"] for r in rows] == ["a", "b", "secret"]


if __name__ == "__main__":
    test_known_vectors()
    test_bucket_from_real_score()
    test_osv_row_uses_vector_not_guess()
    test_sort_real_cvss_first()
    print("cvss tests ok")
