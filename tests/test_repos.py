"""GitHub repo list + local code/secret findings. No network."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.repos import RepoStore, enrich_finding, parse_repo, scan_text
from modules import sca


def test_parse_repo():
    assert parse_repo("https://github.com/acme/app") == ("acme", "app")
    assert parse_repo("https://github.com/acme/app.git") == ("acme", "app")
    assert parse_repo("git@github.com:acme/app.git") == ("acme", "app")
    assert parse_repo("acme/app") == ("acme", "app")
    try:
        parse_repo("just-a-name")
        raise AssertionError("accepted a bare name")
    except ValueError:
        pass


def test_scan_text_secret_and_code():
    hits = scan_text("app.py", """
import pickle
key = '''-----BEGIN RSA PRIVATE KEY-----
MIIB
'''
pickle.loads(data)
""")
    kinds = {h["id"] for h in hits}
    assert "secret.private-key" in kinds
    assert "code.pickle" in kinds
    assert any(h["line"] >= 1 for h in hits)


def test_eval_in_tests_is_ignored():
    hits = scan_text("src/foo.test.ts", "eval(source);\n")
    assert hits == []
    hits = scan_text("tests/eval_effects.py", "eval(code)\n")
    assert hits == []
    hits = scan_text("src/app.ts", "// eval(source) is discussed here\n")
    assert hits == []
    hits = scan_text("src/app.ts", "eval(userInput);\n")
    assert any(h["id"] == "code.eval" for h in hits)


def test_fixtures_and_rule_catalog_are_ignored():
    assert scan_text("tests/test_repos.py", "os.system(cmd)\npickle.loads(data)\n") == []
    assert scan_text(
        "modules/repos.py",
        '    r"dangerouslySetInnerHTML|\\.innerHTML\\s*="\n'
        '    "Replace yaml.load(...) with yaml.safe_load(...)."\n'
        '    "example (AKIAIOSFODNN7EXAMPLE) is a fixture"\n',
    ) == []
    hits = scan_text("app.py", "el.innerHTML = userInput\nyaml.load(data)\n")
    kinds = {h["id"] for h in hits}
    assert "code.innerhtml" in kinds
    assert "code.yaml-load" in kinds
    assert scan_text("ui.js", "el.innerHTML = '<div>ok</div>'\n") == []
    assert scan_text("ui.js", "el.innerHTML = rows.map(r => r.html)\n") == []


def test_scan_text_dangerous_exec():
    hits = scan_text("run.py", "os.system(cmd)\nchild_process.exec(user)\n")
    kinds = {h["id"] for h in hits}
    assert "code.os-system" in kinds
    assert "code.exec-js" in kinds


def test_store_add_and_auth():
    os.environ["DASTDAY_HOME"] = tempfile.mkdtemp(prefix="kerf-repos-")
    store = RepoStore()
    row = store.add("https://github.com/acme/app")
    assert row["owner"] == "acme"
    assert store.add("acme/app")["id"] == row["id"]
    assert len(store.public()["repos"]) == 1
    assert store.public()["authorized"] is False
    try:
        import asyncio
        asyncio.run(store.scan(row["id"]))
        raise AssertionError("scanned without authorization")
    except PermissionError:
        pass
    try:
        store.start_scan(row["id"], full=True)
        raise AssertionError("started a scan without authorization")
    except PermissionError as exc:
        assert "authorized" in str(exc).lower()
    store.configure(authorized=True)
    assert store.public()["authorized"] is True
    store.remove(row["id"])
    assert store.public()["repos"] == []


def test_requirements_keeps_range_vs_pin():
    rows = {p["name"]: p for p in sca.parse_requirements(
        "cryptography>=42.0\nhttpx==0.27.0\n")}
    assert rows["cryptography"]["pinned"] is False
    assert rows["cryptography"]["spec"] == ">=42.0"
    assert rows["cryptography"]["version"] == "42.0"
    assert rows["httpx"]["pinned"] is True
    assert rows["httpx"]["version"] == "0.27.0"


def test_package_lock_includes_dev():
    text = """{
      "packages": {
        "": {"name": "app"},
        "node_modules/leftpad": {"version": "1.0.0"},
        "node_modules/vite": {"version": "8.3.2", "dev": true}
      }
    }"""
    pkgs = sca.parse_package_lock(text)
    names = {p["name"]: p for p in pkgs}
    assert "leftpad" in names
    assert names["vite"]["dev"] is True


def test_stop_flags_a_running_scan():
    os.environ["DASTDAY_HOME"] = tempfile.mkdtemp(prefix="kerf-repos-")
    store = RepoStore()
    store.configure(authorized=True)
    row = store.add("acme/app")
    row["status"] = "scanning"
    row["progress"] = "Reading source 1–16/400…"
    store._save()
    import asyncio
    out = asyncio.run(store.stop(row["id"]))
    listed = next(r for r in out["repos"] if r["id"] == row["id"])
    assert listed["status"] == "stopped"
    assert listed["error"] == "Stopped"


def test_enrich_finding_has_fix_steps():
    code = enrich_finding({"id": "code.eval", "kind": "code", "detail": "eval"})
    assert "confirm" in code["explain"].lower() or "eval" in code["explain"].lower()
    assert len(code["fix"]) >= 3
    dep = enrich_finding({
        "kind": "dependency", "cve": "CVE-2026-112942",
        "detail": "Known vulnerability in a locked dependency.",
        "evidence": "npm vite@8.3.2",
    })
    assert "CVE-2026-112942" in dep["explain"]
    assert any("lockfile" in s.lower() for s in dep["fix"])


def test_heal_stale_scanning():
    home = tempfile.mkdtemp(prefix="kerf-repos-")
    os.environ["DASTDAY_HOME"] = home
    store = RepoStore()
    store.configure(authorized=True)
    row = store.add("acme/app")
    row["status"] = "scanning"
    row["progress"] = "Stopping…"
    store._save()
    again = RepoStore()
    listed = next(r for r in again.public()["repos"] if r["id"] == row["id"])
    assert listed["status"] == "stopped"
    assert listed["progress"] == ""


if __name__ == "__main__":
    test_parse_repo()
    test_scan_text_secret_and_code()
    test_eval_in_tests_is_ignored()
    test_scan_text_dangerous_exec()
    test_store_add_and_auth()
    test_package_lock_includes_dev()
    test_stop_flags_a_running_scan()
    test_enrich_finding_has_fix_steps()
    test_heal_stale_scanning()
    print("repo tests ok")
