"""
Authorized GitHub repository scans.

Fetches lockfiles and source from repos you add, then:
  * runs the existing OSV dependency lookup
  * looks for leaked secrets and a few high-signal dangerous APIs

Files are read from GitHub over HTTP. Nothing is cloned onto disk, no
payloads are sent at a live app, and there is no exploit catalog. Only
add repos you own or have written permission to scan.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid
from pathlib import Path

import httpx

from modules import cvss as cvsslib
from modules import sca

SKIP_DIR = {
    "node_modules", "vendor", "dist", "build", ".git", "__pycache__",
    ".venv", "venv", "target", "Pods", ".next", "coverage",
}
LOCKFILES = {
    "requirements.txt", "requirements-dev.txt", "package-lock.json",
    "go.mod", "cargo.lock", "gemfile.lock",
}
SOURCE_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue",
    ".go", ".rb", ".java", ".php", ".cs", ".rs",
}
SOURCE_NAMES = {".env", ".env.local", ".env.production", "dockerfile"}
MAX_FILES = 400
MAX_BYTES = 400_000
PRIORITY_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "credentials", "secrets", "id_rsa",
}
GH = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"

# Detection only. No payloads, no confirmation against a live target.
RULES = (
    ("secret.private-key", "Private key material", "high", "secret",
     r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----",
     "A private key is committed. Rotate it and remove it from git history."),
    ("secret.aws-key", "AWS access key id", "high", "secret",
     r"AKIA[0-9A-Z]{16}",
     "An AWS access key id looks committed. Rotate the key in IAM."),
    ("secret.github-token", "GitHub token", "high", "secret",
     r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}",
     "A GitHub token looks committed. Revoke it in GitHub settings."),
    ("secret.slack-token", "Slack token", "high", "secret",
     r"xox[baprs]-[A-Za-z0-9-]{10,}",
     "A Slack token looks committed. Revoke it."),
    ("code.pickle", "Unsafe pickle deserialize", "high", "code",
     r"\bpickle\.loads?\s*\(",
     "pickle can execute attacker-controlled objects. Prefer json."),
    ("code.yaml-load", "Unsafe yaml.load", "medium", "code",
     r"\byaml\.load\s*\((?!.*Loader\s*=)",
     "yaml.load without a SafeLoader can execute Python objects."),
    ("code.shell-true", "subprocess shell=True", "medium", "code",
     r"subprocess\.\w+\([^)\n]*shell\s*=\s*True",
     "shell=True can turn untrusted input into command injection."),
    ("code.eval", "eval / Function constructor", "medium", "code",
     r"\beval\s*\(|new\s+Function\s*\(",
     "eval and new Function execute strings. Avoid with untrusted input."),
    ("code.innerhtml", "dangerouslySetInnerHTML / innerHTML", "medium", "code",
     r"dangerouslySetInnerHTML|\.innerHTML\s*=",
     "HTML assignment is a common XSS sink if the string is not trusted."),
    ("code.exec-js", "child_process exec", "high", "code",
     r"(?:child_process|require\(\s*['\"]child_process['\"]\s*\))\s*\.\s*"
     r"(?:exec|execSync|execFileSync)\s*\(",
     "child_process exec runs a shell command. Do not pass untrusted input."),
    ("code.os-system", "os.system / os.popen", "high", "code",
     r"\bos\.(?:system|popen)\s*\(",
     "os.system and os.popen run a shell. Prefer subprocess without shell=True."),
    ("code.php-unserialize", "PHP unserialize", "high", "code",
     r"\bunserialize\s*\(",
     "unserialize of untrusted data can instantiate PHP objects."),
    ("code.marshal", "Ruby Marshal.load", "high", "code",
     r"\bMarshal\.load\s*\(",
     "Marshal.load can deserialize and execute Ruby objects."),
)

GUIDES = {
    "secret.private-key": {
        "explain": (
            "A private key in the repo can be copied by anyone with read access, "
            "including old clones and forks. That key can impersonate the service "
            "or person it belongs to."
        ),
        "fix": [
            "Treat the key as compromised. Issue a new one and revoke the old.",
            "Delete the file from the working tree and purge it from git history.",
            "Store replacements in a secret manager or a local file that is gitignored.",
            "Rescan this repository to confirm the material is gone.",
        ],
    },
    "secret.aws-key": {
        "explain": (
            "Strings starting with AKIA look like AWS access key ids. A real key "
            "plus its secret lets anyone act as that IAM user. AWS's documented "
            "example (AKIAIOSFODNN7EXAMPLE) is a fixture — confirm before rotating."
        ),
        "fix": [
            "Check whether the value is a real key or the AWS example placeholder.",
            "If it is real, deactivate or delete the access key in IAM immediately.",
            "Remove it from the file and from git history.",
            "Load replacements from the environment or a secret manager, never source.",
            "Rescan this repository.",
        ],
    },
    "secret.github-token": {
        "explain": (
            "A GitHub token in source can clone, push, or call the API as that "
            "account. Classic and fine-grained tokens both count."
        ),
        "fix": [
            "Revoke the token under GitHub → Settings → Developer settings.",
            "Remove it from the file and from git history.",
            "Replace it with a short-lived token stored outside the repo.",
            "Rescan this repository.",
        ],
    },
    "secret.slack-token": {
        "explain": (
            "A Slack token in source can post, read, or administer the workspace "
            "as that app or user."
        ),
        "fix": [
            "Revoke the token in Slack app settings.",
            "Remove it from the file and from git history.",
            "Store the replacement outside the repository.",
            "Rescan this repository.",
        ],
    },
    "code.pickle": {
        "explain": (
            "pickle.loads can run arbitrary Python while reconstructing an object. "
            "A crafted blob is code execution."
        ),
        "fix": [
            "Stop unpickling data you did not write yourself.",
            "Prefer json, proto, or a dedicated serializer.",
            "If you must keep pickle, sign the blob and reject anything unsigned.",
            "Rescan this repository.",
        ],
    },
    "code.yaml-load": {
        "explain": (
            "yaml.load without a SafeLoader can construct Python objects from YAML, "
            "which is code execution on hostile input."
        ),
        "fix": [
            "Replace yaml.load(...) with yaml.safe_load(...) or SafeLoader.",
            "Do not load YAML from users or the network with the default loader.",
            "Rescan this repository.",
        ],
    },
    "code.shell-true": {
        "explain": (
            "subprocess with shell=True sends the command through a shell. "
            "Untrusted text in that string is command injection."
        ),
        "fix": [
            "Call subprocess with a argument list and shell=False.",
            "Never interpolate request, file, or user data into a shell string.",
            "Rescan this repository.",
        ],
    },
    "code.eval": {
        "explain": (
            "eval and new Function execute a string as code. If any part of that "
            "string is attacker-controlled, this is remote code execution. Confirm "
            "the call is actually a language eval — model.eval() in ML code and "
            "some CTF solvers are different functions that share the name."
        ),
        "fix": [
            "Open the listed line and confirm what eval refers to.",
            "If it executes a string, remove it. Parse data with JSON or a library.",
            "Never decode user, file, or network bytes and pass them to eval "
            "(including node -e \"eval(Buffer.from(...))\").",
            "If you cannot remove it, sandbox the runtime and block untrusted input.",
            "Rescan this repository.",
        ],
    },
    "code.innerhtml": {
        "explain": (
            "Assigning HTML or using dangerouslySetInnerHTML renders markup. "
            "Untrusted strings here are a stored or reflected XSS sink."
        ),
        "fix": [
            "Prefer textContent or a safe templating API.",
            "If HTML is required, sanitize with a maintained library and a tight allow-list.",
            "Rescan this repository.",
        ],
    },
    "code.exec-js": {
        "explain": (
            "child_process exec runs a shell command. Untrusted input in that "
            "command is host-level code execution."
        ),
        "fix": [
            "Use execFile or spawn with an argument array, not a shell string.",
            "Do not interpolate user or file data into the command.",
            "Rescan this repository.",
        ],
    },
    "code.os-system": {
        "explain": (
            "os.system and os.popen run a shell. Untrusted input in the string "
            "is command injection."
        ),
        "fix": [
            "Switch to subprocess with a argument list and shell=False.",
            "Do not build the command with user or file data.",
            "Rescan this repository.",
        ],
    },
    "code.php-unserialize": {
        "explain": (
            "unserialize of untrusted data can instantiate PHP objects and run "
            "magic methods — a common RCE gadget chain."
        ),
        "fix": [
            "Do not unserialize user or network input.",
            "Use json_decode or a signed, versioned format.",
            "Rescan this repository.",
        ],
    },
    "code.marshal": {
        "explain": (
            "Marshal.load can deserialize and execute Ruby objects from hostile "
            "bytes."
        ),
        "fix": [
            "Do not Marshal.load untrusted data.",
            "Use JSON or a signed format.",
            "Rescan this repository.",
        ],
    },
}


def enrich_finding(f: dict) -> dict:
    """Attach explain + fix so the UI can expand any stored finding."""
    out = dict(f)
    if (out.get("kind") or "") == "dependency":
        ev = (out.get("evidence") or "").strip()
        cve = out.get("cve") or out.get("id") or "this advisory"
        summary = (out.get("detail") or "").strip()
        if not summary or summary.startswith("Known vulnerability"):
            summary = (
                f"{cve} is a published vulnerability in a locked dependency"
                f"{f' ({ev})' if ev else ''}. Anyone who can reach the affected "
                "code path may exploit it until that pin is upgraded."
            )
        out["explain"] = summary
        out["fix"] = [
            f"Find the lockfile that pins {ev or 'this package'}.",
            f"Look up {cve} for the first patched version.",
            "Upgrade, regenerate the lockfile, and commit the change.",
            "Redeploy, then rescan this repository to confirm it is gone.",
        ]
        return out
    g = GUIDES.get(out.get("id") or "") or {}
    out["explain"] = out.get("explain") or g.get("explain") or out.get("detail") or ""
    out["fix"] = out.get("fix") or list(g.get("fix") or [])
    return out


def _home() -> Path:
    return Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))


def _path() -> Path:
    return _home() / "repos.json"


def parse_repo(text: str) -> tuple[str, str]:
    raw = (text or "").strip()
    raw = re.sub(r"^git@github\.com:", "https://github.com/", raw)
    raw = raw.removeprefix("https://github.com/")
    raw = raw.removeprefix("http://github.com/")
    raw = raw.removeprefix("github.com/")
    raw = raw.rstrip("/").removesuffix(".git")
    parts = [p for p in raw.split("/") if p]
    if len(parts) < 2:
        raise ValueError("use owner/repo or a github.com URL")
    owner, name = parts[0], parts[1]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise ValueError("not a GitHub owner/repo")
    return owner, name


def _skip_path(path: str) -> bool:
    parts = path.split("/")
    if any(p in SKIP_DIR for p in parts[:-1]):
        return True
    name = parts[-1].lower()
    if name.endswith(".min.js") or name.endswith(".map"):
        return True
    return False


def _want_source(path: str) -> bool:
    name = Path(path).name.lower()
    if name in SOURCE_NAMES or name in PRIORITY_NAMES:
        return True
    ext = Path(path).suffix.lower()
    if name.startswith(".env"):
        return True
    return ext in SOURCE_EXT and name not in LOCKFILES


def _is_test_path(path: str) -> bool:
    raw = (path or "").replace("\\", "/").lower()
    name = Path(raw).name
    if any(part in ("test", "tests", "__tests__", "spec", "specs")
           for part in raw.split("/")):
        return True
    if ".test." in name or ".spec." in name:
        return True
    if name.endswith(("_test.py", "_test.go", "_test.rb", "_test.js", "_test.ts")):
        return True
    return False


def _is_comment_line(snippet: str) -> bool:
    line = (snippet or "").strip()
    return line.startswith(("//", "#", "*", "/*", "--"))


def _ignore_code_hit(rule_id: str, path: str, snippet: str) -> bool:
    """eval in tests and comments is almost always a fixture, not a sink."""
    if rule_id != "code.eval":
        return False
    return _is_test_path(path) or _is_comment_line(snippet)


def _source_priority(path: str) -> int:
    name = Path(path).name.lower()
    if name.startswith(".env") or name in PRIORITY_NAMES:
        return 0
    if "secret" in name or "credential" in name or name.endswith(".pem"):
        return 1
    return 2


def scan_text(path: str, text: str) -> list[dict]:
    found = []
    for rid, title, sev, kind, pattern, detail in RULES:
        for m in re.finditer(pattern, text):
            line = text.count("\n", 0, m.start()) + 1
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.start())
            if end < 0:
                end = len(text)
            full_line = text[start:end]
            snippet = full_line.strip()[:80]
            if _ignore_code_hit(rid, path, full_line):
                continue
            found.append(enrich_finding({
                "id": rid,
                "kind": kind,
                "severity": sev,
                "title": title,
                "detail": detail,
                "path": path,
                "line": line,
                "evidence": snippet.strip(),
            }))
    return found


def _public_repo(row: dict) -> dict:
    out = dict(row)
    kept = []
    for f in row.get("findings") or []:
        if _ignore_code_hit(f.get("id") or "", f.get("path") or "",
                            f.get("evidence") or ""):
            continue
        kept.append(enrich_finding(f))
    out["findings"] = kept
    return out


class RepoStore:
    def __init__(self) -> None:
        self._data = self._load()
        self._stop: set[str] = set()
        self._stop_all = False
        self._active: set[str] = set()
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._heal_stale()

    def _heal_stale(self) -> None:
        dirty = False
        for row in self._data.get("repos") or []:
            if row.get("status") == "scanning":
                row["status"] = "stopped"
                row["progress"] = ""
                row["error"] = row.get("error") or "Stopped"
                dirty = True
        if dirty:
            self._save()

    def _load(self) -> dict:
        data = {"token": "", "authorized": False, "repos": []}
        try:
            if _path().exists():
                raw = json.loads(_path().read_text())
                if isinstance(raw, dict):
                    data["token"] = str(raw.get("token") or "")
                    data["authorized"] = bool(raw.get("authorized"))
                    repos = raw.get("repos")
                    if isinstance(repos, list):
                        data["repos"] = repos
        except Exception:
            pass
        return data

    def _save(self) -> None:
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._data, indent=2))

    def public(self) -> dict:
        token = self._data.get("token") or ""
        return {
            "authorized": bool(self._data.get("authorized")),
            "has_token": bool(token),
            "token": "••••" if token else "",
            "repos": [_public_repo(r) for r in (self._data.get("repos") or [])],
        }

    def configure(self, *, token: str | None = None,
                  authorized: bool | None = None) -> dict:
        if token is not None and "•" not in token:
            self._data["token"] = token.strip()
        if authorized is not None:
            self._data["authorized"] = bool(authorized)
        self._save()
        return self.public()

    def add(self, spec: str) -> dict:
        owner, name = parse_repo(spec)
        for row in self._data["repos"]:
            if row.get("owner") == owner and row.get("name") == name:
                return row
        row = {
            "id": uuid.uuid4().hex[:10],
            "owner": owner,
            "name": name,
            "url": f"https://github.com/{owner}/{name}",
            "added_at": time.time(),
            "last_scan": 0,
            "status": "idle",
            "progress": "",
            "error": "",
            "files": 0,
            "files_total": 0,
            "packages": 0,
            "mode": "",
            "findings": [],
        }
        self._data["repos"].append(row)
        self._save()
        return row

    def remove(self, repo_id: str) -> dict:
        self._data["repos"] = [r for r in self._data["repos"]
                               if r.get("id") != repo_id]
        self._stop.discard(repo_id)
        self._save()
        return self.public()

    async def stop(self, repo_id: str = "") -> dict:
        """Halt a scan now. If nothing is running, mark it stopped immediately."""
        targets: list[dict] = []
        if repo_id:
            self._stop.add(repo_id)
            try:
                targets.append(self._row(repo_id))
            except KeyError:
                pass
        else:
            self._stop_all = True
            targets = [r for r in (self._data.get("repos") or [])
                       if r.get("status") == "scanning"]
            for row in targets:
                self._stop.add(row["id"])
        for row in targets:
            rid = row["id"]
            client = self._clients.get(rid)
            if client is not None:
                try:
                    await client.aclose()
                except Exception:
                    pass
            if rid not in self._active:
                self._finish_stop(
                    row,
                    list(row.get("findings") or []),
                    [],
                    int(row.get("files") or 0),
                    int(row.get("files_total") or 0),
                )
            elif row.get("status") == "scanning":
                row["progress"] = "Stopping…"
        self._save()
        return self.public()

    def _want_stop(self, repo_id: str) -> bool:
        return self._stop_all or repo_id in self._stop

    def _clear_stop(self, repo_id: str) -> None:
        self._stop.discard(repo_id)

    def _finish_stop(self, row: dict, findings: list, packages: list,
                     files: int, files_total: int) -> dict:
        findings.sort(key=cvsslib.sort_key)
        row["status"] = "stopped"
        row["progress"] = ""
        row["error"] = "Stopped"
        row["files"] = files
        row["files_total"] = files_total
        row["packages"] = len(packages)
        row["findings"] = findings
        self._clear_stop(row["id"])
        self._save()
        return row

    def _mark_unstarted_stopped(self) -> None:
        for row in self._data.get("repos") or []:
            if row.get("status") in ("idle", ""):
                row["status"] = "stopped"
                row["progress"] = ""
                row["error"] = "Stopped"
                self._clear_stop(row["id"])
        self._save()

    def _row(self, repo_id: str) -> dict:
        for row in self._data["repos"]:
            if row.get("id") == repo_id:
                return row
        raise KeyError("repo not found")

    def _headers(self) -> dict:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Kerf-repo-scan",
        }
        token = (self._data.get("token") or "").strip()
        if token:
            headers["Authorization"] = "Bearer " + token
        return headers

    async def _meta(self, client: httpx.AsyncClient, owner: str, name: str) -> dict:
        r = await client.get(f"{GH}/repos/{owner}/{name}", headers=self._headers())
        if r.status_code == 404:
            raise FileNotFoundError(f"{owner}/{name} was not found (or is private)")
        if r.status_code == 403:
            raise PermissionError(
                "GitHub rate-limited the request. Paste a token under Repos.")
        r.raise_for_status()
        return r.json()

    async def _tree(self, client: httpx.AsyncClient, owner: str, name: str,
                    sha: str) -> tuple[list[dict], bool]:
        r = await client.get(
            f"{GH}/repos/{owner}/{name}/git/trees/{sha}",
            headers=self._headers(),
            params={"recursive": "1"},
        )
        r.raise_for_status()
        data = r.json()
        blobs = [t for t in (data.get("tree") or []) if t.get("type") == "blob"]
        return blobs, bool(data.get("truncated"))

    async def _file(self, client: httpx.AsyncClient, owner: str, name: str,
                    ref: str, path: str) -> str:
        url = f"{RAW}/{owner}/{name}/{ref}/{path}"
        headers = {"User-Agent": "Kerf-repo-scan"}
        token = (self._data.get("token") or "").strip()
        if token:
            headers["Authorization"] = "Bearer " + token
        r = await client.get(url, headers=headers, follow_redirects=True)
        if r.status_code != 200:
            return ""
        if len(r.content) > MAX_BYTES:
            return ""
        return r.text

    async def scan(self, repo_id: str, *, full: bool = False,
                  keep_stop: bool = False) -> dict:
        if not self._data.get("authorized"):
            raise PermissionError(
                "Authorize first — only scan repositories you own or "
                "have written permission to test.")
        row = self._row(repo_id)
        if not keep_stop:
            self._stop.discard(repo_id)
            self._stop_all = False
        def note(text: str) -> None:
            row["status"] = "scanning"
            row["progress"] = text
            row["error"] = ""
            self._save()
        row["findings"] = []
        row["packages"] = 0
        row["files"] = 0
        row["files_total"] = 0
        row["mode"] = "full" if full else "quick"
        findings: list = []
        packages: list = []
        files = 0
        files_total = 0
        self._active.add(repo_id)
        note("Listing repository on GitHub…")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                self._clients[repo_id] = client
                try:
                    if self._want_stop(repo_id):
                        return self._finish_stop(
                            row, findings, packages, files, files_total)
                    meta = await self._meta(client, row["owner"], row["name"])
                    ref = meta.get("default_branch") or "main"
                    note(f"Listing files on {ref}…")
                    if self._want_stop(repo_id):
                        return self._finish_stop(
                            row, findings, packages, files, files_total)
                    blobs, truncated = await self._tree(
                        client, row["owner"], row["name"], ref)
                    locks, sources = [], []
                    for blob in blobs:
                        path = blob.get("path") or ""
                        if _skip_path(path):
                            continue
                        name = Path(path).name.lower()
                        if name in LOCKFILES:
                            locks.append(path)
                        elif _want_source(path):
                            sources.append(path)
                    sources.sort(key=_source_priority)
                    files_total = len(locks) + len(sources)
                    if not full:
                        sources = sources[:MAX_FILES]

                    async def read(path: str) -> str:
                        if self._want_stop(repo_id):
                            return ""
                        try:
                            return await self._file(
                                client, row["owner"], row["name"], ref, path)
                        except Exception:
                            return ""

                    note(f"Reading {len(locks)} lockfile(s) over GitHub…")
                    for path in locks:
                        if self._want_stop(repo_id):
                            return self._finish_stop(
                                row, findings, packages, files, files_total)
                        text = await read(path)
                        if not text:
                            continue
                        files += 1
                        packages.extend(sca.parse_any(path, text))
                    batch = 16
                    for i in range(0, len(sources), batch):
                        if self._want_stop(repo_id):
                            return self._finish_stop(
                                row, findings, packages, files, files_total)
                        chunk = sources[i:i + batch]
                        note(f"Reading source {i + 1}–{i + len(chunk)}/{len(sources)}…")
                        texts = await asyncio.gather(
                            *(read(p) for p in chunk), return_exceptions=True)
                        for path, text in zip(chunk, texts):
                            if not isinstance(text, str) or not text:
                                continue
                            files += 1
                            for hit in scan_text(path, text):
                                hit["repo"] = f"{row['owner']}/{row['name']}"
                                findings.append(hit)
                    if self._want_stop(repo_id):
                        return self._finish_stop(
                            row, findings, packages, files, files_total)
                    note(f"Looking up CVSS for {len(packages)} package(s)…")
                    dep = await sca.query_osv(
                        packages, github_token=self._data.get("token") or "")
                    if self._want_stop(repo_id):
                        return self._finish_stop(
                            row, findings, packages, files, files_total)
                    for f in dep:
                        cve = f.get("cve") or ""
                        findings.append({
                            "id": f.get("id") or "",
                            "kind": "dependency",
                            "severity": f.get("severity") or "unknown",
                            "cvss": f.get("cvss"),
                            "cvss_vector": f.get("cvss_vector") or "",
                            "cvss_source": f.get("cvss_source") or "",
                            "cve": cve,
                            "cves": f.get("cves") or [],
                            "sources": f.get("sources") or [],
                            "title": f"{f.get('name')} {f.get('version')} — {cve or f.get('id')}",
                            "detail": f.get("summary") or "Known vulnerability in a locked dependency.",
                            "path": "",
                            "line": 0,
                            "evidence": f"{f.get('ecosystem')} {f.get('name')}@{f.get('version')}",
                            "repo": f"{row['owner']}/{row['name']}",
                            "refs": f.get("refs") or [],
                        })
                    findings.sort(key=cvsslib.sort_key)
                    row["status"] = "ok"
                    row["progress"] = ""
                    row["mode"] = "full" if full else "quick"
                    row["last_scan"] = time.time()
                    row["files"] = files
                    row["files_total"] = files_total
                    row["packages"] = len(packages)
                    row["findings"] = findings
                    row["error"] = (
                        "GitHub truncated the file list; some paths were not listed."
                        if truncated else "")
                    self._save()
                    return row
                except Exception as exc:
                    if self._want_stop(repo_id):
                        return self._finish_stop(
                            row, findings, packages, files, files_total)
                    row["status"] = "error"
                    row["progress"] = ""
                    row["error"] = str(exc)
                    self._save()
                    raise
        finally:
            self._clients.pop(repo_id, None)
            self._active.discard(repo_id)

    async def scan_all(self) -> dict:
        self._stop.clear()
        self._stop_all = False
        for row in self._data.get("repos") or []:
            row["findings"] = []
            row["packages"] = 0
            row["files"] = 0
            row["files_total"] = 0
            row["error"] = ""
            row["progress"] = ""
        self._save()
        errors = []
        for row in list(self._data.get("repos") or []):
            if self._stop_all or self._want_stop(row["id"]):
                self._mark_unstarted_stopped()
                break
            try:
                await self.scan(row["id"], keep_stop=True)
            except Exception as exc:
                errors.append({"id": row.get("id"), "error": str(exc)})
            if self._stop_all:
                self._mark_unstarted_stopped()
                break
        self._stop.clear()
        self._stop_all = False
        out = self.public()
        out["errors"] = errors
        return out
