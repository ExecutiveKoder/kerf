"""
Projects — save and resume a working session.

A project bundles two files under the projects directory:

  * <name>.db    — a copy of the flow database (proxy history).
  * <name>.json  — a manifest: scope, passive + active findings, counts, notes.

Saving snapshots the current session. Resuming merges the saved flows back into
the live history and restores scope and findings. This is the "partial" project
persistence described in the README, built on the existing SQLite layer.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path


_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(name: str) -> str:
    s = _SAFE.sub("-", name.strip()).strip("-")
    return s or "project"


class ProjectManager:
    def __init__(self, *, history, interceptor, passive, active,
                 db_path: str, projects_dir: str | Path = "projects") -> None:
        self.history = history
        self.interceptor = interceptor
        self.passive = passive
        self.active = active
        self.db_path = str(db_path)
        self.dir = Path(projects_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.current: str | None = None

    # --------------------------------------------------------------- paths

    def _db_file(self, slug: str) -> Path:
        return self.dir / f"{slug}.db"

    def _manifest_file(self, slug: str) -> Path:
        return self.dir / f"{slug}.json"

    # ---------------------------------------------------------------- save

    def save(self, name: str, note: str = "") -> dict:
        slug = _slug(name)
        self.history.export_to(self._db_file(slug))
        manifest = {
            "name": name,
            "slug": slug,
            "note": note,
            "saved_at": time.time(),
            "scope": sorted(self.interceptor.scope_hosts),
            "active_scope": sorted(self.active.scope_hosts),
            "active_authorized": bool(self.active.authorized),
            "flows": self.history.count(),
            "passive_findings": self.passive.report(),
            "active_findings": self.active.report(),
        }
        self._manifest_file(slug).write_text(json.dumps(manifest, indent=2))
        self.current = slug
        return self._summary(manifest)

    # ---------------------------------------------------------------- load

    def load(self, name: str, *, restore_authorization: bool = True) -> dict:
        slug = _slug(name)
        mf = self._manifest_file(slug)
        if not mf.exists():
            raise FileNotFoundError(f"no project named '{name}'")
        manifest = json.loads(mf.read_text())

        imported = 0
        if self._db_file(slug).exists():
            imported = self.history.import_from(self._db_file(slug))

        # Restore scope.
        self.interceptor.scope_hosts = set(manifest.get("scope", []))
        # Restore findings.
        self._restore_passive(manifest.get("passive_findings", []))
        self._restore_active(manifest.get("active_findings", []))
        # Restore active-scan authorization (operator is resuming their own work).
        if restore_authorization and manifest.get("active_authorized"):
            self.active.authorize_scope(set(manifest.get("active_scope", [])))
        else:
            self.active.scope_hosts = set(manifest.get("active_scope", []))

        self.current = slug
        out = self._summary(manifest)
        out["imported_flows"] = imported
        return out

    def _restore_passive(self, items) -> None:
        from modules.passive_scanner import Finding
        existing = {(f.check, f.title, f.url) for f in self.passive.findings}
        for it in items:
            key = (it.get("check", ""), it.get("title", ""), it.get("url", ""))
            if key in existing:
                continue
            self.passive.findings.append(Finding(
                it.get("severity", "info"), it.get("title", ""),
                it.get("detail", ""), it.get("flow_id", ""),
                it.get("url", ""), it.get("check", "")))

    def _restore_active(self, items) -> None:
        from modules.active_scan import ActiveFinding
        existing = {(f.check, f.title, f.point, f.url) for f in self.active.findings}
        for it in items:
            key = (it.get("check", ""), it.get("title", ""),
                   it.get("point", ""), it.get("url", ""))
            if key in existing:
                continue
            self.active.findings.append(ActiveFinding(
                it.get("severity", "info"), it.get("title", ""),
                it.get("detail", ""), it.get("url", ""), it.get("check", ""),
                confidence=it.get("confidence", "firm"),
                issue_key=it.get("issue_key", ""), point=it.get("point", ""),
                evidence=it.get("evidence", ""), payload=it.get("payload", "")))

    # ---------------------------------------------------------------- list

    def list(self) -> list:
        out = []
        for mf in sorted(self.dir.glob("*.json")):
            try:
                m = json.loads(mf.read_text())
            except Exception:
                continue
            out.append(self._summary(m))
        return sorted(out, key=lambda p: p["saved_at"], reverse=True)

    def delete(self, name: str) -> bool:
        slug = _slug(name)
        found = False
        for p in (self._db_file(slug), self._manifest_file(slug)):
            if p.exists():
                p.unlink()
                found = True
        if self.current == slug:
            self.current = None
        return found

    def _summary(self, m: dict) -> dict:
        return {
            "name": m.get("name", ""),
            "slug": m.get("slug", ""),
            "note": m.get("note", ""),
            "saved_at": m.get("saved_at", 0),
            "flows": m.get("flows", 0),
            "scope": m.get("scope", []),
            "passive_count": len(m.get("passive_findings", [])),
            "active_count": len(m.get("active_findings", [])),
            "current": m.get("slug") == self.current,
        }
