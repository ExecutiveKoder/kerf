"""
HTTP history: an Addon that records every completed flow to SQLite and serves
search/filter queries for the UI.

Stores request/response metadata plus raw bytes so flows can be replayed in
Repeater or re-examined later. Scope filtering is applied at query time.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from core.interceptor import BaseAddon
from core.http_message import Flow


class HistoryStore(BaseAddon):
    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._local = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self._db_path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            self._local.conn = c
        return c

    def _init_schema(self) -> None:
        c = self._conn()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS flows (
                id TEXT PRIMARY KEY,
                timestamp REAL,
                method TEXT,
                host TEXT,
                path TEXT,
                url TEXT,
                status INTEGER,
                mime TEXT,
                req_length INTEGER,
                resp_length INTEGER,
                duration_ms REAL,
                req_raw BLOB,
                resp_raw BLOB,
                notes TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_host ON flows(host);
            CREATE INDEX IF NOT EXISTS idx_ts ON flows(timestamp);
            """
        )
        c.commit()

    # ---------------------------------------------------------- Addon hook

    async def on_flow_complete(self, flow: Flow) -> None:
        self.record(flow)

    def record(self, flow: Flow) -> None:
        req = flow.request
        resp = flow.response
        c = self._conn()
        c.execute(
            """INSERT OR REPLACE INTO flows
               (id,timestamp,method,host,path,url,status,mime,
                req_length,resp_length,duration_ms,req_raw,resp_raw,notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                flow.id,
                flow.timestamp,
                req.method,
                req.host,
                req.path,
                req.url,
                resp.status_code if resp else None,
                resp.content_type if resp else "",
                len(req.body),
                len(resp.body) if resp else 0,
                flow.duration_ms,
                req.raw(),
                resp.raw() if resp else b"",
                json.dumps(flow.notes),
            ),
        )
        c.commit()

    # ------------------------------------------------------------- queries

    def list(self, *, host: str | None = None, method: str | None = None,
             status: int | None = None, search: str | None = None,
             mime_contains: str | None = None, hide_noise: bool = False,
             status_class: int | None = None, path_prefix: str | None = None,
             limit: int = 500) -> list[dict]:
        sql = "SELECT * FROM flows WHERE 1=1"
        args: list = []
        if host:
            sql += " AND (host = ? OR host LIKE ?)"; args += [host, f"%{host}%"]
        if method:
            sql += " AND method = ?"; args.append(method.upper())
        if status:
            sql += " AND status = ?"; args.append(status)
        if status_class:
            sql += " AND status >= ? AND status < ?"; args += [status_class * 100, status_class * 100 + 100]
        if mime_contains:
            sql += " AND mime LIKE ?"; args.append(f"%{mime_contains}%")
        if path_prefix:
            sql += " AND path LIKE ?"; args.append(f"{path_prefix}%")
        if hide_noise:
            sql += (
                " AND IFNULL(status,0) != 404"
                " AND IFNULL(mime,'') NOT LIKE 'image/%'"
                " AND IFNULL(mime,'') NOT LIKE 'font/%'"
                " AND IFNULL(mime,'') NOT LIKE 'text/css%'"
                " AND IFNULL(mime,'') NOT LIKE '%javascript%'"
                " AND path NOT LIKE '%.js%'"
                " AND path NOT LIKE '%.css%'"
                " AND path NOT LIKE '%.woff%'"
                " AND path NOT LIKE '%.png%'"
                " AND path NOT LIKE '%.jpg%'"
                " AND path NOT LIKE '%.ico%'"
                " AND path NOT LIKE '%.map'"
            )
        if search:
            sql += " AND (url LIKE ? OR req_raw LIKE ? OR resp_raw LIKE ?)"
            like = f"%{search}%"
            args += [like, like.encode(), like.encode()]
        sql += " ORDER BY timestamp DESC LIMIT ?"; args.append(limit)
        rows = self._conn().execute(sql, args).fetchall()
        return [self._row_summary(r) for r in rows]

    def sitemap(self) -> list:
        rows = self._conn().execute(
            """SELECT host, path, COUNT(*) AS n, MAX(timestamp) AS ts
               FROM flows GROUP BY host, path ORDER BY host, path"""
        ).fetchall()
        tree: dict = {}
        for r in rows:
            host = r["host"] or ""
            bucket = tree.setdefault(host, {"host": host, "count": 0, "paths": []})
            bucket["count"] += r["n"]
            bucket["paths"].append({"path": r["path"], "count": r["n"], "ts": r["ts"]})
        return sorted(
            (h for h in tree.values() if h["host"]),
            key=lambda h: (-h["count"], h["host"]))

    def get(self, flow_id: str) -> dict | None:
        r = self._conn().execute("SELECT * FROM flows WHERE id=?", (flow_id,)).fetchone()
        if not r:
            return None
        d = self._row_summary(r)
        d["req_raw"] = (r["req_raw"] or b"").decode("latin-1")
        d["resp_raw"] = (r["resp_raw"] or b"").decode("latin-1")
        return d

    def _row_summary(self, r: sqlite3.Row) -> dict:
        return {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "method": r["method"],
            "host": r["host"],
            "path": r["path"],
            "url": r["url"],
            "status": r["status"],
            "mime": r["mime"],
            "req_length": r["req_length"],
            "resp_length": r["resp_length"],
            "duration_ms": r["duration_ms"],
            "notes": json.loads(r["notes"] or "[]"),
        }

    def clear(self) -> None:
        c = self._conn()
        c.execute("DELETE FROM flows")
        c.commit()

    def count(self) -> int:
        return self._conn().execute("SELECT COUNT(*) FROM flows").fetchone()[0]

    # ----------------------------------------------------------- projects

    def export_to(self, path: str | Path) -> None:
        """Back up the live flow database to `path` (cross-platform, safe copy)."""
        dest = sqlite3.connect(str(path))
        try:
            self._conn().backup(dest)
        finally:
            dest.close()

    def import_from(self, path: str | Path) -> int:
        """Merge flows from a project database file into the live database."""
        c = self._conn()
        before = self.count()
        c.execute("ATTACH DATABASE ? AS proj", (str(path),))
        try:
            c.execute("INSERT OR REPLACE INTO flows SELECT * FROM proj.flows")
            c.commit()
        finally:
            c.execute("DETACH DATABASE proj")
        return self.count() - before
