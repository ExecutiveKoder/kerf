"""On-disk home for Kerf. Default is ~/.kerf. KERF_HOME overrides it."""

from __future__ import annotations

import os
from pathlib import Path


def kerf_home() -> Path:
    override = os.environ.get("KERF_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".kerf"


def adopt_legacy() -> None:
    """Move ~/.dastday to ~/.kerf once, when the process is using the default home.

    If the rename fails, keep reading the old directory for this process.
    """
    if os.environ.get("KERF_HOME"):
        return
    path = Path.home() / ".kerf"
    legacy = Path.home() / ".dastday"
    if path.exists() or not legacy.is_dir():
        return
    try:
        legacy.rename(path)
    except OSError:
        os.environ["KERF_HOME"] = str(legacy)


def adopt_db(path: str | Path) -> Path:
    """Open kerf.db. If that file is missing and dastday.db is beside it, rename it."""
    target = Path(path)
    if target.exists() or target.name != "kerf.db":
        return target
    legacy = target.with_name("dastday.db")
    if not legacy.exists():
        return target
    sidecars = []
    for suffix in ("-wal", "-shm", "-journal"):
        side = Path(str(legacy) + suffix)
        if side.exists():
            sidecars.append((side, Path(str(target) + suffix)))
    try:
        legacy.rename(target)
    except OSError:
        return legacy
    for src, dst in sidecars:
        try:
            src.rename(dst)
        except OSError:
            pass
    return target
