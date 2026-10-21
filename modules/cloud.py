"""
Hosted extras (vault, OAST, AI, lockfile watch).

All of these are open once personal use is attested. This module
stores endpoints and can push an encrypted pack to the vault.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import zipfile
from io import BytesIO
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from modules.brand import NAME
from modules.projects import _slug

def _home() -> Path:
    return Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))


def _settings_path() -> Path:
    return _home() / "cloud.json"


def _default() -> dict:
    return {
        "hosted_oast": "",
        "hosted_ai_url": "",
        "hosted_ai_key": "",
        "vault_url": "",
        "vault_token": "",
        "sca_watch_path": "",
    }


class CloudSettings:
    def __init__(self, license_store) -> None:
        self.license = license_store
        self._settings = self._load()

    def _load(self) -> dict:
        s = _default()
        try:
            path = _settings_path()
            if path.exists():
                data = json.loads(path.read_text())
                if isinstance(data, dict):
                    s.update({k: data.get(k, s[k]) for k in s})
        except Exception:
            pass
        return s

    def _save(self) -> None:
        path = _settings_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._settings, indent=2))

    def public(self) -> dict:
        s = dict(self._settings)
        if s.get("hosted_ai_key"):
            s["hosted_ai_key"] = "••••"
        if s.get("vault_token"):
            s["vault_token"] = "••••"
        open_ = self.license.unlocked
        s["can"] = {
            "shared": open_,
            "vault": open_,
            "oast": open_,
            "ai": open_,
            "sca_watch": open_,
        }
        return s

    def configure(self, patch: dict) -> dict:
        for k in _default():
            if k not in patch or patch[k] is None:
                continue
            if k in ("hosted_ai_key", "vault_token") and "•" in str(patch[k]):
                continue
            self._settings[k] = str(patch[k]).strip()
        self._save()
        return self.public()

    def require(self, feature: str = "") -> None:
        if not self.license.unlocked:
            raise PermissionError(
                f"{NAME} is locked. Attest personal use under Setup → License.")

    def team_pack(self, projects, name: str) -> bytes:
        slug = _slug(name.strip() or projects.current or "project")
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            db = projects._db_file(slug)
            mf = projects._manifest_file(slug)
            if db.exists():
                zf.write(db, f"{slug}.db")
            if mf.exists():
                zf.write(mf, f"{slug}.json")
            zf.writestr("kerf-team.json", json.dumps({
                "product": NAME,
                "project": slug,
                "exported_at": time.time(),
                "org": self.license.public().get("email") or "",
            }, indent=2))
        return buf.getvalue()

    async def vault_put(self, projects, name: str) -> dict:
        self.require()
        url = self._settings.get("vault_url") or ""
        if not url:
            raise ValueError("Set a vault URL under Setup → License.")
        pack = self.team_pack(projects, name)
        key = hashlib.sha256(
            (self._settings.get("vault_token") or "kerf").encode()).digest()
        aes = AESGCM(key)
        nonce = os.urandom(12)
        blob = nonce + aes.encrypt(nonce, pack, b"kerf-vault")
        import httpx
        headers = {}
        if self._settings.get("vault_token"):
            headers["Authorization"] = "Bearer " + self._settings["vault_token"]
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(url, content=blob, headers=headers)
            r.raise_for_status()
        return {"ok": True, "bytes": len(blob), "status": r.status_code}

    def hosted_oast_url(self) -> str:
        if not self.license.unlocked:
            return ""
        return self._settings.get("hosted_oast") or ""
