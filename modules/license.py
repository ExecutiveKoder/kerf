"""
Personal-use attestation for Kerf.

No signed key. The operator checks a box; we store that locally and unlock
every feature. The LICENSE forbids commercial use and redistribution —
commercial licenses are sold via accounts@kerf.software.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from modules.brand import (
    ACCOUNTS_EMAIL, ATTESTATION, ATTEST_VERSION, COPYRIGHT, LICENSE_NAME,
    LICENSE_TERMS,
)


def can_issue() -> bool:
    return False

ATTEST_REQUIRED = (
    "accept the Kerf Personal Use License to unlock "
    "(no commercial use, no redistribution). "
    f"For a commercial license, email {ACCOUNTS_EMAIL}."
)


def _home() -> Path:
    return Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))


def _attest_path() -> Path:
    return _home() / "license.attest"


class LicenseStore:
    def __init__(self) -> None:
        self._error = ""
        self._attested = False
        self._attest_at = 0
        self._load()

    @property
    def unlocked(self) -> bool:
        return self._attested and not self._error

    def _load(self) -> None:
        self._attested = False
        self._attest_at = 0
        self._error = ""
        path = _attest_path()
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
        except Exception as exc:
            self._error = str(exc)
            return
        if not isinstance(data, dict) or not data.get("attested"):
            return
        if int(data.get("v") or 0) < ATTEST_VERSION or not data.get("accepted"):
            return
        self._attested = True
        self._attest_at = int(data.get("at") or 0)

    def attest(self) -> dict:
        now = int(time.time())
        path = _attest_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "v": ATTEST_VERSION,
            "attested": True,
            "accepted": True,
            "use": "personal",
            "license": LICENSE_NAME,
            "text": ATTESTATION,
            "at": now,
        }, indent=2))
        self._attested = True
        self._attest_at = now
        self._error = ""
        return self.public()

    def install(self, token: str = "", *, attest: bool = False,
                persist: bool = True) -> dict:
        return self.activate(token, attest=attest, persist=persist)

    def activate(self, token: str = "", *, attest: bool = False,
                 persist: bool = True) -> dict:
        if not attest:
            raise ValueError(ATTEST_REQUIRED)
        return self.attest()

    def clear(self) -> dict:
        self._error = ""
        self._attested = False
        self._attest_at = 0
        path = _attest_path()
        if path.exists():
            path.unlink()
        return self.public()

    def allows(self, feature: str = "") -> bool:
        return self.unlocked

    def public(self) -> dict:
        unlocked = self.unlocked
        return {
            "plan": "personal" if unlocked else "",
            "use": "personal" if unlocked else "",
            "label": "Personal" if unlocked else "Locked",
            "email": "",
            "seats": 0,
            "expires": 0,
            "licensed": unlocked,
            "locked": not unlocked,
            "attested": self._attested,
            "needs_attest": not self._attested,
            "attestation": ATTESTATION,
            "license_name": LICENSE_NAME,
            "copyright": COPYRIGHT,
            "terms": list(LICENSE_TERMS),
            "license_url": "/LICENSE",
            "accounts": ACCOUNTS_EMAIL,
            "error": self._error,
        }
