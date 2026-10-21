"""Personal-use attestation lock. No signed key."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import license as lic
from modules.brand import ACCOUNTS_EMAIL, ATTESTATION, ATTEST_VERSION, COPYRIGHT, LICENSE_NAME


def _home():
    home = tempfile.mkdtemp(prefix="kerf-lic-")
    os.environ["DASTDAY_HOME"] = home
    return home


def test_locked_until_attest():
    _home()
    store = lic.LicenseStore()
    assert store.unlocked is False
    assert store.public()["locked"] is True
    assert store.public()["accounts"] == ACCOUNTS_EMAIL
    assert not store.allows("anything")
    try:
        store.activate("", attest=False)
        raise AssertionError("unlocked without attestation")
    except ValueError as exc:
        assert "license" in str(exc).lower()
        assert ACCOUNTS_EMAIL in str(exc)
    pub = store.attest()
    assert pub["licensed"] is True
    assert pub["locked"] is False
    assert pub["label"] == "Personal"
    assert pub["attestation"] == ATTESTATION
    assert pub["copyright"] == COPYRIGHT
    assert store.allows("vault")
    store.clear()
    assert store.unlocked is False


def test_attest_persists():
    home = _home()
    store = lic.LicenseStore()
    store.attest()
    path = Path(home) / "license.attest"
    assert path.exists()
    data = __import__("json").loads(path.read_text())
    assert data["v"] == ATTEST_VERSION
    assert data["accepted"] is True
    assert data["license"] == LICENSE_NAME
    again = lic.LicenseStore()
    assert again.unlocked is True


def test_old_attest_without_accept_stays_locked():
    home = _home()
    path = Path(home) / "license.attest"
    path.write_text('{"v":1,"attested":true,"use":"personal"}')
    store = lic.LicenseStore()
    assert store.unlocked is False


if __name__ == "__main__":
    test_locked_until_attest()
    test_attest_persists()
    test_old_attest_without_accept_stays_locked()
    print("license tests ok")
