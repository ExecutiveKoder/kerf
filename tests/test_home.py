"""~/.kerf is the on-disk home. An existing ~/.dastday is renamed once."""

import os

from modules import home


def test_default_home_is_dot_kerf(monkeypatch, tmp_path):
    monkeypatch.delenv("KERF_HOME", raising=False)
    monkeypatch.setattr(home.Path, "home", lambda: tmp_path)
    assert home.kerf_home() == tmp_path / ".kerf"


def test_kerf_home_env_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("KERF_HOME", str(tmp_path / "custom"))
    assert home.kerf_home() == tmp_path / "custom"


def test_adopt_legacy_renames_once(monkeypatch, tmp_path):
    monkeypatch.delenv("KERF_HOME", raising=False)
    monkeypatch.setattr(home.Path, "home", lambda: tmp_path)
    legacy = tmp_path / ".dastday"
    legacy.mkdir()
    (legacy / "license.attest").write_text("ok")
    home.adopt_legacy()
    assert (tmp_path / ".kerf" / "license.attest").read_text() == "ok"
    assert not legacy.exists()
    assert "KERF_HOME" not in os.environ


def test_adopt_legacy_does_not_clobber(monkeypatch, tmp_path):
    monkeypatch.delenv("KERF_HOME", raising=False)
    monkeypatch.setattr(home.Path, "home", lambda: tmp_path)
    legacy = tmp_path / ".dastday"
    current = tmp_path / ".kerf"
    legacy.mkdir()
    current.mkdir()
    (legacy / "license.attest").write_text("old")
    (current / "license.attest").write_text("new")
    home.adopt_legacy()
    assert (current / "license.attest").read_text() == "new"
    assert (legacy / "license.attest").read_text() == "old"


def test_adopt_db_renames_history(tmp_path):
    legacy = tmp_path / "dastday.db"
    legacy.write_text("history")
    (tmp_path / "dastday.db-wal").write_text("wal")
    moved = home.adopt_db(tmp_path / "kerf.db")
    assert moved == tmp_path / "kerf.db"
    assert moved.read_text() == "history"
    assert (tmp_path / "kerf.db-wal").read_text() == "wal"
    assert not legacy.exists()
    assert home.adopt_db(moved) == moved
