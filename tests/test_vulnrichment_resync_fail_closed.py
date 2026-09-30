"""A full Vulnrichment resync aborts on any per-file read or JSON error.

An incomplete clone read must not replace the DB or advance
last_commit_sha; update() returns False so the step fails. The git clone is
replaced by a prepared directory; nothing touches the network.
"""
import json
import subprocess

import pytest

import tip.core.vulnrichment_processor as vr_mod
from tip.core.vulnrichment_processor import VulnrichmentProcessor

OLD_SHA = "a" * 40
NEW_SHA = "c" * 40


def _enrichment_json(cve_id):
    return {"containers": {"adp": [{
        "providerMetadata": {"orgId": vr_mod.CISA_ADP_ORG_ID},
        "metrics": [{"other": {"type": "ssvc", "content": {"id": cve_id, "options": [
            {"Exploitation": "active"}, {"Automatable": "no"}, {"Technical Impact": "partial"},
        ]}}}],
    }]}}


def _bad_json(path):
    path.write_text('{"containers": ')


def _bad_utf8(path):
    path.write_bytes(b'{"containers": "\xff\xfe"}')


def _unreadable(path):
    path.mkdir()  # open() raises IsADirectoryError


@pytest.fixture
def resync_env(tmp_path, monkeypatch):
    db = tmp_path / "vulnrichment_db.json"
    state = tmp_path / "vulnrichment_state.json"
    db.write_text(json.dumps({f"CVE-2020-000{i}": {"ssvcExploitStatus": "none"} for i in range(1, 4)}))
    proc = VulnrichmentProcessor()
    proc.db_path = str(db)
    proc.state_path = str(state)

    clone = tmp_path / "_vulnrichment_clone" / "2024" / "1xxx"
    clone.mkdir(parents=True)
    for i in range(5):
        cid = f"CVE-2024-100{i}"
        (clone / f"{cid}.json").write_text(json.dumps(_enrichment_json(cid)))

    def fake_run(args, **kwargs):
        if "clone" in args:
            return subprocess.CompletedProcess(args, 0, "", "")
        if "rev-parse" in args:
            return subprocess.CompletedProcess(args, 0, NEW_SHA + "\n", "")
        raise AssertionError(args)

    monkeypatch.setattr(vr_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(vr_mod.requests, "get",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network")))
    return proc, db, state, clone


@pytest.mark.parametrize("corrupt", [_bad_json, _bad_utf8, _unreadable])
def test_bootstrap_aborts_on_bad_file(resync_env, corrupt):
    proc, db, state, clone = resync_env
    corrupt(clone / "CVE-2024-1999.json")
    before = db.read_bytes()

    assert proc.update() is False
    assert db.read_bytes() == before
    assert not state.exists()


@pytest.mark.parametrize("corrupt", [_bad_json, _unreadable])
def test_resync_from_incremental_aborts_on_bad_file(resync_env, corrupt, monkeypatch):
    """An incremental run whose DB is unreadable falls back to resync; a bad
    clone file there must not advance the stored sha either."""
    proc, db, state, clone = resync_env
    state.write_text(json.dumps({"last_commit_sha": OLD_SHA}))
    monkeypatch.setattr(VulnrichmentProcessor, "load", lambda self: False)
    corrupt(clone / "CVE-2024-1999.json")
    before_db, before_state = db.read_bytes(), state.read_bytes()

    assert proc.update() is False
    assert db.read_bytes() == before_db
    assert state.read_bytes() == before_state


def test_clean_bootstrap_writes_and_advances(resync_env):
    proc, db, state, clone = resync_env

    assert proc.update() is True
    assert sorted(json.loads(db.read_text())) == [f"CVE-2024-100{i}" for i in range(5)]
    assert json.loads(state.read_text()) == {"last_commit_sha": NEW_SHA}


def _flaky_clone(monkeypatch, clone, failures):
    """git clone exits 128 `failures` times, then recreates the checkout."""
    files = {p.name: p.read_text() for p in clone.iterdir()}
    clones = {"n": 0}

    def fake_run(args, **kwargs):
        if "clone" in args:
            clones["n"] += 1
            root = clone.parent.parent  # the _vulnrichment_clone directory
            if clones["n"] > 1:
                # Each retry starts from an empty directory.
                assert not root.exists() or not any(root.iterdir())
            if clones["n"] <= failures:
                root.mkdir(parents=True, exist_ok=True)
                (root / "partial.pack").write_text("half a checkout")
                raise subprocess.CalledProcessError(128, args, "", "reset by peer")
            clone.mkdir(parents=True, exist_ok=True)
            for name, text in files.items():
                (clone / name).write_text(text)
            return subprocess.CompletedProcess(args, 0, "", "")
        if "rev-parse" in args:
            return subprocess.CompletedProcess(args, 0, NEW_SHA + "\n", "")
        raise AssertionError(args)

    monkeypatch.setattr(vr_mod.subprocess, "run", fake_run)
    return clones


def test_clone_failing_once_is_retried(resync_env, monkeypatch):
    proc, db, state, clone = resync_env
    clones = _flaky_clone(monkeypatch, clone, failures=1)

    assert proc.update() is True
    assert clones["n"] == 2
    assert json.loads(state.read_text()) == {"last_commit_sha": NEW_SHA}


def test_clone_failing_twice_keeps_everything(resync_env, monkeypatch):
    proc, db, state, clone = resync_env
    before = db.read_bytes()
    clones = _flaky_clone(monkeypatch, clone, failures=2)

    assert proc.update() is False
    assert clones["n"] == 2
    assert db.read_bytes() == before
    assert not state.exists()
