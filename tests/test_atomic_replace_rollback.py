"""atomic_replace_many rolls back when a replace fails partway.

A failure on the second os.replace must leave every target byte-identical to
before (or absent, if it did not exist), with no temp or backup files left.
"""
import os

import pytest

import tip.utils.atomic_io as aio

NAMES = ["entity_index.json", "search_index.json", "cve_ids_index.json"]


def _fail_nth_replace(monkeypatch, n):
    real = os.replace
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] == n:
            raise OSError(f"replace #{n} failed")
        return real(src, dst)

    monkeypatch.setattr(aio.os, "replace", flaky)
    return calls


def test_second_replace_failure_restores_all_targets(tmp_path, monkeypatch):
    for n in NAMES:
        (tmp_path / n).write_bytes(f"old {n}".encode())
    before = {n: (tmp_path / n).read_bytes() for n in NAMES}
    _fail_nth_replace(monkeypatch, 2)

    with pytest.raises(OSError, match="replace #2 failed"):
        aio.atomic_replace_many([(tmp_path / n, f"new {n}".encode()) for n in NAMES])

    assert {n: (tmp_path / n).read_bytes() for n in NAMES} == before
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(NAMES)


def test_rollback_removes_a_target_that_did_not_exist(tmp_path, monkeypatch):
    (tmp_path / NAMES[1]).write_bytes(b"old")
    (tmp_path / NAMES[2]).write_bytes(b"old")
    _fail_nth_replace(monkeypatch, 2)

    with pytest.raises(OSError):
        aio.atomic_replace_many([(tmp_path / n, b"new") for n in NAMES])

    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(NAMES[1:])
    assert (tmp_path / NAMES[1]).read_bytes() == b"old"


def test_success_publishes_all_and_leaves_no_backups(tmp_path):
    for n in NAMES:
        (tmp_path / n).write_bytes(b"old")
    aio.atomic_replace_many([(tmp_path / n, f"new {n}".encode()) for n in NAMES])
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == {n: f"new {n}".encode() for n in NAMES}
