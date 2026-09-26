"""F3 and F9: atomic, lossless, deterministic published writes
(ISC-17 to ISC-20, ISC-56).
"""
import gzip
import json
import os

import pytest

import tip.utils.atomic_io as aio
from tip.database.database_optimizer import JSONLManager, ShardCorruptError


def _shard(path, records):
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for k, v in records.items():
            f.write(json.dumps({k: v}) + "\n")


def _no_temps(directory):
    return [p.name for p in directory.iterdir() if p.name.endswith(".tmp")] == []


# ISC-17 ----------------------------------------------------------------------

def test_exception_mid_write_leaves_previous_bytes(tmp_path, monkeypatch):
    target = tmp_path / "CVE-2024.jsonl.gz"
    _shard(target, {"CVE-2024-0001": {"CWE": ["CWE-79"]}})
    before = target.read_bytes()

    def failing_fsync(_fd):
        raise OSError("disk full")

    monkeypatch.setattr(aio.os, "fsync", failing_fsync)
    with pytest.raises(OSError):
        JSONLManager().save_jsonl_incremental(str(tmp_path / "CVE-2024.jsonl"),
                                              {"CVE-2024-0002": {"CWE": []}})
    assert target.read_bytes() == before
    assert _no_temps(tmp_path)


def test_reference_db_serialization_failure_leaves_previous_bytes(tmp_path):
    target = tmp_path / "kev_db.json"
    target.write_text(json.dumps({"CVE-1": {}}))
    before = target.read_bytes()
    with pytest.raises(TypeError):
        aio.write_reference_db(target, {"CVE-1": {}, "CVE-2": {1, 2}})  # set is not JSON
    assert target.read_bytes() == before
    assert _no_temps(tmp_path)


# ISC-18 ----------------------------------------------------------------------

def test_malformed_line_fails_save_loudly(tmp_path):
    target = tmp_path / "CVE-2024.jsonl.gz"
    with gzip.open(target, "wt", encoding="utf-8") as f:
        f.write(json.dumps({"CVE-2024-0001": {}}) + "\n")
        f.write('{"CVE-2024-0002": {"CWE": [\n')  # torn line
        f.write(json.dumps({"CVE-2024-0003": {}}) + "\n")
    before = target.read_bytes()

    with pytest.raises(ShardCorruptError, match=r"CVE-2024\.jsonl\.gz.*line 2"):
        JSONLManager().save_jsonl_incremental(str(tmp_path / "CVE-2024.jsonl"),
                                              {"CVE-2024-0004": {}})
    assert target.read_bytes() == before


# ISC-19 ----------------------------------------------------------------------

def test_truncated_gzip_names_the_file(tmp_path):
    target = tmp_path / "CVE-2023.jsonl.gz"
    _shard(target, {f"CVE-2023-{i:04d}": {"CWE": ["CWE-79"] * 20} for i in range(200)})
    data = target.read_bytes()
    target.write_bytes(data[: len(data) // 2])

    with pytest.raises(ShardCorruptError, match="CVE-2023.jsonl.gz"):
        list(JSONLManager().read_jsonl(str(target)))


def test_generator_reports_truncated_shard_by_name(tmp_path):
    from tip.core.entity_index_generator import generate_entity_index
    db_dir = tmp_path / "docs" / "database"
    db_dir.mkdir(parents=True)
    (tmp_path / "docs" / "data").mkdir()
    target = db_dir / "CVE-2022.jsonl.gz"
    _shard(target, {f"CVE-2022-{i:04d}": {"CWE": ["CWE-79"] * 20} for i in range(200)})
    data = target.read_bytes()
    target.write_bytes(data[: len(data) // 2])

    with pytest.raises(ShardCorruptError, match="CVE-2022.jsonl.gz"):
        generate_entity_index(tmp_path)


# ISC-20 ----------------------------------------------------------------------

def _seed_indexes(out_dir):
    names = ("entity_index.json", "search_index.json", "cve_ids_index.json")
    for n in names:
        (out_dir / n).write_text(json.dumps({"old": n}))
    return {n: (out_dir / n).read_bytes() for n in names}


def test_index_write_is_all_or_nothing_on_serialization_failure(tmp_path):
    from tip.core.entity_index_generator import write_outputs
    before = _seed_indexes(tmp_path)
    with pytest.raises(TypeError):
        write_outputs({"new": 1}, {"new": 2}, tmp_path, {"bad": {1}}, out_dir=tmp_path)
    assert {n: (tmp_path / n).read_bytes() for n in before} == before


def test_index_write_is_all_or_nothing_on_temp_write_failure(tmp_path, monkeypatch):
    from tip.core.entity_index_generator import write_outputs
    before = _seed_indexes(tmp_path)
    real = aio._write_temp
    calls = {"n": 0}

    def flaky(path, data):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("disk full on the third file")
        return real(path, data)

    monkeypatch.setattr(aio, "_write_temp", flaky)
    with pytest.raises(OSError):
        write_outputs({"new": 1}, {"new": 2}, tmp_path, {"new": 3}, out_dir=tmp_path)
    assert {n: (tmp_path / n).read_bytes() for n in before} == before
    assert _no_temps(tmp_path)


def test_index_write_publishes_all_three(tmp_path):
    from tip.core.entity_index_generator import write_outputs
    _seed_indexes(tmp_path)
    write_outputs({"e": 1}, {"s": 2}, tmp_path, {"c": 3}, out_dir=tmp_path)
    assert json.loads((tmp_path / "entity_index.json").read_text()) == {"e": 1}
    assert json.loads((tmp_path / "search_index.json").read_text()) == {"s": 2}
    assert json.loads((tmp_path / "cve_ids_index.json").read_text()) == {"c": 3}


# ISC-56 ----------------------------------------------------------------------

def test_shard_rewrite_is_byte_identical(tmp_path, monkeypatch):
    mgr = JSONLManager()
    base = str(tmp_path / "CVE-2024.jsonl")
    records = {"CVE-2024-0002": {"CWE": ["CWE-79"]}, "CVE-2024-0001": {"CWE": []}}

    mgr.save_jsonl_incremental(base, records)
    first = (tmp_path / "CVE-2024.jsonl.gz").read_bytes()
    os.utime(tmp_path / "CVE-2024.jsonl.gz", (0, 0))
    monkeypatch.setattr("time.time", lambda: 2_000_000_000.0)  # a later clock
    mgr.save_jsonl_incremental(base, dict(reversed(list(records.items()))))
    second = (tmp_path / "CVE-2024.jsonl.gz").read_bytes()

    assert first == second
    # Header carries no mtime and no filename.
    assert first[4:8] == b"\x00\x00\x00\x00"
    assert first[3] & 0x08 == 0  # FNAME flag unset
    lines = gzip.decompress(first).decode().splitlines()
    assert [next(iter(json.loads(line))) for line in lines] == ["CVE-2024-0001", "CVE-2024-0002"]
