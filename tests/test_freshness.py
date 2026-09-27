"""I16 F1: freshness.json records each source's last successful update.

A step that succeeds advances its source; a step that fails, degrades or runs
partial leaves that source's entry exactly as it was, even inside a run where
other sources succeeded. Nothing here touches the network.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests

from tip.core import pipeline_orchestrator as po
from tip.utils import freshness as fr

OLD = datetime(2026, 9, 1, 6, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 9, 26, 6, 30, tzinfo=timezone.utc)
OLD_ISO = "2026-09-01T06:00:00Z"
NOW_ISO = "2026-09-26T06:30:00Z"

ALL_DB_OK = {
    "capec": True, "cwe": True, "techniques": True, "defend": True,
    "kev": True, "vulnrichment": True, "groups": True, "epss": True,
}


def _full_results(**overrides):
    results = {
        "database_updates": {"status": "success", "results": dict(ALL_DB_OK)},
        "cve_retrieval": {"status": "success"},
        "cve_processing": {"status": "success"},
        "campaigns": {"status": "success"},
        "entity_index": {"status": "success"},
        "epss_curated": {"status": "success"},
    }
    results.update(overrides)
    return results


def _seed(path: Path) -> None:
    fr.record_freshness(_full_results(), path, now=OLD)


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_sources_cover_the_isa_list():
    """ISC-2: NVD shards, entity index, KEV, Vulnrichment, EPSS, CWE, CAPEC,
    ATT&CK, D3FEND."""
    assert set(fr.SOURCES) == {
        "nvd", "entity_index", "kev", "vulnrichment", "epss",
        "cwe", "capec", "attack", "d3fend",
    }


def test_full_success_records_every_source(tmp_path):
    path = tmp_path / "freshness.json"
    advanced = fr.record_freshness(_full_results(), path, now=NOW)
    assert set(advanced) == set(fr.SOURCES)
    data = _load(path)
    for key, entry in data["sources"].items():
        assert entry["last_success"] == NOW_ISO
        assert entry["cadence_hours"] == fr.SOURCES[key].cadence_hours
        assert entry["stale_after_hours"] in (36, 192)
        assert entry["label"]
    assert data["sources"]["nvd"]["stale_after_hours"] == 192
    assert data["sources"]["kev"]["stale_after_hours"] == 36


# Each case: results overrides that fail exactly one source, and that source.
DB_FAILURES = [
    ("capec", "capec"), ("cwe", "cwe"), ("defend", "d3fend"), ("kev", "kev"),
    ("vulnrichment", "vulnrichment"), ("epss", "epss"),
    ("techniques", "attack"), ("groups", "attack"),
]


@pytest.mark.parametrize("db, source", DB_FAILURES)
def test_failed_database_step_leaves_only_its_source(tmp_path, db, source):
    path = tmp_path / "freshness.json"
    _seed(path)
    dbs = dict(ALL_DB_OK, **{db: False})
    fr.record_freshness(
        _full_results(database_updates={"status": "partial", "results": dbs}),
        path, now=NOW,
    )
    sources = _load(path)["sources"]
    assert sources[source]["last_success"] == OLD_ISO
    for other, entry in sources.items():
        if other != source:
            assert entry["last_success"] == NOW_ISO, other


@pytest.mark.parametrize("overrides", [
    {"cve_retrieval": {"status": "degraded"}},
    {"cve_retrieval": {"status": "partial"}},      # resumed fetch
    {"cve_retrieval": {"status": "failed"}},
    {"cve_processing": {"status": "failed"}},
    {"cve_processing": {"status": "partial"}},     # written without EPSS
])
def test_unclean_nvd_step_does_not_advance_nvd(tmp_path, overrides):
    path = tmp_path / "freshness.json"
    _seed(path)
    fr.record_freshness(_full_results(**overrides), path, now=NOW)
    sources = _load(path)["sources"]
    assert sources["nvd"]["last_success"] == OLD_ISO
    assert sources["kev"]["last_success"] == NOW_ISO


def test_nvd_with_no_new_cves_counts_as_success(tmp_path):
    """Retrieval succeeded with nothing new, so processing never ran."""
    path = tmp_path / "freshness.json"
    results = _full_results()
    del results["cve_processing"]
    fr.record_freshness(results, path, now=NOW)
    assert _load(path)["sources"]["nvd"]["last_success"] == NOW_ISO


def test_failed_entity_index_does_not_advance(tmp_path):
    path = tmp_path / "freshness.json"
    _seed(path)
    fr.record_freshness(_full_results(entity_index={"status": "failed"}), path, now=NOW)
    assert _load(path)["sources"]["entity_index"]["last_success"] == OLD_ISO


def test_failed_epss_curated_refresh_does_not_advance_epss(tmp_path):
    path = tmp_path / "freshness.json"
    _seed(path)
    fr.record_freshness(_full_results(epss_curated={"status": "failed"}), path, now=NOW)
    assert _load(path)["sources"]["epss"]["last_success"] == OLD_ISO


def test_db_only_run_leaves_weekly_sources_untouched(tmp_path):
    path = tmp_path / "freshness.json"
    _seed(path)
    fr.record_freshness(
        {"database_updates": {"status": "success", "results": dict(ALL_DB_OK)}},
        path, now=NOW,
    )
    sources = _load(path)["sources"]
    assert sources["nvd"]["last_success"] == OLD_ISO
    assert sources["entity_index"]["last_success"] == OLD_ISO
    assert sources["kev"]["last_success"] == NOW_ISO


def test_nothing_advanced_leaves_file_byte_identical(tmp_path):
    path = tmp_path / "freshness.json"
    _seed(path)
    before = path.read_bytes()
    dbs = {k: False for k in ALL_DB_OK}
    advanced = fr.record_freshness(
        {"database_updates": {"status": "partial", "results": dbs}}, path, now=NOW,
    )
    assert advanced == []
    assert path.read_bytes() == before


def test_empty_results_writes_nothing(tmp_path):
    path = tmp_path / "freshness.json"
    assert fr.record_freshness({}, path, now=NOW) == []
    assert not path.exists()


@pytest.mark.parametrize("garbage", ["", "not json", "[]", '{"sources": 5}',
                                     '{"sources": {"kev": "x"}}'])
def test_malformed_existing_file_is_replaced(tmp_path, garbage):
    path = tmp_path / "freshness.json"
    path.write_text(garbage)
    fr.record_freshness(_full_results(), path, now=NOW)
    assert _load(path)["sources"]["kev"]["last_success"] == NOW_ISO


def test_unknown_existing_entries_are_kept(tmp_path):
    """Additive format: an entry this version does not know survives."""
    path = tmp_path / "freshness.json"
    path.write_text(json.dumps({"sources": {"future": {"last_success": OLD_ISO}}}))
    fr.record_freshness(_full_results(), path, now=NOW)
    assert _load(path)["sources"]["future"] == {"last_success": OLD_ISO}


def test_write_is_atomic(tmp_path, monkeypatch):
    """A failure mid-write keeps the previous file."""
    path = tmp_path / "freshness.json"
    _seed(path)
    before = path.read_bytes()

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(fr, "atomic_write_text", boom)
    with pytest.raises(OSError):
        fr.record_freshness(_full_results(), path, now=NOW)
    assert path.read_bytes() == before


# Through the real orchestrator: the per-source rule holds inside a partial run.

@pytest.fixture
def offline_orchestrator(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def _blocked(*_a, **_k):
        raise requests.exceptions.ConnectionError("network blocked in unit tests")

    monkeypatch.setattr(requests, "get", _blocked)
    return po.PipelineOrchestrator(), tmp_path / "docs" / "data" / "freshness.json"


def test_partial_db_run_records_only_successes(offline_orchestrator, monkeypatch):
    orch, path = offline_orchestrator
    monkeypatch.setattr(orch.db_manager, "update_all_databases",
                        lambda: dict(ALL_DB_OK, kev=False))
    summary = orch.run_database_updates_only()
    assert po.exit_code_for(summary) == 1
    sources = _load(path)["sources"]
    assert "kev" not in sources
    assert "capec" in sources and "epss" in sources
    assert "nvd" not in sources


def test_freshness_write_failure_does_not_fail_the_run(offline_orchestrator, monkeypatch):
    orch, path = offline_orchestrator
    monkeypatch.setattr(orch.db_manager, "update_all_databases", lambda: dict(ALL_DB_OK))

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(po, "record_freshness", boom)
    summary = orch.run_database_updates_only()
    assert po.exit_code_for(summary) == 0
