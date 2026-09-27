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
    "ctid": True,
}


def _db(results, fresh=None):
    """A database_updates step. ``fresh`` names the steps that wrote fresh
    data; by default every step that succeeded did."""
    if fresh is None:
        fresh = [k for k, ok in results.items() if ok]
    status = "success" if all(results.values()) else "partial"
    return {"status": status, "results": dict(results), "fresh": sorted(fresh)}


def _full_results(**overrides):
    results = {
        "database_updates": _db(ALL_DB_OK),
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
    ATT&CK, D3FEND; I21 adds the CTID KEV mappings."""
    assert set(fr.SOURCES) == {
        "nvd", "entity_index", "kev", "vulnrichment", "epss",
        "cwe", "capec", "attack", "d3fend", "ctid",
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
    ("techniques", "attack"), ("groups", "attack"), ("ctid", "ctid"),
]


@pytest.mark.parametrize("db, source", DB_FAILURES)
def test_failed_database_step_leaves_only_its_source(tmp_path, db, source):
    path = tmp_path / "freshness.json"
    _seed(path)
    dbs = dict(ALL_DB_OK, **{db: False})
    fr.record_freshness(
        _full_results(database_updates=_db(dbs)),
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


@pytest.mark.parametrize("db, source", DB_FAILURES)
def test_step_that_wrote_nothing_fresh_does_not_advance(tmp_path, db, source):
    """A step can succeed without fresh data (processor skipped, existing
    file kept; D3FEND written without its ontology). It must not advance."""
    path = tmp_path / "freshness.json"
    _seed(path)
    fresh = [k for k in ALL_DB_OK if k != db]
    fr.record_freshness(_full_results(database_updates=_db(ALL_DB_OK, fresh)), path, now=NOW)
    sources = _load(path)["sources"]
    assert sources[source]["last_success"] == OLD_ISO
    assert sources["nvd"]["last_success"] == NOW_ISO


def test_database_step_without_fresh_list_advances_no_reference_source(tmp_path):
    """The fresh signal is explicit: no list, no reference-source advance."""
    path = tmp_path / "freshness.json"
    fr.record_freshness(
        {"database_updates": {"status": "success", "results": dict(ALL_DB_OK)}}, path, now=NOW,
    )
    assert not path.exists()


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
    fr.record_freshness({"database_updates": _db(ALL_DB_OK)}, path, now=NOW)
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
        {"database_updates": _db(dbs)}, path, now=NOW,
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
    def update_all():
        orch.db_manager.fresh_writes = {k for k in ALL_DB_OK if k != "kev"}
        return dict(ALL_DB_OK, kev=False)

    monkeypatch.setattr(orch.db_manager, "update_all_databases", update_all)
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


def test_orchestrator_reports_fresh_writes(offline_orchestrator, monkeypatch):
    orch, path = offline_orchestrator

    def update_all():
        orch.db_manager.fresh_writes = {"kev", "capec"}
        return dict(ALL_DB_OK)

    monkeypatch.setattr(orch.db_manager, "update_all_databases", update_all)
    orch.run_database_updates_only()
    assert orch.results["database_updates"]["fresh"] == ["capec", "kev"]
    assert set(_load(path)["sources"]) == {"kev", "capec"}


# DatabaseManager: which successful updates wrote fresh data.

@pytest.fixture
def manager(tmp_path, monkeypatch):
    from tip.core import database_manager as dm

    monkeypatch.chdir(tmp_path)
    techniques = tmp_path / "techniques_db.json"
    techniques.write_text(json.dumps({"T1001": {}}))
    real_path = dm.config.get_database_path
    monkeypatch.setattr(dm.config, "get_database_path",
                        lambda name: str(techniques) if name == "techniques" else real_path(name))
    m = dm.DatabaseManager()
    m.databases["defend"]["file"] = str(tmp_path / "defend_db.jsonl")
    m.databases["capec"]["file"] = str(tmp_path / "capec_db.json")
    return m, dm, techniques


class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


BINDINGS = {"off_to_def": {"results": {"bindings": [{
    "def_tech": {"value": "http://d3fend.mitre.org/ontologies/d3fend.owl#ExecutableAllowlisting"},
    "def_tech_label": {"value": "Executable Allowlisting"},
}]}}}
ONTOLOGY = {"@graph": [{"@id": "d3f:ExecutableAllowlisting", "d3f:d3fend-id": "D3-EAL"}]}


def _d3fend_get(ontology):
    def fake_get(url, timeout=None, **kw):
        if url.endswith("d3fend.json"):
            return ontology()
        return _Resp(200, BINDINGS)
    return fake_get


def _raise():
    raise requests.exceptions.ConnectionError("ontology down")


def test_d3fend_with_ontology_is_fresh(manager, monkeypatch):
    m, dm, _ = manager
    monkeypatch.setattr(dm.requests, "get", _d3fend_get(lambda: _Resp(200, ONTOLOGY)))
    assert m.update_database("defend") is True
    assert "defend" in m.fresh_writes


@pytest.mark.parametrize("ontology", [lambda: _Resp(503), _raise])
def test_d3fend_without_ontology_is_not_fresh(manager, monkeypatch, ontology):
    """The ontology failure is swallowed (fragment names stand in for D3 ids),
    so the run stays green, but that data is not a fresh success."""
    m, dm, _ = manager
    monkeypatch.setattr(dm.requests, "get", _d3fend_get(ontology))
    assert m.update_database("defend") is True
    assert "defend" not in m.fresh_writes


def test_d3fend_disabled_is_not_fresh(manager, monkeypatch):
    m, dm, _ = manager
    real_get = dm.config.get
    monkeypatch.setattr(dm.config, "get",
                        lambda key, default=None: False if key == "api.d3fend.enabled" else real_get(key, default))
    assert m.update_database("defend") is True
    assert "defend" not in m.fresh_writes


def test_d3fend_without_techniques_file_is_not_fresh(manager):
    m, dm, techniques = manager
    techniques.unlink()
    assert m.update_database("defend") is True
    assert "defend" not in m.fresh_writes


def test_processor_returning_none_is_not_fresh(manager, monkeypatch):
    m, dm, _ = manager
    monkeypatch.setattr(m, "_process_techniques_data", lambda: None)
    m.databases["techniques"]["processor"] = m._process_techniques_data
    assert m.update_database("techniques") is True
    assert "techniques" not in m.fresh_writes


def test_saved_update_is_fresh_and_failed_is_not(manager, monkeypatch):
    m, dm, _ = manager
    m.databases["kev"]["processor"] = lambda: {"CVE-2024-0001": {"x": 1}}
    m.databases["kev"]["file"] = str(Path.cwd() / "kev_db.json")
    assert m.update_database("kev") is True
    assert "kev" in m.fresh_writes

    def boom():
        raise RuntimeError("upstream down")

    m.databases["cwe"]["url"] = "https://example.test/cwe.zip"
    monkeypatch.setattr(m, "_download_file", lambda url, f: boom())
    assert m.update_database("cwe") is False
    assert "cwe" not in m.fresh_writes


def test_update_all_resets_fresh_writes(manager, monkeypatch):
    m, dm, _ = manager
    m.fresh_writes = {"stale-from-earlier"}
    monkeypatch.setattr(m, "update_database", lambda name: False)
    m.update_all_databases()
    assert m.fresh_writes == set()
