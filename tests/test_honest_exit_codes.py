"""F2: honest exit codes (ISC-12 to ISC-15).

CI only sees the process exit code, so every degraded, partial or failed step
must turn it non-zero, and lastUpdate.txt must only move on a clean run.
Everything network-facing is stubbed.
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import run_pipeline  # noqa: E402
from tip.core import pipeline_orchestrator as po  # noqa: E402


def _summary(**session):
    base = {"total_duration": 0.0, "successful_steps": 1, "failed_steps": 0,
            "degraded_steps": 0, "partial_steps": 0, "total_steps": 1}
    base.update(session)
    return {"pipeline_session": base, "results": {}}


class _StubOrchestrator:
    summary: dict = {}

    def __init__(self):
        pass

    def run_full_pipeline(self, force_update=False):
        return self.summary

    def run_database_updates_only(self):
        return self.summary


@pytest.mark.parametrize("argv, session, code", [
    (["--force"], {}, 0),
    (["--force"], {"degraded_steps": 1}, 1),     # ISC-12
    (["--force"], {"failed_steps": 1}, 1),
    (["--db-only"], {"partial_steps": 1}, 1),    # ISC-13
    (["--db-only"], {}, 0),
])
def test_run_pipeline_exit_code(monkeypatch, argv, session, code):
    _StubOrchestrator.summary = _summary(**session)
    monkeypatch.setattr(run_pipeline, "PipelineOrchestrator", _StubOrchestrator)
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", *argv])
    assert run_pipeline.main() == code


@pytest.fixture
def offline_orchestrator(tmp_path, monkeypatch):
    """A real PipelineOrchestrator in a scratch cwd with the network blocked."""
    monkeypatch.chdir(tmp_path)

    def _blocked(*_a, **_k):
        raise requests.exceptions.ConnectionError("network blocked in unit tests")

    monkeypatch.setattr(requests, "get", _blocked)
    orch = po.PipelineOrchestrator()
    last_update = tmp_path / "lastUpdate.txt"
    last_update.write_text("2026-01-01T00:00:00")
    return orch, last_update


def test_db_only_partial_exits_nonzero_end_to_end(offline_orchestrator, monkeypatch):
    """ISC-13 through the real orchestrator: one DB failing makes the run red."""
    orch, last_update = offline_orchestrator
    monkeypatch.setattr(orch.db_manager, "update_all_databases",
                        lambda: {"capec": True, "kev": False})
    monkeypatch.setattr(run_pipeline, "PipelineOrchestrator", lambda: orch)
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", "--db-only"])

    assert run_pipeline.main() == 1
    assert last_update.read_text() == "2026-01-01T00:00:00"  # ISC-15


def _stub_full_run(orch, monkeypatch, *, db_ok=True, nvd_degraded=False, generator_raises=False):
    monkeypatch.setattr(orch.db_manager, "update_all_databases",
                        lambda: {"capec": db_ok})

    def retrieve():
        if nvd_degraded:
            orch.results["cve_retrieval"] = {"status": "degraded"}
            return {"success": False, "degraded": True}
        orch.results["cve_retrieval"] = {"status": "success"}
        return {"success": True}

    monkeypatch.setattr(orch, "_retrieve_cves", retrieve)
    monkeypatch.setattr(orch, "_process_cves", lambda: {"success": True})

    import tip.core.campaign_fetcher as cf
    monkeypatch.setattr(cf, "fetch_campaigns", lambda base: {})

    import tip.core.entity_index_generator as gen

    def fake_generate(base):
        if generator_raises:
            raise RuntimeError("generator blew up")
        return ({"meta": {"entity_count": 1}, "entities": {}}, {}, {"count": 0})

    monkeypatch.setattr(gen, "generate_entity_index", fake_generate)
    monkeypatch.setattr(gen, "write_outputs", lambda *a, **k: None)


def test_entity_index_failure_is_a_failed_step(offline_orchestrator, monkeypatch):
    """ISC-14: a generator exception exits 1, not a logged warning."""
    orch, last_update = offline_orchestrator
    _stub_full_run(orch, monkeypatch, generator_raises=True)

    summary = orch.run_full_pipeline(force_update=True)

    assert summary["results"]["entity_index"]["status"] == "failed"
    assert po.exit_code_for(summary) == 1
    assert last_update.read_text() == "2026-01-01T00:00:00"


@pytest.mark.parametrize("kwargs", [
    {"db_ok": False},
    {"nvd_degraded": True},
    {"generator_raises": True},
])
def test_last_update_only_moves_on_clean_run(offline_orchestrator, monkeypatch, kwargs):
    """ISC-15: degraded, partial or failed runs leave lastUpdate.txt alone."""
    orch, last_update = offline_orchestrator
    _stub_full_run(orch, monkeypatch, **kwargs)
    summary = orch.run_full_pipeline(force_update=True)
    assert po.exit_code_for(summary) == 1
    assert last_update.read_text() == "2026-01-01T00:00:00"


def test_clean_run_advances_last_update(offline_orchestrator, monkeypatch):
    orch, last_update = offline_orchestrator
    _stub_full_run(orch, monkeypatch)
    summary = orch.run_full_pipeline(force_update=True)
    assert po.exit_code_for(summary) == 0
    assert last_update.read_text() != "2026-01-01T00:00:00"


def test_skipped_run_does_not_advance_last_update(offline_orchestrator, monkeypatch):
    """A run that decides no update is needed did no work; the stamp stays."""
    orch, last_update = offline_orchestrator
    monkeypatch.setattr(orch, "_updates_needed", lambda: False)
    orch.run_full_pipeline(force_update=False)
    assert last_update.read_text() == "2026-01-01T00:00:00"


# Audit 2026-11-18 M3 --------------------------------------------------------
# A full run without --force used to be skipped whenever lastUpdate.txt was
# under 24 hours old, which the daily --db-only run guarantees, so it skipped
# with week-old shards. The comparison mixed naive local time with the
# runner's naive UTC stamp, and the skip printed "COMPLETED SUCCESSFULLY".

def _freshness(tmp_path, nvd_stamp):
    path = tmp_path / "docs" / "data" / "freshness.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    sources = {"kev": {"last_success": "2026-11-18T15:00:00Z"}}
    if nvd_stamp is not None:
        sources["nvd"] = {"last_success": nvd_stamp}
    path.write_text(json.dumps({"schema": 1, "sources": sources}))


NOW_UTC = datetime(2026, 11, 18, 20, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("nvd_stamp, needed", [
    ("2026-11-18T18:00:00Z", False),      # 2 hours old
    ("2026-11-17T20:00:01Z", False),      # just under 24 hours
    ("2026-11-17T20:00:00Z", True),       # 24 hours
    ("2026-11-15T16:36:14Z", True),       # the weekly run, 3 days back
    ("2026-11-18T18:00:00", False),       # naive stamps are UTC, not local time
    ("2026-11-18T11:00:00-07:00", False),  # an offset is honored (18:00 UTC)
    ("yesterday", True),
    (None, True),                          # no NVD entry yet
])
def test_full_run_gate_reads_the_nvd_refresh_time(offline_orchestrator, tmp_path, nvd_stamp, needed):
    orch, last_update = offline_orchestrator
    _freshness(tmp_path, nvd_stamp)
    last_update.write_text(NOW_UTC.isoformat())  # a db-only run just finished
    assert orch._updates_needed(now=NOW_UTC) is needed
    assert (orch.skipped_reason is None) is needed


def test_full_run_gate_without_a_freshness_file(offline_orchestrator):
    orch, _ = offline_orchestrator
    assert orch._updates_needed(now=NOW_UTC) is True


def test_skipped_run_is_reported_as_skipped(offline_orchestrator, monkeypatch, capsys):
    orch, last_update = offline_orchestrator
    monkeypatch.setattr(orch, "_updates_needed", lambda: setattr(orch, "skipped_reason", "fresh") or False)
    monkeypatch.setattr(run_pipeline, "PipelineOrchestrator", lambda: orch)
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py"])

    assert run_pipeline.main() == 0
    out = capsys.readouterr().out
    assert "SKIPPED" in out and "fresh" in out
    assert "COMPLETED SUCCESSFULLY" not in out
    assert last_update.read_text() == "2026-01-01T00:00:00"


def test_last_update_is_written_in_utc(offline_orchestrator, monkeypatch):
    orch, last_update = offline_orchestrator
    _stub_full_run(orch, monkeypatch)
    orch.run_full_pipeline(force_update=True)
    stamp = datetime.fromisoformat(last_update.read_text())
    assert stamp.utcoffset() == timedelta(0)
