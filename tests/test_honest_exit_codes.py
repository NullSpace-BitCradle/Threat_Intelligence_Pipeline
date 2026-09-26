"""F2: honest exit codes (ISC-12 to ISC-15).

CI only sees the process exit code, so every degraded, partial or failed step
must turn it non-zero, and lastUpdate.txt must only move on a clean run.
Everything network-facing is stubbed.
"""
import sys
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
