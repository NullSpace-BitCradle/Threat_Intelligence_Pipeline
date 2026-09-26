"""D3FEND update fails closed on any per-technique error except 404.

A 404 means "no mapping for this technique". A timeout, connection error,
5xx, 429 after retries, or bad JSON fails the update so the previous
defend_db stays on disk and a db-only run exits 1.
"""
import json
import sys
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import run_pipeline  # noqa: E402
import tip.core.database_manager as dm_mod  # noqa: E402
from tip.core import pipeline_orchestrator as po  # noqa: E402

_ATTEMPTS = getattr(dm_mod, "D3FEND_ATTEMPTS", 3)

BINDINGS = {"off_to_def": {"results": {"bindings": [{
    "def_tech": {"value": "http://d3fend.mitre.org/ontologies/d3fend.owl#ExecutableAllowlisting"},
    "def_tech_label": {"value": "Executable Allowlisting"},
}]}}}


class _Resp:
    def __init__(self, status, body=None, bad_json=False):
        self.status_code = status
        self._body = body
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise json.JSONDecodeError("Expecting value", "<html>", 0)
        return self._body


def _outcome_500():
    return _Resp(500)


def _outcome_429():
    return _Resp(429)


def _outcome_bad_json():
    return _Resp(200, bad_json=True)


def _outcome_timeout():
    raise requests.exceptions.Timeout("read timed out")


def _outcome_connection():
    raise requests.exceptions.ConnectionError("connection reset")


def _outcome_404():
    return _Resp(404)


@pytest.fixture
def defend_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    techniques = tmp_path / "techniques_db.json"
    techniques.write_text(json.dumps({"T1001": {}, "T1002": {}, "T1003": {}}))
    defend = tmp_path / "defend_db.jsonl"
    defend.write_text(json.dumps({"T9999": {"attack_technique": "T9999",
                                            "defensive_techniques": [{"id": "D3-OLD"}]}}) + "\n")
    real_path = dm_mod.config.get_database_path
    monkeypatch.setattr(dm_mod.config, "get_database_path",
                        lambda name: str(techniques) if name == "techniques" else real_path(name))
    monkeypatch.setattr(dm_mod.time, "sleep", lambda s: None)
    calls = {"T1003": 0}

    def install(t1003_outcome):
        def fake_get(url, timeout=None, **kw):
            if url.endswith("d3fend.json"):
                return _Resp(404)  # ontology unavailable: fragment names are used
            if url.endswith("T1001.json"):
                return _Resp(200, BINDINGS)
            if url.endswith("T1002.json"):
                return _Resp(404)
            if url.endswith("T1003.json"):
                calls["T1003"] += 1
                return t1003_outcome()
            raise AssertionError(url)
        monkeypatch.setattr(dm_mod.requests, "get", fake_get)

    manager = dm_mod.DatabaseManager()
    manager.databases["defend"]["file"] = str(defend)
    return manager, defend, install, calls


@pytest.mark.parametrize("outcome", [
    _outcome_500, _outcome_429, _outcome_bad_json, _outcome_timeout, _outcome_connection,
])
def test_d3fend_error_keeps_previous_file(defend_env, outcome):
    manager, defend, install, calls = defend_env
    install(outcome)
    before = defend.read_bytes()

    assert manager.update_database("defend") is False
    assert defend.read_bytes() == before


@pytest.mark.parametrize("outcome, attempts", [
    (_outcome_429, _ATTEMPTS), (_outcome_500, _ATTEMPTS),
    (_outcome_timeout, _ATTEMPTS), (_outcome_bad_json, 1),
])
def test_d3fend_retries_transient_errors_only(defend_env, outcome, attempts):
    manager, defend, install, calls = defend_env
    install(outcome)
    manager.update_database("defend")
    assert calls["T1003"] == attempts


def test_d3fend_404_is_no_mapping_and_update_succeeds(defend_env):
    manager, defend, install, calls = defend_env
    install(_outcome_404)

    assert manager.update_database("defend") is True
    written = [json.loads(line) for line in defend.read_text().splitlines()]
    assert [next(iter(r)) for r in written] == ["T1001"]


def test_d3fend_transient_error_then_success_recovers(defend_env):
    manager, defend, install, calls = defend_env
    seq = iter([_Resp(503), _Resp(200, BINDINGS)])
    install(lambda: next(seq))

    assert manager.update_database("defend") is True
    written = {next(iter(json.loads(line))) for line in defend.read_text().splitlines()}
    assert written == {"T1001", "T1003"}


def test_d3fend_error_makes_db_only_run_exit_1(defend_env, monkeypatch):
    manager, defend, install, calls = defend_env
    install(_outcome_500)
    before = defend.read_bytes()
    orch = po.PipelineOrchestrator()
    orch.db_manager = manager
    monkeypatch.setattr(manager, "update_all_databases",
                        lambda: {"defend": manager.update_database("defend")})
    monkeypatch.setattr(run_pipeline, "PipelineOrchestrator", lambda: orch)
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", "--db-only"])

    assert run_pipeline.main() == 1
    assert defend.read_bytes() == before
