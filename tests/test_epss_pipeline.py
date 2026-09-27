"""I1: EPSS through the pipeline (ISC-2 exit code, ISC-5 shard records, ISC-13).

The database step and the CVE step share one EPSSProcessor, so the bulk file
is fetched once per run; an EPSS failure turns the run red and leaves the
previous curated file byte-identical. All HTTP is mocked.
"""
import json
import logging
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import run_pipeline  # noqa: E402
from tip.core import epss_processor as ep  # noqa: E402
from tip.core import pipeline_orchestrator as po  # noqa: E402
from tip.core.cve_processor import CVEProcessor  # noqa: E402
from tip.database.database_optimizer import JSONLManager  # noqa: E402

from tests.test_epss_processor import _Resp, make_csv  # noqa: E402


@pytest.fixture
def orch(tmp_path, monkeypatch):
    """A real orchestrator in a scratch cwd; every DB but EPSS is stubbed green."""
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "docs" / "data"
    data.mkdir(parents=True)
    (data / "entity_index.json").write_text(json.dumps(
        {"entities": {"CVE-2023-44487": {"type": "cve"}, "CVE-2024-1234": {"type": "cve"}}}
    ))
    (tmp_path / "lastUpdate.txt").write_text("2026-01-01T00:00:00")
    calls: list[str] = []
    state = {"content": make_csv(), "error": None}

    def fake_get(url, *a, **k):
        if "epss" not in url:
            raise requests.exceptions.ConnectionError("network blocked in unit tests")
        calls.append(url)
        if state["error"]:
            raise state["error"]
        return _Resp(state["content"])

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(ep.time, "sleep", lambda s: None)
    o = po.PipelineOrchestrator()
    real_update = o.db_manager.update_database
    monkeypatch.setattr(
        o.db_manager, "update_database",
        lambda name: real_update(name) if name == "epss" else True,
    )
    return SimpleNamespace(orch=o, calls=calls, state=state, data=data, root=tmp_path)


def _run_db_only(env, monkeypatch) -> int:
    monkeypatch.setattr(run_pipeline, "PipelineOrchestrator", lambda: env.orch)
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", "--db-only"])
    return run_pipeline.main()


def test_db_only_writes_curated_and_exits_zero(orch, monkeypatch):
    assert _run_db_only(orch, monkeypatch) == 0
    out = json.loads((orch.data / "epss_curated.json").read_text())
    assert set(out["scores"]) == {"CVE-2023-44487", "CVE-2024-1234"}
    assert orch.calls == [ep.DEFAULT_URL]


@pytest.mark.parametrize("failure", ["download", "header", "floor"])
def test_db_only_epss_failure_exits_one_and_keeps_prior_file(orch, monkeypatch, failure):
    prior = {"meta": {"total_count": 1_000_000}, "scores": {"CVE-2023-44487": {"score": 0.5, "percentile": 0.5}}}
    target = orch.data / "epss_curated.json"
    target.write_text(json.dumps(prior))
    if failure != "floor":
        # A good-sized prior count would floor-refuse the 3-row fixture, so
        # the non-floor cases start from a small prior.
        target.write_text(json.dumps({**prior, "meta": {"total_count": 3}}))
    before = target.read_bytes()
    if failure == "download":
        orch.state["error"] = requests.exceptions.ConnectionError("down")
    elif failure == "header":
        orch.state["content"] = make_csv(header="#nope\n")

    assert _run_db_only(orch, monkeypatch) == 1
    assert target.read_bytes() == before
    assert (orch.root / "lastUpdate.txt").read_text() == "2026-01-01T00:00:00"


def _processor(tmp_path, monkeypatch):
    import tip.core.cve_processor as cve_mod

    db_dir = tmp_path / "database"
    db_dir.mkdir()
    monkeypatch.setattr(cve_mod, "config", SimpleNamespace(
        get=lambda key, default=None: str(db_dir) if key == "files.database_dir" else default
    ))
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.cwe_db = {}
    proc.capec_db = {}
    proc.techniques_db = {}
    proc.logger = logging.getLogger("test_epss_pipeline")
    proc.owasp_processor = SimpleNamespace(get_owasp_categories_for_cwes=lambda cwes: set())
    proc.kev_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.vulnrichment_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.apt_processor = SimpleNamespace(lookup_by_techniques=lambda t: [])
    proc.jsonl_manager = JSONLManager()
    proc.cve_file = str(tmp_path / "cve.jsonl")
    with open(proc.cve_file, "w") as f:
        for cid in ("CVE-2023-44487", "CVE-2023-99999"):
            f.write(json.dumps({cid: {"CWE": [], "CAPEC": [], "TECHNIQUES": [], "DESCRIPTION": cid}}) + "\n")
    return proc, db_dir


def _shard(db_dir) -> dict:
    out: dict = {}
    for rec in JSONLManager().read_jsonl(str(db_dir / "CVE-2023.jsonl")):
        out.update(rec)
    return out


def test_shard_records_carry_epss_when_scored(tmp_path, monkeypatch):
    """ISC-5: a scored CVE gets EPSS {score, percentile, date}; an unscored one none."""
    proc, db_dir = _processor(tmp_path, monkeypatch)
    epss = ep.EPSSProcessor()
    epss.snapshot = ep.parse_bulk(make_csv())
    proc.epss_processor = epss
    assert proc.process_file() is True
    shard = _shard(db_dir)
    assert shard["CVE-2023-44487"]["EPSS"] == {
        "score": 0.99999, "percentile": 0.99998, "date": "2026-09-26", "model_version": "v2026.06.15",
    }
    assert "EPSS" not in shard["CVE-2023-99999"]
    assert proc.last_epss_error is None


def test_epss_failure_in_cve_step_is_not_clean(tmp_path, monkeypatch):
    proc, db_dir = _processor(tmp_path, monkeypatch)
    epss = ep.EPSSProcessor()
    epss.fetch_error = ep.NetworkError("down")
    proc.epss_processor = epss
    assert proc.process_file() is True
    assert "EPSS" not in _shard(db_dir)["CVE-2023-44487"]
    assert proc.last_epss_error

    o = po.PipelineOrchestrator.__new__(po.PipelineOrchestrator)
    o.results = {}
    o.cve_processor = proc
    o._process_cves()
    assert o.results["cve_processing"]["status"] == "partial"
    assert o.results["cve_processing"]["epss_error"]


def test_fetch_failure_is_not_retried_in_the_same_run(monkeypatch):
    calls = []

    def boom(url, *a, **k):
        calls.append(url)
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(ep.requests, "get", boom)
    monkeypatch.setattr(ep.time, "sleep", lambda s: None)
    proc = ep.EPSSProcessor()
    for _ in range(2):
        with pytest.raises(ep.NetworkError):
            proc.fetch()
    # One bounded retry cycle for the first caller, none for the second.
    assert len(calls) == ep.EPSS_ATTEMPTS


def test_orchestrator_shares_one_processor(orch):
    assert orch.orch.cve_processor.epss_processor is orch.orch.db_manager.epss_processor


def test_refresh_after_index_uses_snapshot_without_refetch(orch):
    o = orch.orch
    assert o.db_manager.update_database("epss") is True
    assert len(orch.calls) == 1
    # The new index adds a curated CVE; the refresh picks it up.
    (orch.data / "entity_index.json").write_text(json.dumps(
        {"entities": {"CVE-1999-0001": {"type": "cve"}, "CVE-2023-44487": {"type": "cve"}}}
    ))
    o.results["entity_index"] = {"status": "success"}
    o._refresh_epss_curated()
    assert o.results["epss_curated"]["status"] == "success"
    out = json.loads((orch.data / "epss_curated.json").read_text())
    assert set(out["scores"]) == {"CVE-1999-0001", "CVE-2023-44487"}
    assert len(orch.calls) == 1


def test_refresh_skipped_without_snapshot(orch):
    o = orch.orch
    o.results["entity_index"] = {"status": "success"}
    o._refresh_epss_curated()
    assert "epss_curated" not in o.results


# ISC-13 --------------------------------------------------------------------

@pytest.mark.parametrize("workflow", ["update-databases.yml", "run-pipeline.yml"])
def test_workflows_stage_only_data_paths(workflow):
    """The staged paths are unchanged, so the only EPSS output reaching a
    commit is what the code writes under docs/data: the curated file."""
    text = (REPO_ROOT / ".github" / "workflows" / workflow).read_text()
    adds = re.findall(r"^\s*git add (.+)$", text, re.MULTILINE)
    assert adds == ["docs/data docs/database lastUpdate.txt"]
    assert "epss" not in text.lower()


# Item 3: fail closed before the NVD crawl -------------------------------------

def _run_full(env, monkeypatch) -> tuple[int, list]:
    crawled: list = []
    monkeypatch.setattr(env.orch.cve_processor, "retrieve_cves_from_nvd",
                        lambda *a, **k: crawled.append(1) or [])
    monkeypatch.setattr(env.orch, "_fetch_campaigns", lambda: None)
    monkeypatch.setattr(env.orch, "_generate_entity_index", lambda: None)
    monkeypatch.setattr(run_pipeline, "PipelineOrchestrator", lambda: env.orch)
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", "--force"])
    return run_pipeline.main(), crawled


def test_full_run_aborts_before_nvd_crawl_when_epss_fails(orch, monkeypatch):
    orch.state["error"] = requests.exceptions.ConnectionError("down")
    code, crawled = _run_full(orch, monkeypatch)
    assert code == 1
    assert crawled == []
    step = orch.orch.results["cve_retrieval"]
    assert step["status"] == "failed" and "EPSS" in step["error"]
    assert len(orch.calls) == ep.EPSS_ATTEMPTS  # bounded retry, then stop


def test_full_run_crawls_when_epss_is_good(orch, monkeypatch):
    code, crawled = _run_full(orch, monkeypatch)
    assert crawled == [1]
    assert len(orch.calls) == 1
