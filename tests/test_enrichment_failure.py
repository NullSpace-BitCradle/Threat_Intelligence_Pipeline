"""A CVE whose enrichment throws is never published as a stripped record.

Its previous shard record stays byte-identical, the failure is counted, and
the cve_processing step fails once failures exceed min(1% of processed, 50).
"""
import gzip
import json
import logging
from types import SimpleNamespace

import pytest

import tip.core.cve_processor as cve_mod
from tip.core import pipeline_orchestrator as po
from tip.core.cve_processor import CVEProcessor
from tip.database.database_optimizer import JSONLManager
from tip.utils.atomic_io import deterministic_gzip, jsonl_bytes


class _Cfg:
    def __init__(self, db_dir):
        self.db_dir = db_dir

    def get(self, key, default=None):
        return str(self.db_dir) if key == "files.database_dir" else default


def _processor(tmp_path, monkeypatch, failing_ids):
    db_dir = tmp_path / "database"
    db_dir.mkdir()
    monkeypatch.setattr(cve_mod, "config", _Cfg(db_dir))

    def kev_lookup(cid):
        if cid in failing_ids:
            raise RuntimeError(f"enrichment blew up for {cid}")
        return None

    proc = CVEProcessor.__new__(CVEProcessor)
    proc.cwe_db = {}
    proc.capec_db = {}
    proc.techniques_db = {}
    proc.logger = logging.getLogger("test_enrichment_failure")
    proc.owasp_processor = SimpleNamespace(get_owasp_categories_for_cwes=lambda cwes: set())
    proc.kev_processor = SimpleNamespace(lookup=kev_lookup)
    proc.vulnrichment_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.apt_processor = SimpleNamespace(lookup_by_techniques=lambda t: [])
    proc.jsonl_manager = JSONLManager()
    proc.cve_file = str(tmp_path / "cve.jsonl")
    return proc, db_dir


def _write_input(proc, ids):
    with open(proc.cve_file, "w") as f:
        for cid in ids:
            rec = {"CWE": [], "CAPEC": [], "TECHNIQUES": [], "DESCRIPTION": f"new {cid}"}
            f.write(json.dumps({cid: rec}) + "\n")


PRIOR = {
    "CWE": ["CWE-79"], "CAPEC": ["63"], "TECHNIQUES": ["T1059"],
    "DEFEND": [{"id": "D3-EAL"}], "OWASP": ["A03:2021"], "DESCRIPTION": "published",
}


def _read_shard(path):
    out = {}
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            out.update(json.loads(line))
    return out


def test_failed_cve_is_not_written_and_prior_record_survives(tmp_path, monkeypatch):
    ids = [f"CVE-2024-{1000 + i}" for i in range(200)]
    failing = {"CVE-2024-1000", "CVE-2023-0001"}
    proc, db_dir = _processor(tmp_path, monkeypatch, failing)

    # Prior published record for a CVE that fails alone in its year, and one
    # that fails next to successes in the same year.
    shard_2023 = db_dir / "CVE-2023.jsonl.gz"
    shard_2023.write_bytes(deterministic_gzip(jsonl_bytes([("CVE-2023-0001", PRIOR)])))
    before_2023 = shard_2023.read_bytes()
    shard_2024 = db_dir / "CVE-2024.jsonl.gz"
    shard_2024.write_bytes(deterministic_gzip(jsonl_bytes([("CVE-2024-1000", PRIOR)])))

    _write_input(proc, ids + ["CVE-2023-0001"])

    # 2 failures of 201 is under min(1% = 2.01, 50): the run succeeds.
    assert proc.process_file() is True
    assert shard_2023.read_bytes() == before_2023
    after_2024 = _read_shard(shard_2024)
    assert after_2024["CVE-2024-1000"] == PRIOR
    assert after_2024["CVE-2024-1001"]["DESCRIPTION"] == "new CVE-2024-1001"
    assert len(after_2024) == 200
    stats = proc.last_enrichment
    assert stats["attempted"] == 201
    assert stats["failed"] == 2
    assert sorted(stats["failed_ids"]) == sorted(failing)
    # The failed CVEs are not in the main output file either.
    out_ids = {next(iter(json.loads(l))) for l in open(proc.cve_file)}
    assert not (out_ids & failing)


def test_failures_over_threshold_fail_the_step(tmp_path, monkeypatch):
    ids = [f"CVE-2024-{1000 + i}" for i in range(100)]
    failing = {"CVE-2024-1000", "CVE-2024-1001"}  # 2 > 1% of 100
    proc, db_dir = _processor(tmp_path, monkeypatch, failing)
    shard = db_dir / "CVE-2024.jsonl.gz"
    shard.write_bytes(deterministic_gzip(jsonl_bytes([("CVE-2024-1000", PRIOR)])))
    _write_input(proc, ids)

    assert proc.process_file() is False
    assert _read_shard(shard)["CVE-2024-1000"] == PRIOR
    assert proc.last_enrichment["failed"] == 2


@pytest.mark.parametrize("failed, attempted, over", [
    (0, 10, False), (1, 10, True), (1, 100, False), (2, 100, True),
    (50, 10000, False), (51, 10000, True), (50, 1_000_000, False), (51, 1_000_000, True),
])
def test_threshold_is_min_of_one_percent_and_fifty(failed, attempted, over):
    assert CVEProcessor.enrichment_failures_exceed_threshold(failed, attempted) is over


def test_orchestrator_records_counts_and_fails_step(tmp_path, monkeypatch):
    orch = po.PipelineOrchestrator.__new__(po.PipelineOrchestrator)
    orch.results = {}
    stats = {"attempted": 100, "failed": 2, "failed_ids": ["CVE-2024-1000", "CVE-2024-1001"]}

    def fake_process_file():
        orch.cve_processor.last_enrichment = stats
        return False

    orch.cve_processor = SimpleNamespace(process_file=fake_process_file, last_enrichment=None)
    orch._process_cves()
    step = orch.results["cve_processing"]
    assert step["status"] == "failed"
    assert step["attempted"] == 100
    assert step["enrichment_failed"] == 2
    assert step["enrichment_failed_ids"] == ["CVE-2024-1000", "CVE-2024-1001"]
