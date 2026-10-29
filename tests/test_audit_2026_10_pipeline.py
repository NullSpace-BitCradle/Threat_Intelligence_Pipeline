"""Pipeline fixes from the 2026-10-29 audit: reference data reloads after the
database step, one bad D3FEND binding costs only itself, campaigns list only
techniques, an empty NVD crawl fails with its reason, and progress saves at
every interval it crosses."""

import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from tip.core.campaign_fetcher import _extract_campaigns
from tip.core.cve_processor import CVEProcessor
from tip.core.database_manager import DatabaseManager
from tip.core.kev_processor import KEVProcessor
from tip.core.pipeline_orchestrator import PipelineOrchestrator


def test_process_file_reads_kev_the_database_step_wrote(tmp_path, monkeypatch):
    """The processor is built before the database step refreshes kev_db.json;
    process_file must read it again, or this week's KEV adds are missed."""
    kev_path = tmp_path / "kev_db.json"
    kev_path.write_text(json.dumps({}))
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.cwe_db, proc.capec_db = {}, {}
    proc.logger = logging.getLogger("test_audit_pipeline")
    proc.owasp_processor = SimpleNamespace(get_owasp_categories_for_cwes=lambda cwes: set())
    proc.kev_processor = KEVProcessor()
    proc.kev_processor.db_path = str(kev_path)
    proc.kev_processor.load()
    proc.vulnrichment_processor = SimpleNamespace(lookup=lambda cid: None, load=lambda: False)
    proc.apt_processor = SimpleNamespace(lookup_attributions=lambda c: [], load=lambda: False)
    proc.get_defend_techniques = lambda t: []
    kev_path.write_text(json.dumps({"CVE-2026-0001": {"inKEV": True, "dateAdded": "2026-10-28"}}))
    seen: dict = {}
    monkeypatch.setattr(proc, "_load_epss", lambda: None)
    monkeypatch.setattr(proc, "_load_ctid", lambda: None)
    monkeypatch.setattr(proc, "save_results", lambda results: seen.update(results))
    proc.cve_file = str(tmp_path / "in.jsonl")
    Path(proc.cve_file).write_text(json.dumps({"CVE-2026-0001": {"CWE": []}}) + "\n")
    proc.last_enrichment = None
    assert proc.process_file() is True
    assert seen["CVE-2026-0001"]["KEV"]["inKEV"] is True


def _binding(fragment):
    return {"def_tech": {"value": f"http://d3fend.mitre.org/ontologies/d3fend.owl#{fragment}"},
            "def_tech_label": {"value": fragment}}


def _d3fend_manager():
    dm = DatabaseManager.__new__(DatabaseManager)
    dm.logger = logging.getLogger("test_audit_pipeline")
    dm._d3fend_canonical_ids = {}
    return dm


def test_one_bad_d3fend_binding_costs_only_itself():
    reply = {"off_to_def": {"results": {"bindings": [
        _binding("FileAnalysis"), {"def_tech": "not-an-object"}, None, _binding("UserAccountManagement"),
    ]}}}
    got = _d3fend_manager()._extract_d3fend_techniques(reply)
    assert [t["id"] for t in got] == ["FileAnalysis", "UserAccountManagement"]


@pytest.mark.parametrize("reply", [{}, {"off_to_def": {"results": {}}}, {"off_to_def": []}])
def test_d3fend_reply_without_bindings_raises(reply):
    with pytest.raises(RuntimeError, match="bindings"):
        _d3fend_manager()._extract_d3fend_techniques(reply)


def test_campaign_techniques_exclude_malware_and_tools():
    def ref(eid):
        return [{"source_name": "mitre-attack", "external_id": eid}]
    objects = [
        {"type": "campaign", "id": "campaign--1", "name": "C", "external_references": ref("C0001")},
        {"type": "attack-pattern", "id": "attack-pattern--1", "external_references": ref("T1190")},
        {"type": "attack-pattern", "id": "attack-pattern--2", "external_references": ref("T1000"), "revoked": True},
        {"type": "malware", "id": "malware--1", "external_references": ref("S0174")},
    ] + [
        {"type": "relationship", "relationship_type": "uses", "source_ref": "campaign--1", "target_ref": t}
        for t in ("attack-pattern--1", "attack-pattern--2", "malware--1")
    ]
    db = _extract_campaigns({"objects": objects})
    assert db["C0001"]["techniques"] == ["T1190"]


def test_empty_full_crawl_fails_with_its_reason(tmp_path):
    orch = PipelineOrchestrator.__new__(PipelineOrchestrator)
    orch.cve_processor = SimpleNamespace(retrieve_cves_from_nvd=lambda *a, **k: [])
    orch.results = {}
    out = tmp_path / "new_cves.jsonl"
    orch.config = SimpleNamespace(get_output_path=lambda _k: str(out))
    result = orch._retrieve_cves()
    assert result["success"] is False
    assert orch.results["cve_retrieval"]["status"] == "failed"
    assert "no CVEs" in orch.results["cve_retrieval"]["error"]
    assert not out.exists()


def test_progress_saves_at_every_interval_crossed(tmp_path, monkeypatch):
    """2000-row pages against a 5000 interval cross it at 6000 and 10000;
    len % 5000 == 0 saved only at 10000."""
    import tip.core.cve_processor as cve_mod
    saves = []
    monkeypatch.setattr(cve_mod, "atomic_write_json", lambda path, data: saves.append(data["total_retrieved"]))
    monkeypatch.setattr(cve_mod.time, "sleep", lambda _s: None)
    total = 11000

    class _Resp:
        status_code = 200

        def __init__(self, start):
            self.start = start

        def json(self):
            n = min(2000, total - self.start)
            return {"totalResults": total, "vulnerabilities": [{"cve": {"id": f"CVE-2020-{self.start + i:05d}"}} for i in range(n)]}

        def raise_for_status(self):
            pass

    settings = {"files.progress_file": str(tmp_path / "progress.json"),
                "progress_tracking.save_interval": 5000}
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.logger = logging.getLogger("test_audit_pipeline")
    proc.config = SimpleNamespace(get=lambda k, d=None: settings.get(k, d), get_api_key=lambda _n: None)
    monkeypatch.setattr(cve_mod.requests, "get", lambda url, params=None, **k: _Resp(params["startIndex"]))
    proc.retrieve_cves_from_nvd()
    assert saves == [6000, 10000]
