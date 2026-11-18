"""Audit 2026-11-18 L1: rejected CVEs are flagged, not served as ordinary CVEs.

NVD keeps rejected IDs in its corpus (19,172 shard records begin "Rejected
reason:" or "** REJECT **"), and its vulnStatus was dropped at ingest, so
they rendered like any other CVE. The status is now kept as VULN_STATUS on
the shard record, carried as vuln_status on the entity and MCP records, and
the site badges a rejected CVE. Records are flagged rather than filtered, so
the shard format stays additive and the CVE totals keep their meaning.
"""
import logging
from types import SimpleNamespace

from tip.core.cve_processor import CVEProcessor
from tip.core.entity_index_generator import build_cve_entity_record
from tip_mcp.tools import _build_shard_record


def _nvd_item(cve_id, status=None):
    cve = {
        "id": cve_id,
        "published": "1999-12-30T05:00:00.000",
        "lastModified": "2025-04-03T01:03:51.193",
        "descriptions": [{"lang": "en", "value": "Rejected reason: DO NOT USE THIS CANDIDATE NUMBER."}],
        "weaknesses": [],
        "metrics": {},
        "references": [],
    }
    if status is not None:
        cve["vulnStatus"] = status
    return {"cve": cve}


def _bare_processor():
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.cwe_db, proc.capec_db = {}, {}
    proc.logger = logging.getLogger("test_rejected_cves")
    proc.owasp_processor = SimpleNamespace(get_owasp_categories_for_cwes=lambda cwes: set())
    proc.kev_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.vulnrichment_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.apt_processor = SimpleNamespace(lookup_attributions=lambda c: [])
    return proc


def test_ingest_keeps_nvd_vuln_status():
    proc = _bare_processor()
    out = proc.process_nvd_cves([
        _nvd_item("CVE-1999-0020", "Rejected"),
        _nvd_item("CVE-2024-0001", "Analyzed"),
        _nvd_item("CVE-2024-0002"),
    ])
    assert out["CVE-1999-0020"]["VULN_STATUS"] == "Rejected"
    assert out["CVE-2024-0001"]["VULN_STATUS"] == "Analyzed"
    assert "VULN_STATUS" not in out["CVE-2024-0002"]


def test_enrichment_carries_vuln_status_through():
    proc = _bare_processor()
    ingested = proc.process_nvd_cves([_nvd_item("CVE-1999-0020", "Rejected")])
    rec = proc.process_cve_pipeline(ingested)["CVE-1999-0020"]
    assert rec["VULN_STATUS"] == "Rejected"


def test_entity_and_mcp_records_carry_vuln_status():
    payload = {"DESCRIPTION": "Rejected reason: duplicate.", "CWE": [], "VULN_STATUS": "Rejected"}
    assert build_cve_entity_record("CVE-1999-0020", payload)["vuln_status"] == "Rejected"
    assert _build_shard_record("CVE-1999-0020", payload, "CVE-1999.jsonl.gz")["vuln_status"] == "Rejected"
    # A shard written before L1 has no status, and neither record invents one.
    legacy = {"DESCRIPTION": "x", "CWE": []}
    assert "vuln_status" not in build_cve_entity_record("CVE-1999-0001", legacy)
    assert "vuln_status" not in _build_shard_record("CVE-1999-0001", legacy, "CVE-1999.jsonl.gz")
