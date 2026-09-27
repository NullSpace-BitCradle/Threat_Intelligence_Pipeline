"""I21 F3: CTID and inferred techniques through shards and the index
(ISC-5, ISC-7, ISC-8, ISC-12).

Fixture data only; nothing is fetched.
"""
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from tip.core import entity_index_generator as gen
from tip.core.ctid_processor import SOURCE as CTID_SOURCE
from tip.core.cve_processor import CVEProcessor
from tip.database.database_optimizer import JSONLManager

NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CTID_DB = {
    "CVE-2024-0002": {"group": "xxe", "techniques": [
        {"id": "T1190", "mapping_type": ["exploitation_technique"], "comment": "Crafted XML."},
        {"id": "T1005", "mapping_type": ["secondary_impact"], "comment": None},
    ]},
}


def _processor(ctid_db=CTID_DB):
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.cwe_db = {"79": {"ChildOf": [], "RelatedAttackPatterns": ["63"]},
                   "787": {"ChildOf": [], "RelatedAttackPatterns": []}}
    proc.capec_db = {"63": {"techniques": "::TAXONOMY NAME:ATTACK:ENTRY ID:1059::"}}
    proc.logger = logging.getLogger("test_i21")
    proc.owasp_processor = SimpleNamespace(get_owasp_categories_for_cwes=lambda cwes: set())
    proc.kev_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.vulnrichment_processor = SimpleNamespace(lookup=lambda cid: None)
    seen: list = []
    proc.apt_processor = SimpleNamespace(lookup_by_techniques=lambda t: seen.append(sorted(t)) or [])
    proc.get_defend_techniques = lambda t: []
    proc.ctid_db = ctid_db
    return proc, seen


def _run(records, ctid_db=CTID_DB):
    proc, seen = _processor(ctid_db)
    return proc.process_cve_pipeline(records), seen


# ── ISC-7: shards ────────────────────────────────────────────────────


def test_ctid_techniques_get_their_own_field_with_source():
    out, seen = _run({"CVE-2024-0002": {"CWE": ["CWE-787"], "CVSS": {"vector": NET}}})
    rec = out["CVE-2024-0002"]
    assert rec["TECHNIQUES"] == [] and rec["TECHNIQUES_INHERITED"] == []
    assert [t["id"] for t in rec["TECHNIQUES_CTID"]] == ["T1190", "T1005"]
    assert all(t["source"] == CTID_SOURCE for t in rec["TECHNIQUES_CTID"])
    assert rec["TECHNIQUES_CTID"][0]["mapping_type"] == ["exploitation_technique"]
    assert rec["TECHNIQUES_CTID"][0]["comment"] == "Crafted XML."
    # CTID fills the slot, so nothing is inferred.
    assert rec["TECHNIQUES_INFERRED"] == []
    # APT linkage stays on the chain (Layer 2 is unchanged).
    assert seen == []


def test_memory_safety_cve_gets_an_inferred_technique_with_its_rule():
    out, seen = _run({"CVE-2024-0003": {"CWE": ["CWE-787"], "CVSS": {"vector": LOCAL}}})
    rec = out["CVE-2024-0003"]
    assert rec["TECHNIQUES_CTID"] == []
    (inf,) = rec["TECHNIQUES_INFERRED"]
    assert inf["id"] == "T1068" and inf["rule"] == "local-full-impact"
    assert "CVSS" in inf["source"]
    assert seen == []


def test_chain_technique_blocks_inference_in_the_processor():
    out, _ = _run({"CVE-2024-0004": {"CWE": ["CWE-79"], "CVSS": {"vector": NET}}})
    rec = out["CVE-2024-0004"]
    assert rec["TECHNIQUES"] == ["1059"]
    assert rec["TECHNIQUES_INFERRED"] == []


def test_no_vector_no_inference():
    out, _ = _run({"CVE-2024-0005": {"CWE": ["CWE-787"]}})
    assert out["CVE-2024-0005"]["TECHNIQUES_INFERRED"] == []


def test_ctid_db_unavailable_writes_neither_field():
    out, _ = _run({"CVE-2024-0002": {"CWE": ["CWE-787"], "CVSS": {"vector": NET}}}, ctid_db=None)
    rec = out["CVE-2024-0002"]
    assert "TECHNIQUES_CTID" not in rec and "TECHNIQUES_INFERRED" not in rec
