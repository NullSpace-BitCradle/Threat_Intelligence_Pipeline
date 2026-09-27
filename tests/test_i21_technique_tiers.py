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


# ── ISC-8: the index ─────────────────────────────────────────────────

from tests.test_i29_inherited_cwe import KEV_ENTRY, NEW_RECORD, _dangling, _write  # noqa: E402

CTID_INDEX_DB = {
    "CVE-2024-0010": {"group": "xxe", "techniques": [
        {"id": "T1190", "mapping_type": ["exploitation_technique"], "comment": "Crafted XML."},
        {"id": "T1005", "mapping_type": ["secondary_impact", "primary_impact"], "comment": None},
        {"id": "T1562.001", "mapping_type": ["secondary_impact"], "comment": None},
    ]},
    "CVE-2024-0001": {"group": "xss", "techniques": [
        {"id": "T1190", "mapping_type": ["exploitation_technique"], "comment": "Reflected."},
    ]},
    "CVE-2025-0099": {"group": "oob", "techniques": [
        {"id": "T1068", "mapping_type": ["exploitation_technique"], "comment": "KEV only."},
    ]},
}
MEMORY = {"CWE": ["CWE-787"], "CVSS": {"score": 9.8, "vector": NET}}


def _build(tmp_path, records, ctid_db=CTID_INDEX_DB, kev_only=()):
    _write(tmp_path, records)
    data = tmp_path / "docs" / "data"
    (data / "techniques_db.json").write_text(json.dumps(
        {t: {"name": f"Tech {t}"} for t in ("1059", "1190", "1562", "1499", "1134", "1068", "1203", "1005")}))
    if ctid_db is not None:
        (data / "ctid_db.json").write_text(json.dumps({"meta": {}, "cves": ctid_db}))
    if kev_only:
        kev = json.loads((data / "kev_db.json").read_text())
        kev.update({k: KEV_ENTRY for k in kev_only})
        (data / "kev_db.json").write_text(json.dumps(kev))
    return gen.generate_entity_index(tmp_path)[0]


def test_ctid_links_carry_per_link_provenance_both_directions(tmp_path):
    ei = _build(tmp_path, {"CVE-2024-0010": MEMORY})
    ents = ei["entities"]
    tech = ents["CVE-2024-0010"]["rels"]["technique"]
    assert tech["ids"] == ["T1005", "T1190"]
    # The body keeps its one source (legacy readers); link_prov overrides it.
    assert tech["tier"] == "derived"
    assert tech["link_prov"]["T1190"] == {
        "source": CTID_SOURCE, "tier": "official",
        "mapping_type": ["exploitation_technique"], "comment": "Crafted XML."}
    assert tech["link_prov"]["T1005"]["mapping_type"] == ["secondary_impact", "primary_impact"]
    back = ents["T1190"]["rels"]["cve"]["link_prov"]["CVE-2024-0010"]
    assert back == {"source": CTID_SOURCE, "tier": "official", "mapping_type": ["exploitation_technique"]}
    # A technique the current ATT&CK release does not have is not linked.
    assert ei["meta"]["ctid_unknown_techniques"] == 1
    assert ei["meta"]["link_provenance"] is True
    # CTID-stated technique outranks inference: nothing inferred.
    assert all(p["tier"] == "official" for p in tech["link_prov"].values())
    # D3FEND through a CTID technique is official, both directions.
    defend = ents["CVE-2024-0010"]["rels"]["defend"]
    assert defend["ids"] == ["D3-EAL", "D3-NTA"]
    assert {p["tier"] for p in defend["link_prov"].values()} == {"official"}
    assert ents["D3-EAL"]["rels"]["cve"]["link_prov"]["CVE-2024-0010"]["tier"] == "official"
    # APT linkage stays on the chain.
    assert "apt_group" not in ents["CVE-2024-0010"]["rels"]
    assert _dangling(ents) == []


def test_inferred_link_from_an_i21_shard(tmp_path):
    rec = dict(MEMORY, TECHNIQUES=[], TECHNIQUES_INHERITED=[], TECHNIQUES_CTID=[], TECHNIQUES_INFERRED=[
        {"id": "T1190", "rule": "network-no-interaction", "source": "TIP inference (rule)"}])
    ents = _build(tmp_path, {"CVE-2024-0011": rec})["entities"]
    tech = ents["CVE-2024-0011"]["rels"]["technique"]
    assert tech["ids"] == ["T1190"]
    assert tech["link_prov"]["T1190"] == {"source": "TIP inference (rule)", "tier": "inferred",
                                          "rule": "network-no-interaction"}
    assert ents["T1190"]["rels"]["cve"]["link_prov"]["CVE-2024-0011"]["tier"] == "inferred"
    defend = ents["CVE-2024-0011"]["rels"]["defend"]
    assert {p["tier"] for p in defend["link_prov"].values()} == {"inferred"}
    assert "apt_group" not in ents["CVE-2024-0011"]["rels"]


def test_legacy_shard_is_inferred_from_its_vector(tmp_path):
    ents = _build(tmp_path, {"CVE-2024-0012": MEMORY})["entities"]
    prov = ents["CVE-2024-0012"]["rels"]["technique"]["link_prov"]
    assert list(prov) == ["T1190"] and prov["T1190"]["tier"] == "inferred"
    assert prov["T1190"]["rule"] == "network-no-interaction"


def test_ctid_overrides_an_inherited_chain_link(tmp_path):
    # NEW_RECORD reaches T1190 only through inherited CWE-74; CTID states it.
    ents = _build(tmp_path, {"CVE-2024-0001": dict(NEW_RECORD, CVSS={"vector": NET})})["entities"]
    tech = ents["CVE-2024-0001"]["rels"]["technique"]
    assert tech["ids"] == ["T1059", "T1190"]
    assert "inherited" not in tech
    assert tech["link_prov"] == {"T1190": {"source": CTID_SOURCE, "tier": "official",
                                           "mapping_type": ["exploitation_technique"], "comment": "Reflected."}}
    assert "inherited" not in ents["T1190"]["rels"]["cve"]
    # D3-NTA was inherited-only through T1190; CTID now reaches it.
    defend = ents["CVE-2024-0001"]["rels"]["defend"]
    assert "inherited" not in defend
    assert defend["link_prov"]["D3-NTA"]["tier"] == "official"
    # APT groups keep their I29 labels (chain only).
    assert ents["CVE-2024-0001"]["rels"]["apt_group"]["inherited"] == ["G0016"]


def test_chain_cve_gets_no_inferred_link(tmp_path):
    ents = _build(tmp_path, {"CVE-2024-0013": {"CWE": ["CWE-79"], "TECHNIQUES": ["1059"],
                                               "CVSS": {"vector": NET}}})["entities"]
    tech = ents["CVE-2024-0013"]["rels"]["technique"]
    assert tech["ids"] == ["T1059"] and "link_prov" not in tech


def test_without_ctid_db_nothing_is_derived_for_legacy_shards(tmp_path):
    ents = _build(tmp_path, {"CVE-2024-0012": MEMORY}, ctid_db=None)["entities"]
    assert "technique" not in ents["CVE-2024-0012"]["rels"]


def test_kev_only_cve_gets_its_ctid_links(tmp_path):
    ents = _build(tmp_path, {"CVE-2024-0012": MEMORY}, kev_only=["CVE-2025-0099"])["entities"]
    prov = ents["CVE-2025-0099"]["rels"]["technique"]["link_prov"]
    assert prov["T1068"]["tier"] == "official"


def test_legacy_index_readers_see_the_same_shape(tmp_path):
    """Every rel body keeps ids/source/tier; link_prov only names live ids."""
    ents = _build(tmp_path, {"CVE-2024-0010": MEMORY, "CVE-2024-0012": MEMORY})["entities"]
    for eid, e in ents.items():
        for rel, body in e["rels"].items():
            assert {"ids", "source", "tier"} <= set(body), (eid, rel)
            assert set(body.get("link_prov", {})) <= set(body["ids"]), (eid, rel)


# ── ISC-12: the curated set does not move ────────────────────────────


def test_curated_set_is_identical_with_and_without_ctid(tmp_path):
    records = {"CVE-2024-0010": MEMORY, "CVE-2024-0001": dict(NEW_RECORD, CVSS={"vector": NET}),
               "CVE-2024-0012": MEMORY}
    with_ctid = _build(tmp_path / "a", records)["entities"]
    without = _build(tmp_path / "b", records, ctid_db=None)["entities"]
    curated = lambda ents: {k for k, v in ents.items() if v["type"] == "cve"}  # noqa: E731
    assert curated(with_ctid) == curated(without)


def test_process_file_reads_ctid_db_after_the_database_step(tmp_path, monkeypatch):
    """ctid_db.json is read in process_file, not at construction, so the
    orchestrator's processor sees the file the database step just wrote."""
    import tip.core.cve_processor as cve_mod

    path = tmp_path / "ctid_db.json"
    path.write_text(json.dumps({"meta": {}, "cves": CTID_DB}))

    class _Cfg:
        def get(self, key, default=None):
            return str(path) if key == "database.ctid.file" else default

    monkeypatch.setattr(cve_mod, "config", _Cfg())
    proc, _ = _processor(ctid_db=None)
    proc._load_ctid()
    assert proc.ctid_db == CTID_DB
    path.unlink()
    proc._load_ctid()
    assert proc.ctid_db is None
