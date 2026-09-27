"""I30 and I32: a CVE links to an APT group only when the ATT&CK bundle
cites that CVE for that group, and every link carries the citing object.

Technique overlap (a group uses a technique the CVE maps to) never links a
CVE to a group, in the processor, the entity index, the MCP, or the change
log. Every test runs on a fixture STIX bundle; nothing touches the network.
"""

from __future__ import annotations

import gzip
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

from tip.core import change_log as cl
from tip.core.apt_processor import APTProcessor, extract_attributions
from tip.core.cve_processor import CVEProcessor
from tip.core.entity_index_generator import generate_entity_index, write_outputs
from tip_mcp.loader import IndexLoader
from tip_mcp.tools import lookup_entity_impl, pivot_from_entity_impl


# ── Fixture STIX bundle ─────────────────────────────────────────────

def _ext(attack_id: str, *refs: dict) -> list:
    return [{"source_name": "mitre-attack", "external_id": attack_id}, *refs]


def _obj(stix_type: str, stix_id: str, attack_id: str = "", description: str = "",
         refs: Optional[list] = None, **extra: Any) -> dict:
    obj: dict = {"type": stix_type, "id": f"{stix_type}--{stix_id}", "description": description}
    obj["external_references"] = _ext(attack_id, *(refs or [])) if attack_id else list(refs or [])
    obj.update(extra)
    return obj


def _rel(rel_id: str, source: dict, target: dict, rel_type: str = "uses", description: str = "",
         refs: Optional[list] = None, **extra: Any) -> dict:
    return {"type": "relationship", "id": f"relationship--{rel_id}", "relationship_type": rel_type,
            "source_ref": source["id"], "target_ref": target["id"], "description": description,
            "external_references": list(refs or []), **extra}


G1 = _obj("intrusion-set", "g1", "G0001", "Group One exploited CVE-2020-0001 in 2020.", name="Group One")
G2 = _obj("intrusion-set", "g2", "G0002", "Group Two.", name="Group Two",
          refs=[{"source_name": "Vendor", "description": "Report on CVE-2020-0002", "url": "https://x.test/a"}])
G3 = _obj("intrusion-set", "g3", "G0003", "Group Three.", name="Group Three")
G_REVOKED = _obj("intrusion-set", "g9", "G0009", "Revoked group used CVE-2020-0099.", name="Old", revoked=True)
T1190 = _obj("attack-pattern", "t1190", "T1190", "Exploit Public-Facing Application", name="Exploit")
T1203 = _obj("attack-pattern", "t1203", "T1203", "Exploitation for Client Execution", name="Client")
S1 = _obj("malware", "s1", "S0001", "Malware that exploits CVE-2020-0098.", name="Bad")
C1 = _obj("campaign", "c1", "C0001", "Campaign One exploited CVE-2020-0004.", name="Campaign One")
C2 = _obj("campaign", "c2", "C0002", "Unattributed campaign used CVE-2020-0097.", name="Campaign Two")
C_DEP = _obj("campaign", "c9", "C0009", "Deprecated campaign used CVE-2020-0096.", name="Dep",
             x_mitre_deprecated=True)

BUNDLE = {"type": "bundle", "objects": [
    G1, G2, G3, G_REVOKED, T1190, T1203, S1, C1, C2, C_DEP,
    # Relationship sourced from a group: description, then an external ref url.
    _rel("r1", G3, T1190, description="Group Three exploited CVE-2020-0003."),
    _rel("r2", G2, T1203, refs=[{"source_name": "Blog", "url": "https://x.test/CVE-2020-0005"}]),
    # A group using malware is still group-sourced: in scope.
    _rel("r3", G1, S1, description="Group One deployed Bad through CVE-2020-0006."),
    # Campaign attributed to Group Two, and a relationship sourced from it.
    _rel("r4", C1, G2, rel_type="attributed-to"),
    _rel("r5", C1, T1190, description="During Campaign One the actors exploited CVE-2020-0007."),
    # The same pair cited twice: the group's own description wins.
    _rel("r6", G1, T1203, description="Group One also used CVE-2020-0001 here."),
    # Exclusions: revoked and deprecated citing objects, a revoked
    # attributed-to, an unattributed campaign, a software object's own text.
    _rel("r7", G3, T1203, description="Revoked link cited CVE-2020-0095.", revoked=True),
    _rel("r8", G3, T1190, description="Deprecated link cited CVE-2020-0094.", x_mitre_deprecated=True),
    _rel("r9", C_DEP, G3, rel_type="attributed-to"),
    _rel("r10", C2, G3, rel_type="attributed-to", revoked=True),
    # Overlap bait: Group Three uses T1190 with no CVE cited.
    _rel("r11", G3, T1190),
]}

EXPECTED = {
    "CVE-2020-0001": [{"id": "G0001", "via": "G0001", "via_type": "intrusion-set"}],
    "CVE-2020-0002": [{"id": "G0002", "via": "G0002", "via_type": "intrusion-set"}],
    "CVE-2020-0003": [{"id": "G0003", "via": "G0003", "via_type": "relationship", "via_target": "T1190"}],
    "CVE-2020-0004": [{"id": "G0002", "via": "C0001", "via_type": "campaign"}],
    "CVE-2020-0005": [{"id": "G0002", "via": "G0002", "via_type": "relationship", "via_target": "T1203"}],
    "CVE-2020-0006": [{"id": "G0001", "via": "G0001", "via_type": "relationship", "via_target": "S0001"}],
    "CVE-2020-0007": [{"id": "G0002", "via": "C0001", "via_type": "relationship", "via_target": "T1190"}],
}


# ── ISC-1: extraction ───────────────────────────────────────────────

def test_isc1_extractor_returns_exact_pairs_for_every_source_kind():
    assert extract_attributions(BUNDLE) == EXPECTED


def test_isc1_each_exclusion_holds():
    cves = set(extract_attributions(BUNDLE))
    for excluded in ("CVE-2020-0099",   # revoked intrusion-set
                     "CVE-2020-0098",   # cited on software only (two hop, out of scope)
                     "CVE-2020-0097",   # campaign whose attributed-to is revoked
                     "CVE-2020-0096",   # deprecated campaign
                     "CVE-2020-0095",   # revoked relationship
                     "CVE-2020-0094"):  # deprecated relationship
        assert excluded not in cves, excluded


def test_isc1_duplicate_citations_dedupe_to_one_entry_by_rank():
    """CVE-2020-0001 is cited by G0001's description and by one of its
    relationships: one entry, the intrusion-set evidence."""
    assert extract_attributions(BUNDLE)["CVE-2020-0001"] == [
        {"id": "G0001", "via": "G0001", "via_type": "intrusion-set"}]
    # Rank is independent of bundle order.
    reordered = {"objects": list(reversed(BUNDLE["objects"]))}
    assert extract_attributions(reordered) == EXPECTED


def test_isc1_one_cve_many_groups_sorted():
    bundle = {"objects": BUNDLE["objects"] + [
        _rel("r12", G3, T1203, description="Group Three too: CVE-2020-0004.")]}
    assert extract_attributions(bundle)["CVE-2020-0004"] == [
        {"id": "G0002", "via": "C0001", "via_type": "campaign"},
        {"id": "G0003", "via": "G0003", "via_type": "relationship", "via_target": "T1203"},
    ]


def test_isc1_groups_db_carries_attributions():
    db = APTProcessor()._process_stix_data(BUNDLE)
    assert db["attributions"] == EXPECTED
    assert set(db["groups"]) == {"G0001", "G0002", "G0003"}
    # The official group to technique links stay.
    assert "T1190" in db["groups"]["G0003"]["techniques"]


# ── Processor (ISC-3, ISC-4) ────────────────────────────────────────

def _processor(groups_db: dict) -> CVEProcessor:
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.cwe_db = {"20": {"ChildOf": [], "RelatedAttackPatterns": ["10"]}}
    proc.capec_db = {"10": {"techniques": "::TAXONOMY NAME:ATTACK:ENTRY ID:1190::"}}
    proc.techniques_db = {}
    proc.logger = logging.getLogger("test_i32")
    proc.owasp_processor = SimpleNamespace(get_owasp_categories_for_cwes=lambda cwes: set())
    proc.kev_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.vulnrichment_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.get_defend_techniques = lambda t: []
    proc.apt_processor = APTProcessor()
    proc.apt_processor.groups_db = groups_db
    return proc


def test_isc4_processor_writes_apt_groups_from_attribution_with_evidence():
    proc = _processor(APTProcessor()._process_stix_data(BUNDLE))
    out = proc.process_cve_pipeline({"CVE-2020-0007": {"CWE": ["CWE-20"]}})
    assert out["CVE-2020-0007"]["APT_GROUPS"] == [
        {"id": "G0002", "name": "Group Two", "via": "C0001", "via_type": "relationship", "via_target": "T1190"}]


def test_isc3_technique_a_group_uses_without_citation_links_nothing():
    """CVE-2020-0050 maps to T1190 through CWE-20; Group Three uses T1190;
    ATT&CK cites no CVE there. No APT_GROUPS."""
    proc = _processor(APTProcessor()._process_stix_data(BUNDLE))
    rec = proc.process_cve_pipeline({"CVE-2020-0050": {"CWE": ["CWE-20"]}})["CVE-2020-0050"]
    assert rec["TECHNIQUES"] == ["1190"]
    assert "APT_GROUPS" not in rec


def test_isc4_process_file_reloads_groups_db_the_database_step_wrote(tmp_path, monkeypatch):
    """The processor is built before the database step; process_file reads
    groups_db.json again, so this run's attribution reaches the shards."""
    db_path = tmp_path / "groups_db.json"
    db_path.write_text(json.dumps({"groups": {}}))
    proc = _processor({})
    proc.apt_processor.db_path = str(db_path)
    proc.apt_processor.load()
    db_path.write_text(json.dumps(APTProcessor()._process_stix_data(BUNDLE)))
    seen: dict = {}
    monkeypatch.setattr(proc, "_load_epss", lambda: None)
    monkeypatch.setattr(proc, "_load_ctid", lambda: None)
    monkeypatch.setattr(proc, "save_results", lambda results: seen.update(results))
    proc.cve_file = str(tmp_path / "in.jsonl")
    Path(proc.cve_file).write_text(json.dumps({"CVE-2020-0003": {"CWE": ["CWE-20"]}}) + "\n")
    proc.last_enrichment = None
    assert proc.process_file() is True
    assert [g["id"] for g in seen["CVE-2020-0003"]["APT_GROUPS"]] == ["G0003"]


# ── Entity index (ISC-5, ISC-6, ISC-9) ──────────────────────────────

KEV = {"inKEV": True, "dateAdded": "2024-01-01", "vendorProject": "V", "product": "P"}


def _base(base: Path, shards: dict, groups_db: dict, kev: Optional[dict] = None) -> Path:
    data = base / "docs" / "data"
    db = base / "docs" / "database"
    data.mkdir(parents=True)
    db.mkdir(parents=True)
    (data / "cwe_db.json").write_text(json.dumps({"20": {"name": "Input", "ChildOf": [],
                                                         "RelatedAttackPatterns": ["10"]}}))
    (data / "capec_db.json").write_text(json.dumps(
        {"10": {"name": "Pattern", "techniques": "::TAXONOMY NAME:ATTACK:ENTRY ID:1190::"}}))
    (data / "techniques_db.json").write_text(json.dumps({"1190": {"name": "Exploit"}, "1203": {"name": "Client"}}))
    (data / "groups_db.json").write_text(json.dumps(groups_db))
    (data / "campaigns_db.json").write_text(json.dumps(
        {"C0001": {"name": "Campaign One", "groups": ["G0002"], "techniques": ["T1190"]}}))
    (data / "kev_db.json").write_text(json.dumps(kev or {}))
    (data / "vulnrichment_db.json").write_text("{}")
    (data / "defend_db.jsonl").write_text("")
    with gzip.open(db / "CVE-2020.jsonl.gz", "wt") as f:
        for k, v in shards.items():
            f.write(json.dumps({k: v}) + "\n")
    return base


def _groups_db() -> dict:
    return APTProcessor()._process_stix_data(BUNDLE)


def _legacy_groups_db() -> dict:
    db = _groups_db()
    del db["attributions"]
    return db


# CVE-2020-0003 (cited, KEV), CVE-2020-0004 (cited via campaign, not KEV),
# CVE-2020-0050 (KEV, maps to T1190 which G0003 uses, never cited).
SHARDS = {
    "CVE-2020-0003": {"CWE": ["CWE-20"], "TECHNIQUES": ["1190"]},
    "CVE-2020-0004": {"CWE": ["CWE-20"], "TECHNIQUES": ["1190"]},
    "CVE-2020-0050": {"CWE": ["CWE-20"], "TECHNIQUES": ["1190"]},
    "CVE-2020-0060": {"CWE": ["CWE-20"], "TECHNIQUES": ["1190"]},
}
KEV_DB = {"CVE-2020-0003": KEV, "CVE-2020-0050": KEV}


def _index(tmp_path: Path, shards: dict = SHARDS, groups_db: Optional[dict] = None) -> dict:
    base = _base(tmp_path, shards, _groups_db() if groups_db is None else groups_db, KEV_DB)
    return generate_entity_index(base)[0]


def test_isc5_cited_cve_outside_kev_is_curated_by_the_unchanged_rule(tmp_path):
    ents = _index(tmp_path)["entities"]
    cves = sorted(k for k, e in ents.items() if e["type"] == "cve")
    # 0004 is not in KEV and has no SSVC: attribution alone curates it. 0060
    # (T1190, uncited, not KEV) stays out.
    assert cves == ["CVE-2020-0003", "CVE-2020-0004", "CVE-2020-0050"]


def test_isc5_groups_db_wins_over_stale_shard_apt_groups(tmp_path):
    """Shards are rewritten weekly, groups_db.json daily: a shard entry
    ATT&CK no longer cites does not curate or link."""
    shards = dict(SHARDS, **{"CVE-2020-0060": {"CWE": ["CWE-20"], "APT_GROUPS": [
        {"id": "G0001", "via": "G0001", "via_type": "intrusion-set"}]}})
    ents = _index(tmp_path, shards)["entities"]
    assert "CVE-2020-0060" not in ents


def test_isc6_index_links_are_official_with_evidence_both_directions(tmp_path):
    ei = _index(tmp_path)
    ents = ei["entities"]
    assert ei["meta"]["apt_attribution"] is True
    fwd = ents["CVE-2020-0004"]["rels"]["apt_group"]
    assert fwd["ids"] == ["G0002"]
    assert (fwd["source"], fwd["tier"]) == ("MITRE ATT&CK", "official")
    assert fwd["link_prov"] == {"G0002": {"source": "MITRE ATT&CK", "tier": "official",
                                          "via": "C0001", "via_type": "campaign"}}
    back = ents["G0003"]["rels"]["cve"]
    assert back["ids"] == ["CVE-2020-0003"]
    assert (back["source"], back["tier"]) == ("MITRE ATT&CK", "official")
    assert back["link_prov"]["CVE-2020-0003"] == {"source": "MITRE ATT&CK", "tier": "official", "via": "G0003",
                                                  "via_type": "relationship", "via_target": "T1190"}


def test_isc6_group_page_lists_only_attributed_cves(tmp_path):
    """G0003 uses T1190, and three curated CVEs map to T1190; only the one
    ATT&CK cites is on its page. No rel anywhere says technique overlap."""
    ei = _index(tmp_path)
    ents = ei["entities"]
    assert ents["G0003"]["rels"]["cve"]["ids"] == ["CVE-2020-0003"]
    assert "apt_group" not in ents["CVE-2020-0050"]["rels"]
    assert "overlap" not in json.dumps(ei)
    # Official group to technique and campaign to group links stay.
    assert "G0003" in ents["T1190"]["rels"]["apt_group"]["ids"]
    assert ents["C0001"]["rels"]["apt_group"]["ids"] == ["G0002"]


def test_isc6_kev_cve_without_shard_still_gets_its_attribution(tmp_path):
    base = _base(tmp_path, {}, _groups_db(), {"CVE-2020-0001": KEV})
    ents = generate_entity_index(base)[0]["entities"]
    assert ents["CVE-2020-0001"]["rels"]["apt_group"]["ids"] == ["G0001"]


def test_isc9_legacy_groups_db_and_overlap_shards_give_no_links(tmp_path):
    """A groups_db.json from before I32 (no attributions) and shards whose
    APT_GROUPS is the old overlap shape: generation succeeds, nothing is
    linked, nothing is curated by it."""
    shards = {k: dict(v, APT_GROUPS=[{"id": "G0003", "name": "Group Three", "aliases": [],
                                      "techniques_overlap": ["T1190"]}, "G0001"])
              for k, v in SHARDS.items()}
    ei = _index(tmp_path, shards, _legacy_groups_db())
    ents = ei["entities"]
    assert sorted(k for k, e in ents.items() if e["type"] == "cve") == ["CVE-2020-0003", "CVE-2020-0050"]
    assert all("apt_group" not in e["rels"] for e in ents.values() if e["type"] == "cve")
    assert "cve" not in ents["G0003"]["rels"]


def test_isc9_legacy_groups_db_uses_shard_entries_that_carry_evidence(tmp_path):
    shards = dict(SHARDS, **{"CVE-2020-0060": {"CWE": ["CWE-20"], "APT_GROUPS": [
        {"id": "G0001", "via": "G0001", "via_type": "intrusion-set"}]}})
    ents = _index(tmp_path, shards, _legacy_groups_db())["entities"]
    assert ents["CVE-2020-0060"]["rels"]["apt_group"]["link_prov"]["G0001"]["via"] == "G0001"


# ── MCP (ISC-8, ISC-9) ──────────────────────────────────────────────

def _written(tmp_path: Path) -> IndexLoader:
    base = _base(tmp_path, SHARDS, _groups_db(), KEV_DB)
    write_outputs(*generate_entity_index(base)[:2], base)
    ld = IndexLoader(base / "docs" / "data", shards_dir=base / "docs" / "database")
    ld.load()
    return ld


def test_isc8_index_backed_tools_return_attributed_rels_with_evidence(tmp_path):
    ld = _written(tmp_path)
    rels = [r for r in lookup_entity_impl(ld, "CVE-2020-0004")["data"]["rels"] if r["rel_type"] == "apt_group"]
    assert rels == [{"target_id": "G0002", "rel_type": "apt_group", "source": "MITRE ATT&CK",
                     "tier": "official", "via": "C0001", "via_type": "campaign"}]
    hits = pivot_from_entity_impl(ld, "G0003", "cve")["data"]
    assert [(h["id"], h["tier"], h["via"], h["via_type"], h["via_target"]) for h in hits] == [
        ("CVE-2020-0003", "official", "G0003", "relationship", "T1190")]
    # The uncited KEV CVE on T1190 answers with no group.
    assert pivot_from_entity_impl(ld, "CVE-2020-0050", "apt_group")["data"] == []


def test_isc8_shard_path_projects_no_overlap_groups(tmp_path):
    """CVE-2020-0060 is not curated; its shard reaches T1190, which G0003
    uses in the graph. The shard path adds no group."""
    ld = _written(tmp_path)
    resp = lookup_entity_impl(ld, "CVE-2020-0060")
    assert resp["meta"]["source"] == "shard"
    assert [r for r in resp["data"]["rels"] if r["rel_type"] == "apt_group"] == []


LEGACY_OVERLAP = {"ids": ["G0003"], "source": "Pipeline (technique overlap)", "tier": "derived"}


def _legacy_index(tmp_path: Path, meta: dict) -> IndexLoader:
    ents = {
        "CVE-2020-0050": {"type": "cve", "id": "CVE-2020-0050", "name": "x", "rels": {
            "apt_group": LEGACY_OVERLAP,
            "technique": {"ids": ["T1190"], "source": "chain", "tier": "derived"}}},
        "G0003": {"type": "apt_group", "id": "G0003", "name": "Group Three", "rels": {
            "cve": dict(LEGACY_OVERLAP, ids=["CVE-2020-0050"]),
            "technique": {"ids": ["T1190"], "source": "MITRE ATT&CK", "tier": "official"}}},
        "T1190": {"type": "technique", "id": "T1190", "name": "Exploit", "rels": {
            "apt_group": {"ids": ["G0003"], "source": "MITRE ATT&CK", "tier": "official"},
            "cve": {"ids": ["CVE-2020-0050"], "source": "chain", "tier": "derived"}}},
    }
    (tmp_path / "entity_index.json").write_text(json.dumps({"meta": meta, "entities": ents}))
    (tmp_path / "search_index.json").write_text("{}")
    ld = IndexLoader(tmp_path)
    ld.load()
    return ld


def test_isc9_legacy_index_answers_without_overlap_links(tmp_path):
    ld = _legacy_index(tmp_path, {"link_provenance": True})
    cve = lookup_entity_impl(ld, "CVE-2020-0050")
    assert cve["ok"] is True
    assert {r["rel_type"] for r in cve["data"]["rels"]} == {"technique"}
    assert pivot_from_entity_impl(ld, "G0003", "cve")["data"] == []
    # Official links to the group stay.
    assert [h["id"] for h in pivot_from_entity_impl(ld, "G0003", "technique")["data"]] == ["T1190"]
    assert [h["id"] for h in pivot_from_entity_impl(ld, "T1190", "apt_group")["data"]] == ["G0003"]


def test_isc9_flagged_index_keeps_its_links(tmp_path):
    """The drop is keyed on the flag, not the label: an I32 index is read as is."""
    ld = _legacy_index(tmp_path, {"apt_attribution": True})
    assert [h["id"] for h in pivot_from_entity_impl(ld, "CVE-2020-0050", "apt_group")["data"]] == ["G0003"]


# ── ISC-10: change log related ids ──────────────────────────────────

def test_isc10_change_log_related_groups_come_from_attribution(tmp_path):
    ei = _index(tmp_path)
    graph = cl.project_entities(ei)
    assert graph is not None
    assert graph["CVE-2020-0004"]["apt_group"] == ["G0002"]
    # The uncited CVE on a technique G0003 uses carries no group, so a G0003
    # watch does not match it.
    assert "apt_group" not in graph["CVE-2020-0050"]
    before = {"entity_index": {k: dict(v, cvss=1.0) for k, v in graph.items()}}
    events = cl.compute_events(before, {"entity_index": graph}, ["entity_index"], "2026-09-27")
    watching_g3 = [e["cve"] for e in events if "G0003" in e.get("related", {}).get("apt_group", [])]
    assert watching_g3 == ["CVE-2020-0003"]


def test_isc10_legacy_index_gives_no_related_groups(tmp_path):
    legacy = {"meta": {"link_provenance": True}, "entities": {
        "CVE-2020-0050": {"type": "cve", "cvss_score": 9.8, "rels": {
            "apt_group": LEGACY_OVERLAP, "technique": {"ids": ["T1190"]}}}}}
    graph = cl.project_entities(legacy)
    assert graph == {"CVE-2020-0050": {"cvss": 9.8, "technique": ["T1190"]}}
    # Backfill from a legacy graph cannot add overlap groups to an event.
    ev = [{"date": "2026-09-27", "type": "kev_added", "cve": "CVE-2020-0050"}]
    cl.backfill_related(ev, graph)
    assert "apt_group" not in ev[0].get("related", {})
