"""I29 (ISC-11 to ISC-14): the MCP tools flag links reached only through an
inherited parent CWE, reading the index's inherited subsets. Legacy indexes
and shards (no inherited fields) produce exactly today's output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from tip_mcp.loader import IndexLoader
from tip_mcp.tools import (
    build_attack_chain_impl,
    get_defenses_impl,
    lookup_entity_impl,
    pivot_from_entity_impl,
)

from .sweeps import all_tier_violations, chain_cve_mismatches, chain_inherited_cwe_violations


def _rel(ids: list, source: str = "Test", tier: str = "derived", inherited: Optional[list] = None) -> dict:
    body: dict = {"ids": ids, "source": source, "tier": tier}
    if inherited:
        body["inherited"] = inherited
    return body


def _load(tmp_path: Path, entities: dict, meta: Optional[dict] = None, shard: Optional[dict] = None,
          cwe_db: Optional[dict] = None) -> IndexLoader:
    for eid, ent in entities.items():
        ent.setdefault("id", eid)
        ent.setdefault("name", eid)
        ent.setdefault("rels", {})
    (tmp_path / "entity_index.json").write_text(json.dumps({"meta": meta or {}, "entities": entities}))
    (tmp_path / "search_index.json").write_text("{}")
    if cwe_db is not None:
        (tmp_path / "cwe_db.json").write_text(json.dumps(cwe_db))
    shards = tmp_path / "database"
    shards.mkdir(exist_ok=True)
    for cve_id, payload in (shard or {}).items():
        (shards / f"CVE-{cve_id.split('-')[1]}.jsonl").write_text(json.dumps({cve_id: payload}) + "\n")
    ld = IndexLoader(tmp_path, shards_dir=shards)
    ld.load()
    return ld


CHAIN = "Pipeline (CAPEC→Technique chain)"
NVD = "NVD Enrichment"


def _graph(inherited: bool = True) -> dict:
    """T9001 <- CAPEC-900 <- CWE-900. CVE-A is assigned CWE-900. CVE-B is
    assigned CWE-901 (no path) and inherits its parent CWE-900, so it reaches
    T9001 only through the parent. CWE-902 reaches CAPEC-900 only through an
    ancestor. With inherited=False the same graph has no inherited fields."""
    inh = (lambda ids: ids) if inherited else (lambda ids: None)
    g = {
        "T9001": {"type": "technique", "rels": {
            "cve": _rel(["CVE-2020-0001", "CVE-2020-0002"], CHAIN, "derived", inh(["CVE-2020-0002"])),
            "defend": _rel(["D3-A"], "MITRE D3FEND", "official"),
        }},
        "T9002": {"type": "technique", "rels": {
            "defend": _rel(["D3-A", "D3-C"], "MITRE D3FEND", "official"),
        }},
        "CAPEC-900": {"type": "capec", "rels": {"technique": _rel(["T9001"], "MITRE CAPEC Database", "official")}},
        "CWE-900": {"type": "cwe", "rels": {
            "capec": _rel(["CAPEC-900"], "MITRE CWE Database", "official"),
            "cve": _rel(["CVE-2020-0001"], NVD, "authoritative"),
        }},
        "CWE-901": {"type": "cwe", "rels": {"cve": _rel(["CVE-2020-0002"], NVD, "authoritative")}},
        "CWE-902": {"type": "cwe", "rels": {
            "capec": _rel(["CAPEC-900"], "MITRE CWE Database", "official", inh(["CAPEC-900"])),
        }},
        "CVE-2020-0001": {"type": "cve", "kev": True, "rels": {
            "cwe": _rel(["CWE-900"], NVD, "authoritative"),
            "technique": _rel(["T9001"], CHAIN),
            "defend": _rel(["D3-A"], "Pipeline (Technique→D3FEND chain)"),
        }},
        "CVE-2020-0002": {"type": "cve", "kev": False, "rels": {
            "cwe": _rel(["CWE-901"], NVD, "authoritative"),
            "technique": _rel(["T9001"], CHAIN, "derived", inh(["T9001"])),
            "defend": _rel(["D3-A"], "Pipeline (Technique→D3FEND chain)", "derived", inh(["D3-A"])),
        }},
        "CVE-2020-0003": {"type": "cve", "kev": False, "rels": {
            "technique": _rel(["T9001", "T9002"], CHAIN, "derived", inh(["T9002"])),
            "defend": _rel(["D3-A", "D3-C"], "Pipeline (Technique→D3FEND chain)", "derived", inh(["D3-C"])),
        }},
        "D3-A": {"type": "defend"},
        "D3-C": {"type": "defend"},
    }
    if inherited:
        g["CVE-2020-0002"]["cwe_inherited"] = ["CWE-900"]
        g["CVE-2020-0001"]["cwe_inherited"] = []
    return g


META = {"inherited_links": True}


# ISC-11 --------------------------------------------------------------------------

def test_isc11_pivot_hits_flag_inherited_links(tmp_path):
    ld = _load(tmp_path, _graph(), META)
    hits = pivot_from_entity_impl(ld, "CVE-2020-0002", "technique")["data"]
    assert [(h["id"], h.get("inherited")) for h in hits] == [("T9001", True)]
    direct = pivot_from_entity_impl(ld, "CVE-2020-0001", "technique")["data"]
    assert "inherited" not in direct[0]
    back = {h["id"]: h.get("inherited") for h in pivot_from_entity_impl(ld, "T9001", "cve")["data"]}
    assert back == {"CVE-2020-0001": None, "CVE-2020-0002": True}
    capecs = pivot_from_entity_impl(ld, "CWE-902", "capec")["data"]
    assert capecs[0]["inherited"] is True


def test_isc11_lookup_rels_flag_inherited_and_carry_cwe_inherited(tmp_path):
    ld = _load(tmp_path, _graph(), META)
    rec = lookup_entity_impl(ld, "CVE-2020-0002")["data"]
    assert rec["cwe_inherited"] == ["CWE-900"]
    flags = {(r["rel_type"], r["target_id"]): r.get("inherited") for r in rec["rels"]}
    assert flags[("technique", "T9001")] is True
    assert flags[("cwe", "CWE-901")] is None


NEW_SHARD = {
    "CWE": ["CWE-901"], "CWE_INHERITED": ["CWE-900"],
    "CAPEC": [], "CAPEC_INHERITED": ["900"],
    "TECHNIQUES": ["9002"], "TECHNIQUES_INHERITED": ["9001"],
    "OWASP": [], "OWASP_INHERITED": ["A05:2021"],
    "DEFEND": [{"id": "D3-C"}, {"id": "D3-A", "inherited": True}],
}


def test_isc11_shard_pivot_flags_inherited_and_keeps_cwe_rels_assigned(tmp_path):
    ld = _load(tmp_path, _graph(), META, shard={"CVE-2021-0009": NEW_SHARD})
    hits = {(h["rel_type"], h["id"]): h.get("inherited")
            for h in pivot_from_entity_impl(ld, "CVE-2021-0009")["data"]}
    assert hits[("cwe", "CWE-901")] is None
    assert ("cwe", "CWE-900") not in hits
    assert hits[("capec", "CAPEC-900")] is True
    assert hits[("technique", "T9001")] is True and hits[("technique", "T9002")] is None
    assert hits[("owasp", "A05:2021")] is True
    assert hits[("defend", "D3-A")] is True and hits[("defend", "D3-C")] is None
    rec = lookup_entity_impl(ld, "CVE-2021-0009")["data"]
    assert rec["cwe_inherited"] == ["CWE-900"]


# ISC-12 --------------------------------------------------------------------------

def test_isc12_chain_explains_cve_through_inherited_cwe(tmp_path):
    ld = _load(tmp_path, _graph(), META)
    resp = build_attack_chain_impl(ld, "T9001")
    cves = {c["id"]: c for c in resp["data"]["cves"]}
    b = cves["CVE-2020-0002"]
    assert b["via_cwes"] == ["CWE-900"] and b["via_capecs"] == ["CAPEC-900"]
    assert b["inherited_cwes"] == ["CWE-900"]
    assert b["inherited"] is True
    assert b["tier"] == "derived"
    a = cves["CVE-2020-0001"]
    assert "inherited_cwes" not in a and "inherited" not in a
    cwe = {c["id"]: c for c in resp["data"]["cwes"]}["CWE-900"]
    assert cwe["inherited_parent"] is True
    assert cwe["inherited"] is False  # its CAPEC hop is its own


def test_isc12_chain_prefers_assigned_path(tmp_path):
    g = _graph()
    g["CWE-901"]["rels"]["capec"] = _rel(["CAPEC-900"], "MITRE CWE Database", "official")
    ld = _load(tmp_path, g, META)
    b = {c["id"]: c for c in build_attack_chain_impl(ld, "T9001")["data"]["cves"]}["CVE-2020-0002"]
    assert b["via_cwes"] == ["CWE-901"] and "inherited_cwes" not in b


def test_isc12_chain_reads_cwe_capec_inherited_from_index_without_cwe_db(tmp_path):
    g = _graph()
    g["CVE-2020-0001"]["rels"]["cwe"] = _rel(["CWE-900", "CWE-902"], NVD, "authoritative")
    ld = _load(tmp_path, g, META)
    resp = build_attack_chain_impl(ld, "T9001")
    cwes = {c["id"]: c for c in resp["data"]["cwes"]}
    assert cwes["CWE-902"]["inherited"] is True and cwes["CWE-902"]["inherited_capecs"] == ["CAPEC-900"]
    assert cwes["CWE-902"]["tier"] == "derived"
    assert cwes["CWE-900"]["inherited"] is False and cwes["CWE-900"]["tier"] == "official"
    assert "cwe_db_note" not in resp["meta"]


# ISC-13 --------------------------------------------------------------------------

def test_isc13_defenses_flag_inherited_only(tmp_path):
    ld = _load(tmp_path, _graph(), META)
    b = get_defenses_impl(ld, cve_id="CVE-2020-0002")["data"]
    assert [(d["id"], d.get("inherited")) for d in b] == [("D3-A", True)]
    c = {d["id"]: d.get("inherited") for d in get_defenses_impl(ld, cve_id="CVE-2020-0003")["data"]}
    assert c == {"D3-A": None, "D3-C": True}
    a = get_defenses_impl(ld, cve_id="CVE-2020-0001")["data"]
    assert "inherited" not in a[0]


def test_isc13_shard_defenses_flag_inherited(tmp_path):
    ld = _load(tmp_path, _graph(), META, shard={"CVE-2021-0009": NEW_SHARD})
    defs = {d["id"]: d.get("inherited") for d in get_defenses_impl(ld, cve_id="CVE-2021-0009")["data"]}
    # D3-A: via T9001 (inherited) and T9002 (direct) -> not inherited.
    assert defs == {"D3-A": None, "D3-C": None}
    only_inh = dict(NEW_SHARD, TECHNIQUES=[], DEFEND=[{"id": "D3-A", "inherited": True}])
    (tmp_path / "x").mkdir()
    ld2 = _load(tmp_path / "x", _graph(), META, shard={"CVE-2021-0009": only_inh})
    defs2 = {d["id"]: d.get("inherited") for d in get_defenses_impl(ld2, cve_id="CVE-2021-0009")["data"]}
    assert defs2 == {"D3-A": True}


# ISC-14 / legacy -----------------------------------------------------------------

def test_isc14_sweeps_hold_on_inherited_graph(tmp_path):
    ld = _load(tmp_path, _graph(), META, cwe_db={"900": {"RelatedAttackPatterns": ["900"]},
                                                  "902": {"RelatedAttackPatterns": []}})
    assert chain_cve_mismatches(ld) == []
    report = all_tier_violations(ld)
    assert report["chain_violations"] == [] and report["defense_violations"] == []
    assert chain_inherited_cwe_violations(ld) == []


def test_legacy_index_and_shard_output_has_no_inherited_fields(tmp_path):
    legacy_shard = {"CWE": ["CWE-901", "900"], "CAPEC": ["900"], "TECHNIQUES": ["9001"],
                    "OWASP": ["A05:2021"], "DEFEND": [{"id": "D3-A"}]}
    ld = _load(tmp_path, _graph(inherited=False), shard={"CVE-2021-0009": legacy_shard},
               cwe_db={"900": {"RelatedAttackPatterns": ["900"]}, "902": {"RelatedAttackPatterns": ["900"]}})
    outputs = [
        pivot_from_entity_impl(ld, "CVE-2020-0002"),
        pivot_from_entity_impl(ld, "T9001", "cve"),
        pivot_from_entity_impl(ld, "CVE-2021-0009"),
        lookup_entity_impl(ld, "CVE-2020-0002"),
        lookup_entity_impl(ld, "CVE-2021-0009"),
        build_attack_chain_impl(ld, "T9001"),
        get_defenses_impl(ld, cve_id="CVE-2020-0002"),
        get_defenses_impl(ld, cve_id="CVE-2021-0009"),
    ]
    text = json.dumps(outputs)
    assert "inherited_cwes" not in text and "cwe_inherited" not in text and "inherited_parent" not in text
    for out in outputs[:5] + outputs[6:]:
        assert '"inherited"' not in json.dumps(out)
    # Legacy shard CWE lists still project every listed CWE.
    hits = {h["id"] for h in outputs[2]["data"] if h["rel_type"] == "cwe"}
    assert hits == {"CWE-901", "CWE-900"}


# Review fixes --------------------------------------------------------------------

def test_chain_via_capecs_are_only_capecs_the_cve_credits(tmp_path):
    """A CWE can reach a chain CAPEC the CVE itself no longer credits (e.g. a
    pillar CAPEC the processor dropped). The CVE element never names it, and
    a CWE whose chain CAPECs the CVE credits none of does not explain it."""
    g = _graph()
    g["CAPEC-901"] = {"type": "capec", "rels": {"technique": _rel(["T9001"], "MITRE CAPEC Database", "official")}}
    g["CWE-900"]["rels"]["capec"] = _rel(["CAPEC-900", "CAPEC-901"], "MITRE CWE Database", "official")
    g["CWE-903"] = {"type": "cwe", "rels": {"capec": _rel(["CAPEC-901"], "MITRE CWE Database", "official")}}
    g["CVE-2020-0001"]["rels"]["cwe"] = _rel(["CWE-900", "CWE-903"], NVD, "authoritative")
    g["CVE-2020-0001"]["rels"]["capec"] = _rel(["CAPEC-900"], "Pipeline (CWE→CAPEC chain)")
    ld = _load(tmp_path, g, META)
    cves = {c["id"]: c for c in build_attack_chain_impl(ld, "T9001")["data"]["cves"]}
    a = cves["CVE-2020-0001"]
    assert a["via_capecs"] == ["CAPEC-900"]
    assert a["via_cwes"] == ["CWE-900"]
    # A CVE with no capec rels at all (hand-built graphs) keeps the CWE path.
    assert cves["CVE-2020-0002"]["via_capecs"] == ["CAPEC-900", "CAPEC-901"]


def test_chain_uncredited_assigned_path_falls_back_to_inherited_parent(tmp_path):
    """When the assigned CWE reaches the technique only through CAPECs the
    CVE does not credit, the inherited parent that does is the explanation."""
    g = _graph()
    g["CAPEC-901"] = {"type": "capec", "rels": {"technique": _rel(["T9001"], "MITRE CAPEC Database", "official")}}
    g["CWE-901"]["rels"]["capec"] = _rel(["CAPEC-901"], "MITRE CWE Database", "official")
    g["CVE-2020-0002"]["rels"]["capec"] = _rel(["CAPEC-900"], "Pipeline (CWE→CAPEC chain)", "derived", ["CAPEC-900"])
    ld = _load(tmp_path, g, META)
    b = {c["id"]: c for c in build_attack_chain_impl(ld, "T9001")["data"]["cves"]}["CVE-2020-0002"]
    assert b["via_cwes"] == ["CWE-900"] and b["inherited_cwes"] == ["CWE-900"]
    assert b["via_capecs"] == ["CAPEC-900"]


def test_shard_overlap_apt_groups_give_no_rels(tmp_path):
    """I32: APT_GROUPS entries without evidence (older processor dicts with
    techniques_overlap, or bare ids) are overlap guesses and give no rel,
    and the graph's groups for a linked technique are never projected."""
    g = _graph()
    g["T9002"]["rels"]["apt_group"] = _rel(["G0005"], "MITRE ATT&CK", "official")
    shard = dict(NEW_SHARD, APT_GROUPS=[
        {"id": "G0001", "techniques_overlap": ["9001"]},
        {"id": "G0003", "techniques_overlap": ["T9002"]},
        "g0004",
    ])
    ld = _load(tmp_path, g, META, shard={"CVE-2021-0009": shard})
    assert pivot_from_entity_impl(ld, "CVE-2021-0009", "apt_group")["data"] == []
    rels = lookup_entity_impl(ld, "CVE-2021-0009")["data"]["rels"]
    assert [r for r in rels if r["rel_type"] == "apt_group"] == []


def test_shard_attributed_apt_group_is_official_never_inherited(tmp_path):
    """An attributed entry is ATT&CK's statement: official, with its
    evidence, and not inherited even when every technique of the CVE is."""
    shard = dict(NEW_SHARD, TECHNIQUES=[], APT_GROUPS=[
        {"id": "G0001", "via": "G0001", "via_type": "relationship", "via_target": "T9001"}])
    ld = _load(tmp_path, _graph(), META, shard={"CVE-2021-0009": shard})
    (hit,) = pivot_from_entity_impl(ld, "CVE-2021-0009", "apt_group")["data"]
    assert hit["id"] == "G0001" and hit["tier"] == "official" and hit["source"] == "MITRE ATT&CK"
    assert (hit["via"], hit["via_type"], hit["via_target"]) == ("G0001", "relationship", "T9001")
    assert "inherited" not in hit
