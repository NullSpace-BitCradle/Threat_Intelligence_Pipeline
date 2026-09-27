"""I21 (ISC-9): the MCP tools carry per-link provenance. A CTID or inferred
technique link never reads as chain derived and vice versa, on the entity
path and the shard path, and the P10 sweeps hold with the new tiers."""

from __future__ import annotations

import json

import tip_mcp.tools as tools
from tip_intel.link_tiers import CTID_SOURCE
from tip_mcp.tools import (
    _weakest,
    build_attack_chain_impl,
    get_defenses_impl,
    lookup_entity_impl,
    pivot_from_entity_impl,
)

from .sweeps import (
    all_tier_violations,
    chain_cve_mismatches,
    chain_inherited_cwe_violations,
    link_label_violations,
)
from .test_i29_inherited import CHAIN, NVD, _load, _rel

INFERRED_SRC = "TIP inference from the CVSS vector (AV:N and UI:N: T1190 Exploit Public-Facing Application)"
CTID_T = {"source": CTID_SOURCE, "tier": "official", "mapping_type": ["exploitation_technique"]}
CTID_C = dict(CTID_T, comment="Crafted request.")
INF = {"source": INFERRED_SRC, "tier": "inferred", "rule": "network-no-interaction"}
DEF_CTID = {"source": "CTID technique, then D3FEND", "tier": "derived"}
DEF_INF = {"source": "Inferred technique, then D3FEND", "tier": "inferred"}
DEF_CHAIN = "Pipeline (Technique→D3FEND chain)"
META = {"inherited_links": True, "link_provenance": True}


def _with(body: dict, link_prov: dict) -> dict:
    body["link_prov"] = link_prov
    return body


def _graph() -> dict:
    """T9001 <- CAPEC-900 <- CWE-900. CVE-A reaches T9001 through the chain;
    CVE-C only through CTID; CVE-D only by inference; CVE-E through an
    inherited parent CWE and CTID (CTID wins, so it is not inherited)."""
    return {
        "T9001": {"type": "technique", "rels": {
            "cve": _with(_rel(["CVE-2020-0101", "CVE-2020-0103", "CVE-2020-0104", "CVE-2020-0105"], CHAIN),
                         {"CVE-2020-0103": CTID_T, "CVE-2020-0104": INF, "CVE-2020-0105": CTID_T}),
            "defend": _rel(["D3-A"], "MITRE D3FEND", "official"),
        }},
        "T9002": {"type": "technique", "rels": {"defend": _rel(["D3-A", "D3-C"], "MITRE D3FEND", "official")}},
        "CAPEC-900": {"type": "capec", "rels": {"technique": _rel(["T9001"], "MITRE CAPEC Database", "official")}},
        "CWE-900": {"type": "cwe", "rels": {
            "capec": _rel(["CAPEC-900"], "MITRE CWE Database", "official"),
            "cve": _rel(["CVE-2020-0101"], NVD, "authoritative"),
        }},
        "CWE-901": {"type": "cwe", "rels": {"cve": _rel(["CVE-2020-0105"], NVD, "authoritative")}},
        "CVE-2020-0101": {"type": "cve", "kev": True, "cwe_inherited": [], "rels": {
            "cwe": _rel(["CWE-900"], NVD, "authoritative"),
            "technique": _rel(["T9001"], CHAIN),
            "defend": _rel(["D3-A"], DEF_CHAIN),
        }},
        "CVE-2020-0103": {"type": "cve", "kev": True, "rels": {
            "technique": _with(_rel(["T9001"], CHAIN), {"T9001": CTID_C}),
            "defend": _with(_rel(["D3-A"], DEF_CHAIN), {"D3-A": DEF_CTID}),
        }},
        "CVE-2020-0104": {"type": "cve", "kev": False, "rels": {
            "technique": _with(_rel(["T9001"], CHAIN), {"T9001": INF}),
            "defend": _with(_rel(["D3-A"], DEF_CHAIN), {"D3-A": DEF_INF}),
        }},
        "CVE-2020-0105": {"type": "cve", "kev": True, "cwe_inherited": ["CWE-900"], "rels": {
            "cwe": _rel(["CWE-901"], NVD, "authoritative"),
            "capec": _rel(["CAPEC-900"], "Pipeline (CWE→CAPEC chain)"),
            "technique": _with(_rel(["T9001"], CHAIN), {"T9001": CTID_C}),
            "defend": _with(_rel(["D3-A"], DEF_CHAIN), {"D3-A": DEF_CTID}),
        }},
        "D3-A": {"type": "defend", "rels": {
            "technique": _rel(["T9001", "T9002"], "MITRE D3FEND", "official"),
            "cve": _with(_rel(["CVE-2020-0101", "CVE-2020-0103", "CVE-2020-0104", "CVE-2020-0105"], DEF_CHAIN),
                         {"CVE-2020-0103": DEF_CTID, "CVE-2020-0104": DEF_INF, "CVE-2020-0105": DEF_CTID}),
        }},
        "D3-C": {"type": "defend"},
    }


CWE_DB = {"900": {"RelatedAttackPatterns": ["900"]}}
SHARD = {
    # Chain T9001, CTID T9002.
    "CVE-2021-0009": {"CWE": ["CWE-900"], "TECHNIQUES": ["9001"], "TECHNIQUES_INHERITED": [],
                      "TECHNIQUES_CTID": [{"id": "T9002", "mapping_type": ["primary_impact"],
                                           "source": CTID_SOURCE, "comment": "Shard comment."}],
                      "TECHNIQUES_INFERRED": []},
    # Inferred only.
    "CVE-2022-0010": {"CWE": ["CWE-787"], "TECHNIQUES": [], "TECHNIQUES_INHERITED": [], "TECHNIQUES_CTID": [],
                      "TECHNIQUES_INFERRED": [{"id": "T9001", "rule": "network-no-interaction",
                                               "source": INFERRED_SRC}]},
    # CTID and chain name the same technique: CTID wins.
    "CVE-2023-0011": {"CWE": ["CWE-900"], "TECHNIQUES": ["9001"], "TECHNIQUES_INHERITED": [],
                      "TECHNIQUES_CTID": [{"id": "T9001", "mapping_type": ["exploitation_technique"],
                                           "source": CTID_SOURCE}],
                      "TECHNIQUES_INFERRED": []},
}


def _ld(tmp_path):
    return _load(tmp_path, _graph(), META, shard=SHARD, cwe_db=CWE_DB)


def _by_target(rels, rel_type):
    return {r["target_id"]: r for r in rels if r["rel_type"] == rel_type}


# ── entity path ──────────────────────────────────────────────────────


def test_lookup_rels_carry_the_link_provenance(tmp_path):
    ld = _ld(tmp_path)
    c = _by_target(lookup_entity_impl(ld, "CVE-2020-0103")["data"]["rels"], "technique")["T9001"]
    assert (c["source"], c["tier"], c["mapping_type"], c["comment"]) == (
        CTID_SOURCE, "official", ["exploitation_technique"], "Crafted request.")
    d = _by_target(lookup_entity_impl(ld, "CVE-2020-0104")["data"]["rels"], "technique")["T9001"]
    assert (d["source"], d["tier"], d["rule"]) == (INFERRED_SRC, "inferred", "network-no-interaction")
    a = _by_target(lookup_entity_impl(ld, "CVE-2020-0101")["data"]["rels"], "technique")["T9001"]
    assert (a["source"], a["tier"]) == (CHAIN, "derived")
    assert "mapping_type" not in a and "rule" not in a


def test_pivot_hits_carry_the_link_provenance_both_directions(tmp_path):
    ld = _ld(tmp_path)
    back = {h["id"]: (h["source"], h["tier"]) for h in pivot_from_entity_impl(ld, "T9001", "cve")["data"]}
    assert back == {
        "CVE-2020-0101": (CHAIN, "derived"),
        "CVE-2020-0103": (CTID_SOURCE, "official"),
        "CVE-2020-0104": (INFERRED_SRC, "inferred"),
        "CVE-2020-0105": (CTID_SOURCE, "official"),
    }
    fwd = pivot_from_entity_impl(ld, "CVE-2020-0104", "defend")["data"]
    assert [(h["id"], h["tier"]) for h in fwd] == [("D3-A", "inferred")]


def test_chain_labels_ctid_and_inferred_cves_by_their_link(tmp_path):
    ld = _ld(tmp_path)
    resp = build_attack_chain_impl(ld, "T9001")
    cves = {c["id"]: c for c in resp["data"]["cves"]}
    assert (cves["CVE-2020-0101"]["tier"], cves["CVE-2020-0101"]["link_tier"]) == ("derived", "derived")
    assert cves["CVE-2020-0101"]["via_cwes"] == ["CWE-900"]
    assert cves["CVE-2020-0101"]["link_source"] == CHAIN
    c = cves["CVE-2020-0103"]
    assert (c["source"], c["tier"], c["link_tier"]) == (CTID_SOURCE, "official", "official")
    assert c["mapping_type"] == ["exploitation_technique"] and c["comment"] == "Crafted request."
    assert c["via_cwes"] == []
    d = cves["CVE-2020-0104"]
    assert (d["source"], d["tier"], d["rule"]) == (INFERRED_SRC, "inferred", "network-no-interaction")
    # CTID link explained through an inherited parent CWE stays official;
    # the path is shown, flagged, but does not make the link.
    e = cves["CVE-2020-0105"]
    assert e["tier"] == "official" and e["inherited_cwes"] == ["CWE-900"] and "inherited" not in e
    assert resp["meta"]["link_tiers"] == {"derived": 1, "inferred": 1, "official": 2}


def test_defenses_take_the_weakest_link_tier(tmp_path):
    ld = _ld(tmp_path)
    d = get_defenses_impl(ld, cve_id="CVE-2020-0104")["data"]
    assert [(x["id"], x["tier"]) for x in d] == [("D3-A", "inferred")]
    assert d[0]["technique_links"] == [{"id": "T9001", **INF}]
    assert "TIP inference" in d[0]["mapping_source"]
    c = get_defenses_impl(ld, cve_id="CVE-2020-0103")["data"]
    assert [(x["id"], x["tier"]) for x in c] == [("D3-A", "derived")]
    assert c[0]["technique_links"] == [{"id": "T9001", **CTID_T}]
    a = get_defenses_impl(ld, cve_id="CVE-2020-0101")["data"]
    assert [(x["id"], x["tier"]) for x in a] == [("D3-A", "derived")]


def test_inferred_ranks_below_derived_and_unknown_below_inferred():
    assert _weakest([("a", "derived"), ("b", "inferred")]) == ("b", "inferred")
    assert _weakest([("a", "official"), ("b", "inferred"), ("c", "derived")]) == ("b", "inferred")
    assert _weakest([("a", "inferred"), ("b", "mystery")]) == ("b", "mystery")


# ── shard path ───────────────────────────────────────────────────────


def test_shard_lookup_and_pivot_carry_ctid_and_inferred(tmp_path):
    ld = _ld(tmp_path)
    rels = _by_target(lookup_entity_impl(ld, "CVE-2021-0009")["data"]["rels"], "technique")
    assert rels["T9002"]["tier"] == "official" and rels["T9002"]["source"] == CTID_SOURCE
    assert rels["T9002"]["mapping_type"] == ["primary_impact"] and rels["T9002"]["comment"] == "Shard comment."
    assert "tier" not in rels["T9001"] and rels["T9001"]["source"] == "shard"
    hits = {h["id"]: h for h in pivot_from_entity_impl(ld, "CVE-2021-0009", "technique")["data"]}
    assert (hits["T9002"]["source"], hits["T9002"]["tier"]) == (CTID_SOURCE, "official")
    assert (hits["T9001"]["source"], hits["T9001"]["tier"]) == ("Pipeline (shard enrichment)", "derived")
    inf = pivot_from_entity_impl(ld, "CVE-2022-0010", "technique")["data"]
    assert [(h["id"], h["tier"], h["rule"]) for h in inf] == [("T9001", "inferred", "network-no-interaction")]
    both = pivot_from_entity_impl(ld, "CVE-2023-0011", "technique")["data"]
    assert [(h["id"], h["tier"]) for h in both] == [("T9001", "official")]


def test_shard_defenses_use_the_link_tier(tmp_path):
    ld = _ld(tmp_path)
    defs = {d["id"]: d for d in get_defenses_impl(ld, cve_id="CVE-2021-0009")["data"]}
    # D3-C only through the CTID technique: derived (a composition). D3-A
    # also through the chain technique: derived.
    assert defs["D3-C"]["tier"] == "derived"
    assert defs["D3-A"]["tier"] == "derived"
    inf = get_defenses_impl(ld, cve_id="CVE-2022-0010")["data"]
    assert [(d["id"], d["tier"]) for d in inf] == [("D3-A", "inferred")]


def test_shard_apt_groups_ignore_ctid_and_inferred(tmp_path):
    ld = _ld(tmp_path)
    ld.entities["T9002"]["rels"]["apt_group"] = _rel(["G9999"], "MITRE ATT&CK", "official")
    hits = pivot_from_entity_impl(ld, "CVE-2021-0009", "apt_group")["data"]
    assert hits == []


# ── sweeps ───────────────────────────────────────────────────────────


def test_sweeps_hold_with_the_new_tiers(tmp_path):
    ld = _ld(tmp_path)
    assert chain_cve_mismatches(ld) == []
    report = all_tier_violations(ld)
    assert report["chain_violations"] == [] and report["defense_violations"] == []
    assert report["defenses"] >= 4
    assert chain_inherited_cwe_violations(ld) == []
    assert link_label_violations(ld) == []


def test_sweeps_catch_a_tool_that_ignores_link_provenance(tmp_path, monkeypatch):
    """The refuting case: a tool that labels every link with the body's
    chain source must fail the sweeps."""
    ld = _ld(tmp_path)

    def body_only(body, target_id):
        return {"source": body.get("source"), "tier": body.get("tier")} if isinstance(body, dict) \
            else {"source": None, "tier": None}
    monkeypatch.setattr(tools, "link_provenance", body_only)
    bad = link_label_violations(ld)
    assert {b["tool"] for b in bad} >= {"lookup", "pivot", "chain", "defenses"}
    assert any(v["kind"] == "cve-link" for v in all_tier_violations(ld)["chain_violations"])


def test_legacy_index_output_carries_no_i21_fields(tmp_path):
    """An index without link_prov and a shard without the I21 lists produce
    no mapping_type, rule, or technique link tiers other than the body's."""
    g = _graph()
    for ent in g.values():
        for body in (ent.get("rels") or {}).values():
            body.pop("link_prov", None)
    legacy_shard = {"CWE": ["CWE-900"], "TECHNIQUES": ["9001"]}
    ld = _load(tmp_path, g, {"inherited_links": True}, shard={"CVE-2021-0009": legacy_shard}, cwe_db=CWE_DB)
    outputs = [
        lookup_entity_impl(ld, "CVE-2020-0103"), pivot_from_entity_impl(ld, "T9001", "cve"),
        pivot_from_entity_impl(ld, "CVE-2021-0009"), lookup_entity_impl(ld, "CVE-2021-0009"),
        get_defenses_impl(ld, cve_id="CVE-2020-0104"),
    ]
    text = json.dumps(outputs)
    assert "mapping_type" not in text and '"rule"' not in text
    assert "official" not in json.dumps(outputs[1]) and "inferred" not in text
    assert link_label_violations(ld) == []


# ── review fixes ─────────────────────────────────────────────────────


def test_legacy_fixture_output_is_byte_identical_to_main(loader):
    """Every tool call on the pre-I21 fixture returns exactly what main's
    tools returned (recorded in fixtures/legacy_outputs_main.json)."""
    from pathlib import Path

    golden = json.loads((Path(__file__).parent / "fixtures" / "legacy_outputs_main.json").read_text())
    fn = {"lookup_entity": lookup_entity_impl, "pivot_from_entity": pivot_from_entity_impl,
          "build_attack_chain": build_attack_chain_impl, "get_defenses": get_defenses_impl}
    assert len(golden) > 50
    for name, args, want in golden:
        got = json.loads(json.dumps(fn[name](loader, **args), sort_keys=True))
        assert got == want, (name, args)


def test_ctid_technique_defense_is_derived_on_both_paths(tmp_path):
    ld = _ld(tmp_path)
    c = get_defenses_impl(ld, cve_id="CVE-2020-0103")["data"]
    assert [(x["id"], x["tier"]) for x in c] == [("D3-A", "derived")]
    assert "CTID technique, then D3FEND" in c[0]["mapping_source"]
    # Shard path, no own defend rel: the composition is still derived.
    defs = {d["id"]: d for d in get_defenses_impl(ld, cve_id="CVE-2021-0009")["data"]}
    assert defs["D3-C"]["tier"] == "derived"


def test_default_prov_labels_the_chain_links_of_a_relabeled_body(tmp_path):
    g = _graph()
    body = g["T9001"]["rels"]["cve"]
    body["tier"] = "inferred"
    body["default_prov"] = {"source": CHAIN, "tier": "derived"}
    ld = _load(tmp_path, g, META, cwe_db=CWE_DB)
    back = {h["id"]: h["tier"] for h in pivot_from_entity_impl(ld, "T9001", "cve")["data"]}
    assert back["CVE-2020-0101"] == "derived" and back["CVE-2020-0104"] == "inferred"
    assert link_label_violations(ld) == []


def test_chain_note_names_ctid_and_inferred_cves_without_a_capec(tmp_path):
    g = _graph()
    g["T9003"] = {"type": "technique", "rels": {"cve": _with(_rel(["CVE-2020-0103", "CVE-2020-0104"], CHAIN),
                                                            {"CVE-2020-0103": CTID_T, "CVE-2020-0104": INF})}}
    ld = _load(tmp_path, g, META, cwe_db=CWE_DB)
    note = build_attack_chain_impl(ld, "T9003")["meta"]["note"]
    assert "1 MITRE CTID analyst mapping" in note and "1 inferred from the CVSS vector" in note
    assert "listed without a CAPEC or CWE path" not in note
