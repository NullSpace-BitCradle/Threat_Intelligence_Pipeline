"""Phase B (P10) tools: build_attack_chain, get_defenses, kev_status.

Shared-fixture tests use the fixture corpus as it stands (T1548 has CAPECs
and a CWE behind it, T1053.005 has no CAPEC, T1574.010 has a CAPEC with no
CWE). Ordering, limit, SSVC, and shard-verb cases build small graphs in
tmp_path so they do not depend on or disturb the shared corpus.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from tip_mcp.loader import IndexLoader
from tip_mcp.tools import (
    build_attack_chain_impl,
    get_defenses_impl,
    kev_status_impl,
)

from .sweeps import all_tier_violations, chain_cve_mismatches

KEV_KEYS = (
    "date_added",
    "due_date",
    "known_ransomware_campaign_use",
    "required_action",
    "vendor_project",
    "product",
)


def _rel(ids: list, source: str = "Test source", tier: str = "derived") -> dict:
    return {"ids": ids, "source": source, "tier": tier}


def _graph(
    tmp_path: Path,
    entities: dict,
    kev_db: Optional[dict] = None,
    shard: Optional[dict] = None,
    cwe_db: Optional[dict] = None,
) -> IndexLoader:
    """Write a tiny index (and optional kev_db / cwe_db / one shard) and load it."""
    for eid, ent in entities.items():
        ent.setdefault("id", eid)
        ent.setdefault("name", eid)
    (tmp_path / "entity_index.json").write_text(json.dumps({"meta": {}, "entities": entities}))
    (tmp_path / "search_index.json").write_text("{}")
    if kev_db is not None:
        (tmp_path / "kev_db.json").write_text(json.dumps(kev_db))
    if cwe_db is not None:
        (tmp_path / "cwe_db.json").write_text(json.dumps(cwe_db))
    shards = tmp_path / "database"
    shards.mkdir(exist_ok=True)
    if shard:
        by_year: dict[str, list[str]] = {}
        for cve_id, payload in shard.items():
            by_year.setdefault(cve_id.split("-")[1], []).append(json.dumps({cve_id: payload}))
        for year, lines in by_year.items():
            (shards / f"CVE-{year}.jsonl").write_text("\n".join(lines) + "\n")
    ld = IndexLoader(tmp_path, shards_dir=shards)
    ld.load()
    return ld


CHAIN_CVES = ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004"]


def _capec_900() -> dict:
    return {"capec": _rel(["CAPEC-900"], "Pipeline (CWE→CAPEC chain)")}


def _chain_graph() -> dict:
    """technique T9001 <- CAPEC-900 <- CWE-900 -> four CVEs of mixed KEV/CVSS.

    Only forward edges are stored: the CAPEC names the technique and the CWE
    names the CAPEC; neither the technique nor the CAPEC names them back. The
    technique's own cve rels (derived, as the generator writes them) name the
    same four CVEs.
    """
    return {
        "T9001": {
            "type": "technique",
            "rels": {
                "defend": _rel(["D3-B", "D3-A"], "MITRE D3FEND", "official"),
                "cve": _rel(list(CHAIN_CVES), "Pipeline (CAPEC→Technique chain)", "derived"),
            },
        },
        "CAPEC-900": {"type": "capec", "rels": {"technique": _rel(["T9001"], "CAPEC", "official")}},
        "CWE-900": {
            "type": "cwe",
            "rels": {
                "capec": _rel(["CAPEC-900"], "CWE", "official"),
                "cve": _rel(list(CHAIN_CVES), "NVD", "authoritative"),
            },
        },
        # Real CVEs credit the CAPECs their CWEs reach (cve -> capec rels); the
        # chain only names a CAPEC the CVE credits.
        "CVE-2020-0001": {"type": "cve", "kev": False, "cvss_score": 9.8, "severity": "CRITICAL", "rels": _capec_900()},
        "CVE-2020-0002": {"type": "cve", "kev": True, "cvss_score": 5.0, "severity": "MEDIUM", "rels": _capec_900()},
        "CVE-2020-0003": {"type": "cve", "kev": True, "cvss_score": 8.1, "severity": "HIGH", "rels": _capec_900()},
        "CVE-2020-0004": {"type": "cve", "kev": True, "rels": _capec_900()},
        "D3-A": {"type": "defend"},
        "D3-B": {"type": "defend"},
    }


# ---------------------------------------------------------------- F1 chain


def test_chain_walks_reverse_edges_on_fixture(loader):
    # The fixture stores capec -> technique and cwe -> capec only.
    assert "capec" not in loader.entities["T1548"]["rels"]
    assert "cwe" not in loader.entities["CAPEC-122"]["rels"]

    resp = build_attack_chain_impl(loader, "t1548")
    assert resp["ok"] is True
    data = resp["data"]
    assert data["technique"]["id"] == "T1548"
    assert [c["id"] for c in data["capecs"]] == ["CAPEC-122", "CAPEC-233"]
    assert [c["id"] for c in data["cwes"]] == ["CWE-269"]
    assert data["cwes"][0]["via_capecs"] == ["CAPEC-122", "CAPEC-233"]
    assert [c["id"] for c in data["cves"]] == ["CVE-2002-0367"]
    assert data["cves"][0]["kev"] is True
    assert data["cves"][0]["via_cwes"] == ["CWE-269"]
    assert data["cves"][0]["via_capecs"] == ["CAPEC-122", "CAPEC-233"]
    assert len(data["defenses"]) == 5
    assert "note" not in resp["meta"]
    assert resp["meta"]["totals"] == {"capecs": 2, "cwes": 1, "cves": 1, "defenses": 5}


def test_chain_walks_forward_only_synthetic_graph(tmp_path):
    ld = _graph(tmp_path, _chain_graph())
    resp = build_attack_chain_impl(ld, "T9001")
    assert resp["ok"] is True
    assert [c["id"] for c in resp["data"]["capecs"]] == ["CAPEC-900"]
    assert [c["id"] for c in resp["data"]["cwes"]] == ["CWE-900"]
    assert len(resp["data"]["cves"]) == 4
    for c in resp["data"]["cves"]:
        assert c["via_cwes"] == ["CWE-900"] and c["via_capecs"] == ["CAPEC-900"]


def test_chain_cves_ordered_kev_first_then_cvss_desc(tmp_path):
    ld = _graph(tmp_path, _chain_graph())
    cves = build_attack_chain_impl(ld, "T9001")["data"]["cves"]
    assert [c["id"] for c in cves] == [
        "CVE-2020-0003",  # KEV, 8.1
        "CVE-2020-0002",  # KEV, 5.0
        "CVE-2020-0004",  # KEV, no CVSS: after scored KEV CVEs
        "CVE-2020-0001",  # not KEV, even at 9.8
    ]
    for c in cves:
        assert {"kev", "cvss_score", "severity"} <= set(c)
    assert cves[2]["cvss_score"] is None and cves[2]["severity"] is None


def test_chain_every_element_carries_provenance(tmp_path, loader):
    for ld, tid in ((loader, "T1548"), (_graph(tmp_path, _chain_graph()), "T9001")):
        data = build_attack_chain_impl(ld, tid)["data"]
        for key in ("capecs", "cwes", "cves", "defenses"):
            assert data[key], key
            for el in data[key]:
                assert el["source"], (key, el)
                assert el["tier"], (key, el)
    data = build_attack_chain_impl(ld, "T9001")["data"]
    assert data["capecs"][0]["source"] == "CAPEC" and data["capecs"][0]["tier"] == "official"
    # A chain CVE is only as strong as the technique -> cve rel that put it
    # there, never the NVD tier of the CVE's own CWE link.
    assert data["cves"][0]["source"] == "Pipeline (CAPEC→Technique chain)"
    assert data["cves"][0]["tier"] == "derived"
    assert data["defenses"][0]["source"] == "MITRE D3FEND"


def test_chain_cwe_capec_hop_not_in_related_attack_patterns_is_inherited(loader):
    # Fixture cwe_db lists CAPEC-122 (and 58) for CWE-269, not CAPEC-233: the
    # graph's CWE-269 -> CAPEC-233 edge came from a ChildOf parent.
    data = build_attack_chain_impl(loader, "T1548")["data"]
    (cwe,) = data["cwes"]
    assert cwe["inherited"] is True
    assert cwe["inherited_capecs"] == ["CAPEC-233"]
    assert cwe["tier"] == "derived"
    assert "inherit" in cwe["source"].lower()
    assert data["cves"][0]["tier"] == "derived"


def test_chain_cwe_hop_in_related_attack_patterns_keeps_graph_tier(tmp_path):
    ld = _graph(tmp_path, _chain_graph(), cwe_db={"900": {"RelatedAttackPatterns": ["900"]}})
    (cwe,) = build_attack_chain_impl(ld, "T9001")["data"]["cwes"]
    assert cwe["inherited"] is False and cwe["inherited_capecs"] == []
    assert cwe["tier"] == "official" and cwe["source"] == "CWE"


def test_chain_without_cwe_db_marks_hops_unverified(tmp_path):
    ld = _graph(tmp_path, _chain_graph())
    resp = build_attack_chain_impl(ld, "T9001")
    (cwe,) = resp["data"]["cwes"]
    assert cwe["inherited"] is None
    assert cwe["tier"] == "derived"
    assert "cwe_db.json" in resp["meta"]["cwe_db_note"]


def test_chain_no_capec_returns_empty_chain_with_note_and_defenses(loader):
    resp = build_attack_chain_impl(loader, "T1053.005")
    assert resp["ok"] is True
    assert resp["data"]["capecs"] == resp["data"]["cwes"] == resp["data"]["cves"] == []
    assert "No CAPEC" in resp["meta"]["note"]
    assert "T1053.005" in resp["meta"]["note"]
    assert [d["id"] for d in resp["data"]["defenses"]] == [
        "Application-basedProcessIsolation",
        "ExecutableAllowlisting",
        "ExecutableDenylisting",
    ]


def test_chain_capec_without_cwe_lists_own_cves_unexplained(loader):
    resp = build_attack_chain_impl(loader, "T1574.010")
    assert resp["ok"] is True
    assert [c["id"] for c in resp["data"]["capecs"]] == ["CAPEC-1"]
    assert resp["data"]["cwes"] == []
    assert [c["id"] for c in resp["data"]["cves"]] == ["CVE-2013-0431", "CVE-2013-0632", "CVE-2013-2465"]
    for c in resp["data"]["cves"]:
        assert c["via_cwes"] == [] and c["via_capecs"] == []
        assert c["tier"] == "derived"
    assert "no CWE" in resp["meta"]["note"]
    assert resp["meta"]["cves_without_path"] == 3


def test_chain_cwe_without_cve_path_keeps_own_cves(tmp_path):
    g = _chain_graph()
    del g["CWE-900"]["rels"]["cve"]
    resp = build_attack_chain_impl(_graph(tmp_path, g), "T9001")
    assert resp["data"]["cwes"] == []
    assert {c["id"] for c in resp["data"]["cves"]} == set(CHAIN_CVES)
    assert "no CWE" in resp["meta"]["note"]


def test_chain_technique_without_cves_says_so(tmp_path):
    g = _chain_graph()
    del g["T9001"]["rels"]["cve"]
    resp = build_attack_chain_impl(_graph(tmp_path, g), "T9001")
    assert resp["data"]["capecs"] and resp["data"]["cves"] == [] and resp["data"]["cwes"] == []
    assert "No CVE" in resp["meta"]["note"]


def test_chain_cves_are_exactly_the_techniques_own_rels(tmp_path):
    g = _chain_graph()
    # Reaches CWE-900 but the technique never names it: must not appear.
    g["CVE-2021-0009"] = {"type": "cve", "kev": True, "rels": {
        "cwe": _rel(["CWE-900"], "NVD", "authoritative"), "capec": _rel(["CAPEC-900"])}}
    # Named by the technique, linked to CWE-900 only from its own side.
    g["CVE-2021-0010"] = {"type": "cve", "kev": False, "rels": {
        "cwe": _rel(["CWE-900"], "NVD", "authoritative"), "capec": _rel(["CAPEC-900"])}}
    g["T9001"]["rels"]["cve"]["ids"].append("CVE-2021-0010")
    g["D3-C"] = {"type": "defend", "rels": {"technique": _rel(["T9001"], "MITRE D3FEND", "official")}}
    data = build_attack_chain_impl(_graph(tmp_path, g), "T9001")["data"]
    ids = [c["id"] for c in data["cves"]]
    assert "CVE-2021-0009" not in ids
    assert set(ids) == set(CHAIN_CVES) | {"CVE-2021-0010"}
    by_id = {c["id"]: c for c in data["cves"]}
    assert by_id["CVE-2021-0010"]["via_cwes"] == ["CWE-900"]
    assert [d["id"] for d in data["defenses"]] == ["D3-A", "D3-B", "D3-C"]


def test_chain_cwes_are_only_those_used_by_returned_cves(tmp_path):
    g = _chain_graph()
    # A second CWE reaches the CAPEC but no chain CVE carries it.
    g["CWE-901"] = {"type": "cwe", "rels": {"capec": _rel(["CAPEC-900"], "CWE", "official")}}
    data = build_attack_chain_impl(_graph(tmp_path, g), "T9001")["data"]
    assert [c["id"] for c in data["cwes"]] == ["CWE-900"]


def test_chain_kev_flag_uses_catalog_and_missing_inkev_means_listed(tmp_path):
    g = _chain_graph()
    g["T9001"]["rels"]["cve"]["ids"] += ["CVE-2022-0005", "CVE-2022-0006"]
    # CVE-2022-0005 is not a graph entity; CWE-900 names it from its side.
    g["CWE-900"]["rels"]["cve"]["ids"].append("CVE-2022-0005")
    # It has no entity, so the CAPEC names it from its side.
    g["CAPEC-900"]["rels"]["cve"] = _rel(["CVE-2022-0005"], "Pipeline (CWE→CAPEC chain)")
    kev_db = {"CVE-2022-0005": {}, "CVE-2022-0006": {"inKEV": False}, "CVE-2020-0001": {"inKEV": True}}
    ld = _graph(tmp_path, g, kev_db=kev_db)
    cves = {c["id"]: c for c in build_attack_chain_impl(ld, "T9001")["data"]["cves"]}
    assert cves["CVE-2022-0005"]["kev"] is True
    assert cves["CVE-2022-0005"]["name"] is None
    assert cves["CVE-2022-0005"]["via_cwes"] == ["CWE-900"]
    assert cves["CVE-2022-0006"]["via_cwes"] == []
    assert cves["CVE-2022-0006"]["kev"] is False
    # The catalog decides: graph kev flags do not override it.
    assert cves["CVE-2020-0001"]["kev"] is True
    assert cves["CVE-2020-0002"]["kev"] is False
    assert kev_status_impl(ld, "CVE-2022-0005")["data"]["in_kev"] is True
    assert kev_status_impl(ld, "CVE-2022-0006")["data"]["in_kev"] is False


def test_chain_limit_caps_lists_and_reports_true_totals(tmp_path):
    ld = _graph(tmp_path, _chain_graph())
    resp = build_attack_chain_impl(ld, "T9001", limit=2)
    assert len(resp["data"]["cves"]) == 2
    assert [c["id"] for c in resp["data"]["cves"]] == ["CVE-2020-0003", "CVE-2020-0002"]
    assert len(resp["data"]["defenses"]) == 2
    assert resp["meta"]["totals"]["cves"] == 4
    assert resp["meta"]["limit"] == 2
    assert resp["meta"]["truncated"] is True
    full = build_attack_chain_impl(ld, "T9001")
    assert full["meta"]["limit"] == 50
    assert full["meta"]["truncated"] is False


def _fanout_graph() -> dict:
    """The review's T1134 shape: a pillar CWE inherits the technique's CAPEC
    and names many CVEs the technique itself never links to."""
    g = _chain_graph()
    g["CWE-664"] = {
        "type": "cwe",
        "rels": {
            "capec": _rel(["CAPEC-900"], "MITRE CWE Database", "official"),
            "cve": _rel([f"CVE-2019-{n:04d}" for n in range(1, 31)], "NVD Enrichment", "authoritative"),
        },
    }
    for n in range(1, 31):
        g[f"CVE-2019-{n:04d}"] = {"type": "cve", "kev": True, "cvss_score": 9.0}
    g["CVE-2020-0001"]["rels"] = {
        "cwe": _rel(["CWE-664"], "NVD Enrichment", "authoritative"),
        "capec": _rel(["CAPEC-900"], "Pipeline (CWE→CAPEC chain)"),
    }
    return g


def test_sweep_chain_cves_equal_own_rels_on_fixture_and_fanout(tmp_path, loader):
    assert chain_cve_mismatches(loader) == []
    ld = _graph(tmp_path, _fanout_graph(), cwe_db={"900": {"RelatedAttackPatterns": ["900"]}, "664": {"RelatedAttackPatterns": []}})
    assert chain_cve_mismatches(ld) == []
    data = build_attack_chain_impl(ld, "T9001", limit=1000)["data"]
    assert len(data["cves"]) == 4
    cwes = {c["id"]: c for c in data["cwes"]}
    assert cwes["CWE-664"]["inherited"] is True and cwes["CWE-664"]["tier"] == "derived"
    assert cwes["CWE-900"]["tier"] == "official"


def test_sweep_no_strong_tier_on_a_weak_path(tmp_path, loader):
    report = all_tier_violations(loader)
    assert report["chain_violations"] == [] and report["defense_violations"] == []
    assert report["defenses"] > 0
    ld = _graph(tmp_path, _fanout_graph(), cwe_db={"900": {"RelatedAttackPatterns": ["900"]}})
    report = all_tier_violations(ld)
    assert report["chain_violations"] == [] and report["defense_violations"] == []


@pytest.mark.parametrize("limit", [0, -1, "5", True, 1.5])
def test_chain_bad_limit_is_bad_param(loader, limit):
    resp = build_attack_chain_impl(loader, "T1548", limit=limit)
    assert resp["error"]["code"] == "bad_param"


def test_chain_unknown_technique_is_not_found(loader):
    assert build_attack_chain_impl(loader, "T9999")["error"]["code"] == "not_found"


def test_chain_non_technique_is_invalid_type(loader):
    resp = build_attack_chain_impl(loader, "CVE-2002-0367")
    assert resp["error"]["code"] == "invalid_type"
    assert "cve" in resp["error"]["message"]


@pytest.mark.parametrize("value", ["", "   ", None, 42])
def test_chain_blank_or_non_string_is_bad_param(loader, value):
    assert build_attack_chain_impl(loader, value)["error"]["code"] == "bad_param"


def test_reverse_adjacency_is_built_once_and_reset_on_load(loader):
    first = loader.reverse_adjacency
    assert loader.reverse_adjacency is first
    assert [(src, rel) for src, rel, _, _ in first["T1548"]["capec"]] == [
        ("CAPEC-233", "technique"),
        ("CAPEC-122", "technique"),
    ]
    loader.load()
    assert loader.reverse_adjacency is not first


def test_new_tools_report_index_not_loaded(tmp_path):
    ld = IndexLoader(tmp_path / "missing")
    assert build_attack_chain_impl(ld, "T1548")["error"]["code"] == "index_not_loaded"
    assert get_defenses_impl(ld, technique_id="T1548")["error"]["code"] == "index_not_loaded"
    assert kev_status_impl(ld, "CVE-2002-0367")["error"]["code"] == "index_not_loaded"


# ------------------------------------------------------------ F2 defenses


def test_defenses_for_technique(loader):
    resp = get_defenses_impl(loader, technique_id="T1548")
    assert resp["ok"] is True
    assert resp["meta"]["count"] == 5
    for d in resp["data"]:
        assert d["id"] and d["name"] and d["mapping_source"]
        assert d["via_techniques"] == ["T1548"]


def test_defenses_for_cve_name_the_technique(loader):
    resp = get_defenses_impl(loader, cve_id="cve-2002-0367")
    assert resp["ok"] is True
    assert resp["meta"]["techniques"] == ["T1548"]
    assert len(resp["data"]) == 5
    for d in resp["data"]:
        assert d["via_techniques"] == ["T1548"]
        assert "direct" not in d
        # CVE -> T1548 is a derived pipeline link, so the composed path is
        # derived even though T1548 -> D3FEND is official.
        assert d["tier"] == "derived"
        assert "Pipeline (CAPEC→Technique chain)" in d["mapping_source"]
        assert "MITRE D3FEND" in d["mapping_source"]


def test_defenses_for_technique_keep_official_provenance(loader):
    for d in get_defenses_impl(loader, technique_id="T1548")["data"]:
        assert d["tier"] == "official" and d["mapping_source"] == "MITRE D3FEND"


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"technique_id": "T1548", "cve_id": "CVE-2002-0367"},
        {"technique_id": "  ", "cve_id": None},
        {"technique_id": None, "cve_id": ""},
    ],
)
def test_defenses_need_exactly_one_argument(loader, kwargs):
    assert get_defenses_impl(loader, **kwargs)["error"]["code"] == "bad_param"


def test_defenses_bad_cve_id_is_bad_param(loader):
    assert get_defenses_impl(loader, cve_id="CVE-20-1")["error"]["code"] == "bad_param"


@pytest.mark.parametrize(
    "kwargs",
    [{"technique_id": 42}, {"cve_id": 42}, {"technique_id": ["T1548"]}, {"technique_id": 42, "cve_id": None}],
)
def test_defenses_non_string_args_are_bad_param(loader, kwargs):
    assert get_defenses_impl(loader, **kwargs)["error"]["code"] == "bad_param"


def test_defenses_unknown_or_wrong_type_ids(loader):
    assert get_defenses_impl(loader, technique_id="T9999")["error"]["code"] == "not_found"
    assert get_defenses_impl(loader, technique_id="CWE-269")["error"]["code"] == "invalid_type"
    assert get_defenses_impl(loader, cve_id="CVE-2099-0001")["error"]["code"] == "not_found"


def test_defenses_shard_only_cve_carry_relationship_verb(loader):
    resp = get_defenses_impl(loader, cve_id="CVE-2024-31337")
    assert resp["ok"] is True
    assert resp["meta"]["source"] == "shard"
    assert resp["meta"]["techniques"] == ["T1059"]
    (psa,) = resp["data"]
    assert psa["id"] == "D3-PSA"
    assert psa["relationship"] == "analyzes"
    assert psa["name"] == "Process Spawn Analysis"
    assert "direct" not in psa
    assert psa["via_techniques"] == []
    assert psa["tier"] == "derived"


def _defend_graph() -> dict:
    return {
        "T9100": {"type": "technique", "rels": {"defend": _rel(["D3-ISO", "ProcessIsolationFrag"], "MITRE D3FEND", "official")}},
        "CVE-2023-1000": {
            "type": "cve",
            "kev": True,
            "rels": {
                "technique": _rel(["T9100"], "Pipeline", "derived"),
                "defend": _rel(["D3-ISO", "D3-DIRECT"], "Pipeline", "derived"),
            },
        },
        "CVE-2023-2000": {"type": "cve", "kev": False, "rels": {}},
        "D3-ISO": {"type": "defend", "name": "Isolation"},
        "ProcessIsolationFrag": {"type": "defend", "name": "Process Isolation"},
        "D3-DIRECT": {"type": "defend", "name": "Direct"},
    }


def test_defenses_graph_cve_gets_verbs_by_id_and_by_fragment(tmp_path):
    shard = {
        "CVE-2023-1000": {
            "DEFEND": [
                {"id": "D3-ISO", "name": "Isolation", "relationship": "isolates"},
                {"id": "D3-PI", "d3fend_fragment": "ProcessIsolationFrag", "name": "Process Isolation", "relationship": "hardens"},
            ]
        }
    }
    resp = get_defenses_impl(_graph(tmp_path, _defend_graph(), shard=shard), cve_id="CVE-2023-1000")
    by_id = {d["id"]: d for d in resp["data"]}
    assert by_id["D3-ISO"]["relationship"] == "isolates"
    assert by_id["ProcessIsolationFrag"]["relationship"] == "hardens"
    assert "relationship" not in by_id["D3-DIRECT"]
    # A defense only on the CVE's own rel is kept, with no technique and the
    # rel's own (derived) tier and source.
    assert by_id["D3-DIRECT"]["via_techniques"] == []
    assert by_id["D3-DIRECT"]["tier"] == "derived"
    assert by_id["D3-DIRECT"]["mapping_source"] == "Pipeline"
    for d in resp["data"]:
        assert "direct" not in d
        assert d["tier"] == "derived"
    assert by_id["ProcessIsolationFrag"]["via_techniques"] == ["T9100"]


def test_defenses_cve_tier_is_weakest_hop_not_first_seen(tmp_path):
    # The technique path is seen first and is official on its D3FEND hop;
    # the CVE -> technique hop is derived, so the defense must be derived.
    resp = get_defenses_impl(_graph(tmp_path, _defend_graph()), cve_id="CVE-2023-1000")
    iso = {d["id"]: d for d in resp["data"]}["D3-ISO"]
    assert iso["via_techniques"] == ["T9100"]
    assert iso["tier"] == "derived"
    assert "Pipeline" in iso["mapping_source"] and "MITRE D3FEND" in iso["mapping_source"]


def test_defenses_cve_without_techniques_says_so(tmp_path):
    resp = get_defenses_impl(_graph(tmp_path, _defend_graph()), cve_id="CVE-2023-2000")
    assert resp["ok"] is True and resp["data"] == []
    assert "no ATT&CK technique" in resp["meta"]["note"]


def test_defenses_corrupt_shard(tmp_path):
    ld = _graph(tmp_path, _defend_graph())
    (tmp_path / "database" / "CVE-2023.jsonl.gz").write_bytes(b"not gzip")
    resp = get_defenses_impl(ld, cve_id="CVE-2023-1000")
    assert resp["ok"] is True and "shard_error" in resp["meta"]
    assert get_defenses_impl(ld, cve_id="CVE-2023-3000")["error"]["code"] == "data_corrupt"


# ---------------------------------------------------------------- F3 KEV


def test_kev_status_in_kev(loader):
    resp = kev_status_impl(loader, " cve-2002-0367 ")
    assert resp["ok"] is True
    data = resp["data"]
    assert data["cve_id"] == "CVE-2002-0367"
    assert data["in_kev"] is True
    assert data["date_added"] == "2022-03-03"
    assert data["due_date"] == "2022-03-24"
    assert data["known_ransomware_campaign_use"] == "Known"
    assert data["required_action"].startswith("Apply updates")
    assert data["vendor_project"] == "Microsoft"
    assert data["product"] == "Windows"
    assert resp["meta"]["kev_source"] == "kev_db.json"


def test_kev_status_not_in_kev_is_ok_with_nulls(loader):
    resp = kev_status_impl(loader, "CVE-2024-99999")
    assert resp["ok"] is True
    assert resp["data"]["in_kev"] is False
    for key in KEV_KEYS:
        assert resp["data"][key] is None
    assert resp["data"]["ssvc"] is None


def test_kev_status_uses_catalog_for_cve_outside_graph(loader):
    assert loader.resolve_entity_key("CVE-2024-31337") is None
    resp = kev_status_impl(loader, "CVE-2024-31337")
    assert resp["data"]["in_kev"] is True
    assert resp["data"]["date_added"] == "2024-05-01"
    assert resp["meta"]["in_entity_graph"] is False


def test_kev_status_catalog_overrides_graph_flag(loader):
    # CVE-2022-23748 is kev=true in the fixture graph but absent from the
    # fixture catalog: the catalog is authoritative.
    assert loader.entities["CVE-2022-23748"]["kev"] is True
    assert kev_status_impl(loader, "CVE-2022-23748")["data"]["in_kev"] is False


def test_kev_status_ssvc_from_entity_shard_or_null(tmp_path):
    ssvc = {"ssvcExploitStatus": "active", "ssvcAutomatable": "yes", "ssvcTechnicalImpact": "total"}
    ents = {
        "CVE-2023-0001": {"type": "cve", "kev": True, "ssvc": ssvc},
        "CVE-2023-0002": {"type": "cve", "kev": False},
    }
    shard = {
        "CVE-2023-0002": {"VULNRICHMENT": {"ssvcExploitStatus": "poc", "ssvcAutomatable": "no"}},
        "CVE-2023-0003": {"VULNRICHMENT": None},
    }
    ld = _graph(tmp_path, ents, kev_db={}, shard=shard)
    one = kev_status_impl(ld, "CVE-2023-0001")
    assert one["data"]["ssvc"] == ssvc and one["meta"]["ssvc_source"] == "entity_index.json"
    two = kev_status_impl(ld, "CVE-2023-0002")
    assert two["data"]["ssvc"] == {"ssvcExploitStatus": "poc", "ssvcAutomatable": "no"}
    assert two["meta"]["ssvc_source"] == "shard"
    three = kev_status_impl(ld, "CVE-2023-0003")
    assert three["data"]["ssvc"] is None and three["meta"]["ssvc_source"] is None


@pytest.mark.parametrize("value", ["CVE-2023", "T1499", "", None, 7, "CVE-23-44487"])
def test_kev_status_malformed_id_is_bad_param(loader, value):
    assert kev_status_impl(loader, value)["error"]["code"] == "bad_param"


def test_kev_status_never_ingested_cve_is_ok_with_note(loader):
    resp = kev_status_impl(loader, "CVE-2031-0001")
    assert resp["ok"] is True
    assert resp["data"]["in_kev"] is False
    assert "not in the entity graph or the shards" in resp["meta"]["note"]


def test_kev_status_without_catalog_falls_back_to_graph(tmp_path):
    ents = {
        "CVE-2023-0001": {
            "type": "cve",
            "kev": True,
            "kev_detail": {"dateAdded": "2023-01-01", "dueDate": "2023-01-22"},
        },
        "CVE-2023-0002": {"type": "cve", "kev": True},
        "CVE-2023-0004": {"type": "cve", "kev": False},
    }
    shard = {"CVE-2023-0003": {"KEV": {"inKEV": True, "dateAdded": "2023-02-02"}}}
    ld = _graph(tmp_path, ents, shard=shard)
    assert ld.kev_db is None
    one = kev_status_impl(ld, "CVE-2023-0001")
    assert one["data"]["in_kev"] is True and one["data"]["date_added"] == "2023-01-01"
    assert one["meta"]["kev_source"] == "entity_index.json"
    assert "kev_db.json unavailable" in one["meta"]["note"]
    two = kev_status_impl(ld, "CVE-2023-0002")
    assert two["data"]["in_kev"] is True and two["data"]["date_added"] is None
    three = kev_status_impl(ld, "CVE-2023-0003")
    assert three["data"]["date_added"] == "2023-02-02" and three["meta"]["kev_source"] == "shard"
    assert kev_status_impl(ld, "CVE-2023-0004")["data"]["in_kev"] is False


def test_kev_db_malformed_is_treated_as_absent(tmp_path):
    ld = _graph(tmp_path, {"CVE-2023-0001": {"type": "cve", "kev": True}})
    (tmp_path / "kev_db.json").write_text("{not json")
    assert ld.kev_db is None
    (tmp_path / "kev_db.json").write_text("[1, 2]")
    ld.load()
    assert ld.kev_db is None


def test_kev_status_corrupt_shard_still_answers(tmp_path):
    ld = _graph(tmp_path, {"CVE-2023-0001": {"type": "cve", "kev": True}}, kev_db={"CVE-2023-0001": {"inKEV": True}})
    (tmp_path / "database" / "CVE-2023.jsonl.gz").write_bytes(b"not gzip")
    resp = kev_status_impl(ld, "CVE-2023-0001")
    assert resp["ok"] is True and resp["data"]["in_kev"] is True
    assert "shard_error" in resp["meta"]


def test_sweep_catches_a_mislabeled_inherited_flag(loader):
    # The checker recomputes "inherited" from cwe_db.json, so a chain that
    # claims an inherited hop is direct (and official) is a violation.
    from .sweeps import chain_tier_violations

    chain = build_attack_chain_impl(loader, "T1548")["data"]
    assert chain_tier_violations(loader, "T1548", chain) == []
    chain["cwes"][0].update(inherited=False, inherited_capecs=[], tier="official")
    kinds = {v["kind"] for v in chain_tier_violations(loader, "T1548", chain)}
    assert kinds == {"cwe-inherited-flag", "cwe"}


def test_chain_unrelated_cwe_and_no_capec_with_own_cves(tmp_path):
    g = _chain_graph()
    # CVE-2020-0001 also carries a CWE that reaches no chain CAPEC.
    g["CWE-999"] = {"type": "cwe", "rels": {"cve": _rel(["CVE-2020-0001"], "NVD", "authoritative")}}
    data = build_attack_chain_impl(_graph(tmp_path, g), "T9001")["data"]
    assert {c["id"]: c for c in data["cves"]}["CVE-2020-0001"]["via_cwes"] == ["CWE-900"]
    assert [c["id"] for c in data["cwes"]] == ["CWE-900"]
    # Without its CAPEC the technique still lists its own CVEs, unexplained.
    del g["CAPEC-900"]
    resp = build_attack_chain_impl(_graph(tmp_path, g), "T9001")
    assert resp["data"]["capecs"] == [] and len(resp["data"]["cves"]) == 4
    assert "No CAPEC" in resp["meta"]["note"] and "4 linked CVEs" in resp["meta"]["note"]


def test_cwe_db_malformed_or_odd_entries(tmp_path):
    ld = _graph(tmp_path, _chain_graph())
    (tmp_path / "cwe_db.json").write_text("{not json")
    assert ld.cwe_related_capecs is None
    (tmp_path / "cwe_db.json").write_text(json.dumps({"900": {"RelatedAttackPatterns": [900]}, "901": "junk"}))
    ld.load()
    assert ld.cwe_related_capecs == {"900": frozenset({"900"})}


def test_pivot_hits_carry_link_provenance(loader):
    """Every pivot hit names the source and tier of the link it came from, on
    both the entity path and the shard path, so a derived mapping never reads
    as a stated fact."""
    from tip_mcp.tools import pivot_from_entity_impl

    for entity_id, rel_owner in (("T1548", "T1548"),):
        res = pivot_from_entity_impl(loader, entity_id)
        assert res["ok"] and res["data"]
        rels = loader.entities[rel_owner]["rels"]
        for hit in res["data"]:
            body = rels[hit["rel_type"]]
            assert hit["source"] == body.get("source")
            assert hit["tier"] == body.get("tier")


def test_pivot_shard_hits_are_derived(loader):
    from tip_mcp.tools import pivot_from_entity_impl

    res = pivot_from_entity_impl(loader, "CVE-2024-31337")
    assert res["ok"] and res["meta"]["source"] == "shard" and res["data"]
    assert {h["tier"] for h in res["data"]} == {"derived"}
