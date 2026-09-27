"""I29: NVD-assigned CWEs apart from inherited parents (ISC-1 to ISC-9).

Fixture data only; nothing is fetched.
"""
import logging
from pathlib import Path
from types import SimpleNamespace

from tip.core import id_normalize as ids
from tip.core.cve_processor import CVEProcessor, derive_cve_links

REPO = Path(__file__).resolve().parents[1]

# 79 -ChildOf-> 74 -ChildOf-> 707 (pillar); 400 -ChildOf-> 664 (pillar);
# 89 -ChildOf-> 943 -ChildOf-> 74.
CWE_DB = {
    "79": {"name": "XSS", "ChildOf": ["74"], "RelatedAttackPatterns": ["63"]},
    "74": {"name": "Injection", "ChildOf": ["707"], "RelatedAttackPatterns": ["66", "63"]},
    "707": {"name": "Improper Neutralization", "ChildOf": [], "RelatedAttackPatterns": ["152"]},
    "400": {"name": "Resource Consumption", "ChildOf": ["664"], "RelatedAttackPatterns": ["147"]},
    "664": {"name": "Resource Control", "ChildOf": [], "RelatedAttackPatterns": ["21"]},
    "89": {"name": "SQLi", "ChildOf": ["943"], "RelatedAttackPatterns": []},
    "943": {"name": "Data Query Logic", "ChildOf": ["74"], "RelatedAttackPatterns": []},
}
CAPEC_TECH = {
    "63": ["1059"],
    "66": ["1190", "1059"],
    "152": ["1562"],
    "147": ["1499"],
    "21": ["1134"],
}
OWASP = {"79": ["A03:2021"], "74": ["A03:2021", "A05:2021"], "664": ["A04:2021"]}
DEFEND = {
    "1059": [{"id": "D3-EAL", "name": "Allowlisting"}],
    "1190": [{"id": "D3-EAL", "name": "Allowlisting"}, {"id": "D3-NTA", "name": "Traffic Analysis"}],
}


def _processor():
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.cwe_db = CWE_DB
    proc.capec_db = {k: {"techniques": "".join(f"::TAXONOMY NAME:ATTACK:ENTRY ID:{t}" for t in v) + "::"}
                     for k, v in CAPEC_TECH.items()}
    proc.techniques_db = {}
    proc.logger = logging.getLogger("test_i29")
    proc.owasp_processor = SimpleNamespace(
        get_owasp_categories_for_cwes=lambda cwes: {o for c in cwes for o in OWASP.get(c.replace("CWE-", ""), [])})
    proc.kev_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.vulnrichment_processor = SimpleNamespace(lookup=lambda cid: None)
    seen_techs: list = []
    proc.apt_processor = SimpleNamespace(
        lookup_by_techniques=lambda t: seen_techs.append(sorted(t)) or [{"id": "G0007", "name": "APT28"}])
    proc.get_defend_techniques = lambda t: DEFEND.get(t, [])
    return proc, seen_techs


def _run(cwes):
    proc, seen = _processor()
    return proc.process_cve_pipeline({"CVE-2024-0001": {"CWE": cwes}})["CVE-2024-0001"], seen


# F1: ingestion ----------------------------------------------------------------

def test_isc1_pillar_parent_is_not_inherited():
    rec, _ = _run(["CWE-400"])
    assert rec["CWE"] == ["CWE-400"]
    assert rec["CWE_INHERITED"] == []
    # CWE-664's CAPEC-21 and T1134 are not reached at all.
    assert rec["CAPEC"] == ["147"] and rec["CAPEC_INHERITED"] == []
    assert rec["TECHNIQUES"] == ["1499"] and rec["TECHNIQUES_INHERITED"] == []
    assert rec["OWASP"] == [] and rec["OWASP_INHERITED"] == []


def test_isc1_non_pillar_parent_is_inherited():
    rec, _ = _run(["79"])
    assert rec["CWE"] == ["CWE-79"]
    assert rec["CWE_INHERITED"] == ["CWE-74"]


def test_isc2_direct_and_inherited_lists_are_disjoint():
    rec, _ = _run(["CWE-79"])
    # 79 owns CAPEC-63; 74 adds 66 (63 is already direct).
    assert rec["CAPEC"] == ["63"]
    assert rec["CAPEC_INHERITED"] == ["66"]
    assert rec["TECHNIQUES"] == ["1059"]
    assert rec["TECHNIQUES_INHERITED"] == ["1190"]
    assert rec["OWASP"] == ["A03:2021"]
    assert rec["OWASP_INHERITED"] == ["A05:2021"]


def test_isc2_assigned_parent_is_direct_not_inherited():
    """When NVD assigns both child and parent, the parent is assigned."""
    rec, _ = _run(["CWE-79", "CWE-74"])
    assert rec["CWE"] == ["CWE-74", "CWE-79"]
    assert rec["CWE_INHERITED"] == []
    assert rec["CAPEC"] == ["63", "66"] and rec["CAPEC_INHERITED"] == []


def test_isc3_defend_inherited_flag():
    rec, _ = _run(["CWE-79"])
    by_id = {d["id"]: d for d in rec["DEFEND"]}
    assert set(by_id) == {"D3-EAL", "D3-NTA"}
    assert "inherited" not in by_id["D3-EAL"]  # also reached through T1059 (direct)
    assert by_id["D3-NTA"]["inherited"] is True
    # The cached lookup lists are never mutated.
    assert all("inherited" not in d for d in DEFEND["1190"])


def test_isc3_apt_lookup_uses_direct_and_inherited_techniques():
    """APT linkage is out of I29's scope: the lookup keeps the same technique
    set it had, minus what only pillar parents supplied."""
    rec, seen = _run(["CWE-79"])
    assert seen == [["1059", "1190"]]
    assert rec["APT_GROUPS"][0]["id"] == "G0007"


def test_isc4_no_pillar_is_ever_inherited():
    pillars = sorted(ids.CWE_PILLARS)
    assert len(pillars) == 10
    db = {str(n): {"ChildOf": [p[4:] for p in pillars]} for n in range(1, 50)}
    for n in range(1, 50):
        assigned, inherited = ids.split_cwe_list(db, [str(n)])
        assert inherited == [] and assigned == [f"CWE-{n}"]
    # A pillar NVD assigns directly stays assigned.
    assert ids.split_cwe_list(CWE_DB, ["CWE-664"]) == (["CWE-664"], [])


def test_isc5_pillar_constant_defined_once():
    """No second pillar list in the code: CWE-693 and CWE-710 appear together
    in one file only (pure Python, so CI needs no rg)."""
    hits = []
    for path in list((REPO / "src").rglob("*.py")) + list((REPO / "scripts").rglob("*.py")) \
            + list((REPO / "docs" / "js").rglob("*.js")):
        text = path.read_text(encoding="utf-8")
        if "693" in text and "710" in text and "284" in text:
            hits.append(path.relative_to(REPO).as_posix())
    assert hits == ["src/tip/core/id_normalize.py"]


def test_derive_is_pure_and_matches_processor():
    rec, _ = _run(["CWE-79"])
    assigned, inherited = ids.split_cwe_list(CWE_DB, ["CWE-79"])
    links = derive_cve_links(
        assigned, inherited,
        capecs_for_cwe=lambda c: CWE_DB.get(c[4:], {}).get("RelatedAttackPatterns", []),
        techniques_for_capec=lambda c: CAPEC_TECH.get(c, []),
        owasp_for_cwes=lambda cs: {o for c in cs for o in OWASP.get(c[4:], [])},
    )
    for key, value in links.items():
        assert rec[key] == value
