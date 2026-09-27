"""I29: NVD-assigned CWEs apart from inherited parents (ISC-1 to ISC-9).

Fixture data only; nothing is fetched.
"""
import logging
import re
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


_PILLAR_NUMS = {p[4:] for p in ids.CWE_PILLARS}
# Any bracketed or braced literal (Python set/list/tuple/frozenset, JS array
# or object), across lines.
_LITERAL_RE = re.compile(r"[\[{(]([^\[\]{}()]*)[\]})]", re.DOTALL)
_NUM_RE = re.compile(r"(?:CWE-?)?\b(\d+)\b", re.IGNORECASE)


def _pillar_literals(text: str) -> list[set[str]]:
    """Literals naming 3+ distinct pillar numbers (bare or CWE-prefixed)."""
    out = []
    for m in _LITERAL_RE.finditer(text):
        nums = {n for n in _NUM_RE.findall(m.group(1)) if n in _PILLAR_NUMS}
        if len(nums) >= 3:
            out.append(nums)
    return out


def test_isc5_pillar_literal_scan_catches_a_second_copy():
    """The scan below would catch the copies a second pillar list could take."""
    assert _pillar_literals('X = frozenset({"CWE-284", "CWE-435",\n "CWE-664"})')
    assert _pillar_literals("const P = [664, 682, 691];")
    assert _pillar_literals("p = ('693', '697', '703')")
    assert not _pillar_literals('x = ["CWE-79", "CWE-664", "CWE-400"]')


def test_isc5_pillar_constant_defined_once():
    """The pillar set is id_normalize.CWE_PILLARS, parsed from that module's
    source, and no other literal in src, scripts, or docs/js names 3+ pillars."""
    source = (REPO / "src" / "tip" / "core" / "id_normalize.py").read_text(encoding="utf-8")
    m = re.search(r"^CWE_PILLARS = frozenset\((\{.*?\})\)", source, re.DOTALL | re.MULTILINE)
    assert m, "CWE_PILLARS literal not found in id_normalize.py"
    assert {f"CWE-{n}" for n in _NUM_RE.findall(m.group(1))} == set(ids.CWE_PILLARS)
    assert len(ids.CWE_PILLARS) == 10

    hits = []
    for path in list((REPO / "src").rglob("*.py")) + list((REPO / "scripts").rglob("*.py")) \
            + list((REPO / "docs" / "js").rglob("*.js")):
        for nums in _pillar_literals(path.read_text(encoding="utf-8")):
            hits.append((path.relative_to(REPO).as_posix(), len(nums)))
    assert hits == [("src/tip/core/id_normalize.py", 10)]


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


# F2: entity index -------------------------------------------------------------

import gzip  # noqa: E402
import json  # noqa: E402

from tip.core.entity_index_generator import generate_entity_index  # noqa: E402

KEV_ENTRY = {"inKEV": True, "dateAdded": "2024-01-01", "vendorProject": "V", "product": "P"}

NEW_RECORD = {
    "CWE": ["CWE-79"], "CWE_INHERITED": ["CWE-74"],
    "CAPEC": ["63"], "CAPEC_INHERITED": ["66"],
    "TECHNIQUES": ["1059"], "TECHNIQUES_INHERITED": ["1190"],
    "OWASP": ["A03:2021"], "OWASP_INHERITED": ["A05:2021"],
    "DEFEND": [{"id": "D3-EAL"}, {"id": "D3-NTA", "inherited": True}],
}
LEGACY_RECORD = {"CWE": ["74", "CWE-79"], "CAPEC": ["63", "66"], "TECHNIQUES": ["1059", "1190"],
                 "OWASP": ["A03:2021", "A05:2021"], "DEFEND": [{"id": "D3-EAL"}, {"id": "D3-NTA"}]}


def _write(base: Path, records: dict) -> None:
    data = base / "docs" / "data"
    db = base / "docs" / "database"
    data.mkdir(parents=True)
    db.mkdir(parents=True)
    (data / "cwe_db.json").write_text(json.dumps(CWE_DB))
    (data / "capec_db.json").write_text(json.dumps({
        k: {"name": f"CAPEC {k}", "techniques": "".join(f"::TAXONOMY NAME:ATTACK:ENTRY ID:{t}" for t in v) + "::"}
        for k, v in CAPEC_TECH.items()}))
    (data / "techniques_db.json").write_text(json.dumps(
        {t: {"name": f"Tech {t}"} for t in ("1059", "1190", "1562", "1499", "1134")}))
    (data / "groups_db.json").write_text(json.dumps({
        "groups": {"G0007": {"name": "APT28", "aliases": [], "techniques": ["T1059"]},
                   "G0016": {"name": "APT29", "aliases": [], "techniques": ["T1190"]}},
        "technique_to_groups": {"T1059": ["G0007"], "T1190": ["G0016"]},
    }))
    (data / "campaigns_db.json").write_text("{}")
    (data / "kev_db.json").write_text(json.dumps({k: KEV_ENTRY for k in records}))
    (data / "vulnrichment_db.json").write_text("{}")
    with open(data / "defend_db.jsonl", "w") as f:
        for tech, defs in DEFEND.items():
            f.write(json.dumps({tech: {"defensive_techniques": defs}}) + "\n")
    with gzip.open(db / "CVE-2024.jsonl.gz", "wt") as f:
        for k, v in records.items():
            f.write(json.dumps({k: v}) + "\n")


def _index(tmp_path, records):
    _write(tmp_path, records)
    ei, _, _ = generate_entity_index(tmp_path)
    return ei


def _dangling(entities):
    return [(eid, rel, t) for eid, e in entities.items()
            for rel, v in e["rels"].items() for t in v["ids"] if t not in entities]


def test_isc6_cve_cwe_rels_are_assigned_only(tmp_path):
    ents = _index(tmp_path, {"CVE-2024-0001": NEW_RECORD})["entities"]
    cve = ents["CVE-2024-0001"]
    assert cve["rels"]["cwe"]["ids"] == ["CWE-79"]
    assert cve["rels"]["cwe"]["tier"] == "authoritative"
    assert "inherited" not in cve["rels"]["cwe"]
    assert cve["cwe_inherited"] == ["CWE-74"]
    assert "cve" not in ents["CWE-74"]["rels"]
    assert ents["CWE-79"]["rels"]["cve"]["ids"] == ["CVE-2024-0001"]


def test_isc7_inherited_subsets_both_directions(tmp_path):
    ei = _index(tmp_path, {"CVE-2024-0001": NEW_RECORD, "CVE-2024-0002": {
        "CWE": ["CWE-74"], "CWE_INHERITED": [], "CAPEC": ["63", "66"], "CAPEC_INHERITED": [],
        "TECHNIQUES": ["1059", "1190"], "TECHNIQUES_INHERITED": [], "OWASP": ["A05:2021"],
        "OWASP_INHERITED": [], "DEFEND": [{"id": "D3-EAL"}, {"id": "D3-NTA"}]}})
    ents = ei["entities"]
    rels = ents["CVE-2024-0001"]["rels"]
    assert rels["capec"]["ids"] == ["CAPEC-63", "CAPEC-66"] and rels["capec"]["inherited"] == ["CAPEC-66"]
    assert rels["technique"]["ids"] == ["T1059", "T1190"] and rels["technique"]["inherited"] == ["T1190"]
    assert rels["defend"]["ids"] == ["D3-EAL", "D3-NTA"] and rels["defend"]["inherited"] == ["D3-NTA"]
    assert rels["owasp"]["ids"] == ["A03:2021", "A05:2021"] and rels["owasp"]["inherited"] == ["A05:2021"]
    assert rels["apt_group"]["ids"] == ["G0007", "G0016"] and rels["apt_group"]["inherited"] == ["G0016"]
    # Tier and source per rel type are unchanged (format constraint).
    assert rels["technique"]["tier"] == "derived"
    # Reverse edges: the other CVE reaches the same targets directly.
    for target, rel in (("CAPEC-66", "cve"), ("T1190", "cve"), ("D3-NTA", "cve"),
                        ("A05:2021", "cve"), ("G0016", "cve")):
        body = ents[target]["rels"][rel]
        assert body["ids"] == ["CVE-2024-0001", "CVE-2024-0002"], target
        assert body["inherited"] == ["CVE-2024-0001"], target
    assert "inherited" not in ents["CAPEC-63"]["rels"]["cve"]
    assert "inherited" not in ents["CVE-2024-0002"]["rels"]["technique"]
    assert _dangling(ents) == []
    assert ei["meta"]["inherited_links"] is True


def test_isc8_cwe_capec_rels_label_ancestor_capecs(tmp_path):
    ents = _index(tmp_path, {"CVE-2024-0001": NEW_RECORD})["entities"]
    c79 = ents["CWE-79"]["rels"]["capec"]
    assert c79["ids"] == ["CAPEC-152", "CAPEC-63", "CAPEC-66"]
    assert c79["inherited"] == ["CAPEC-152", "CAPEC-66"]
    c74 = ents["CWE-74"]["rels"]["capec"]
    assert c74["inherited"] == ["CAPEC-152"]
    assert "inherited" not in ents["CWE-707"]["rels"]["capec"]


def test_isc9_legacy_shard_generates_as_today(tmp_path):
    ents = _index(tmp_path, {"CVE-2024-0001": LEGACY_RECORD})["entities"]
    cve = ents["CVE-2024-0001"]
    assert cve["rels"]["cwe"]["ids"] == ["CWE-74", "CWE-79"]
    assert "cwe_inherited" not in cve
    for rel, body in cve["rels"].items():
        assert "inherited" not in body, rel
    assert cve["rels"]["technique"]["ids"] == ["T1059", "T1190"]
    assert cve["rels"]["defend"]["ids"] == ["D3-EAL", "D3-NTA"]
    assert "CVE-2024-0001" in ents["CWE-74"]["rels"]["cve"]["ids"]
