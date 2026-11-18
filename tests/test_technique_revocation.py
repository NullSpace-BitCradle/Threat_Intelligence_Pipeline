"""Audit 2026-11-18 H2: revoked ATT&CK techniques resolve to their replacement.

CAPEC still names techniques ATT&CK has revoked (T1562.003 -> T1690 in
ATT&CK 20.1). The techniques step writes technique_revocations.json from the
STIX bundle's revoked-by relationships; the CVE chain and the entity index
generator map CAPEC's IDs through it, so no surface serves a revoked ID.

Fixture bundles only; nothing touches the network.
"""
import gzip
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

import tip.core.database_manager as dm_mod
from tip.core.cve_processor import CVEProcessor
from tip.core.entity_index_generator import (
    DanglingGrowthError,
    check_dangling_growth,
    generate_entity_index,
)
from tip.core.technique_revocation import (
    build_revocation_map,
    load_revocation_map,
    resolve_technique_ids,
)


def _technique(stix_id, attack_id, *, revoked=False, deprecated=False):
    obj = {
        "type": "attack-pattern",
        "id": stix_id,
        "name": attack_id,
        "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
    }
    if revoked:
        obj["revoked"] = True
    if deprecated:
        obj["x_mitre_deprecated"] = True
    return obj


def _revoked_by(src, dst):
    return {"type": "relationship", "relationship_type": "revoked-by",
            "source_ref": src, "target_ref": dst}


BUNDLE = {"type": "bundle", "objects": [
    # The audit's real case: T1562.003 revoked by T1690.
    _technique("attack-pattern--a", "T1562.003", revoked=True),
    _technique("attack-pattern--b", "T1690"),
    _revoked_by("attack-pattern--a", "attack-pattern--b"),
    # A chain: T1000 -> T1001 (also revoked) -> T1002 (live).
    _technique("attack-pattern--c", "T1000", revoked=True),
    _technique("attack-pattern--d", "T1001", revoked=True),
    _technique("attack-pattern--e", "T1002"),
    _revoked_by("attack-pattern--c", "attack-pattern--d"),
    _revoked_by("attack-pattern--d", "attack-pattern--e"),
    # Deprecated with no replacement.
    _technique("attack-pattern--f", "T1003", deprecated=True),
    # Revoked by an object outside the bundle.
    _technique("attack-pattern--g", "T1004", revoked=True),
    _revoked_by("attack-pattern--g", "attack-pattern--missing"),
    # A cycle of revoked objects.
    _technique("attack-pattern--h", "T1005", revoked=True),
    _technique("attack-pattern--i", "T1006", revoked=True),
    _revoked_by("attack-pattern--h", "attack-pattern--i"),
    _revoked_by("attack-pattern--i", "attack-pattern--h"),
    # Live and untouched.
    _technique("attack-pattern--j", "T1059"),
]}


def test_revocation_map_follows_revoked_by_to_a_live_technique():
    rev = build_revocation_map(BUNDLE)
    assert rev["1562.003"] == "1690"
    assert rev["1000"] == "1002"
    assert rev["1001"] == "1002"
    assert rev["1003"] is None        # deprecated, no replacement
    assert rev["1004"] is None        # target not in the bundle
    assert rev["1005"] is None and rev["1006"] is None  # cycle
    assert "1059" not in rev and "1690" not in rev and "1002" not in rev


def test_revocation_map_never_retires_an_id_a_live_object_carries():
    bundle = {"objects": [
        _technique("attack-pattern--old", "T1070", revoked=True),
        _technique("attack-pattern--new", "T1070"),
    ]}
    assert build_revocation_map(bundle) == {}


def test_revocation_map_rejects_a_body_without_objects():
    with pytest.raises(ValueError):
        build_revocation_map({"type": "bundle"})


def test_resolve_replaces_drops_dedupes_and_keeps_the_prefix():
    rev = build_revocation_map(BUNDLE)
    assert resolve_technique_ids(["1562.003", "1059", "1003", "1690"], rev) == ["1690", "1059"]
    assert resolve_technique_ids(["T1562.003", "T1000", "T1001"], rev) == ["T1690", "T1002"]
    # An ID the map does not name (T1513 is a mobile technique) passes through.
    assert resolve_technique_ids(["1513"], rev) == ["1513"]
    # No map: everything passes through.
    assert resolve_technique_ids(["1562.003", "1562.003"], None) == ["1562.003"]


def test_load_revocation_map_rejects_bad_shapes(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"1562.003": "1690", "1003": None}))
    assert load_revocation_map(good) == {"1562.003": "1690", "1003": None}
    for name, body in [("list.json", "[]"), ("num.json", '{"1": 2}'), ("bad.json", "{")]:
        path = tmp_path / name
        path.write_text(body)
        assert load_revocation_map(path) is None
    assert load_revocation_map(tmp_path / "missing.json") is None


def test_database_step_writes_the_map_from_the_bundle(tmp_path, monkeypatch):
    target = tmp_path / "technique_revocations.json"
    manager = dm_mod.DatabaseManager()
    manager.databases["technique_revocations"]["file"] = str(target)
    monkeypatch.setattr(dm_mod, "fetch_stix_bundle", lambda url=None: BUNDLE)

    assert manager.update_database("technique_revocations") is True
    assert json.loads(target.read_text())["1562.003"] == "1690"
    assert "technique_revocations" in manager.fresh_writes


def test_database_step_fails_and_keeps_the_file_on_a_bad_bundle(tmp_path, monkeypatch):
    target = tmp_path / "technique_revocations.json"
    target.write_text(json.dumps({"1562.003": "1690"}))
    before = target.read_bytes()
    manager = dm_mod.DatabaseManager()
    manager.databases["technique_revocations"]["file"] = str(target)
    monkeypatch.setattr(dm_mod, "fetch_stix_bundle", lambda url=None: {"objects": []})

    assert manager.update_database("technique_revocations") is False
    assert target.read_bytes() == before


# The CVE chain ------------------------------------------------------------

CWE_DB = {"79": {"name": "XSS", "ChildOf": [], "RelatedAttackPatterns": ["63", "152"]}}
CAPEC_DB = {
    "63": {"name": "XSS pattern", "techniques": "::TAXONOMY NAME:ATTACK:ENTRY ID:1059::"},
    # CAPEC-152 names two revoked techniques that share one replacement path
    # and one deprecated technique with none.
    "152": {"name": "Inject", "techniques": (
        "::TAXONOMY NAME:ATTACK:ENTRY ID:1562.003:ENTRY NAME:Impair History"
        "::TAXONOMY NAME:ATTACK:ENTRY ID:1000::"
        "::TAXONOMY NAME:ATTACK:ENTRY ID:1001::"
        "::TAXONOMY NAME:ATTACK:ENTRY ID:1003::"
    )},
}


def _bare_processor(revocations):
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.cwe_db = CWE_DB
    proc.capec_db = CAPEC_DB
    proc.logger = logging.getLogger("test_technique_revocation")
    proc.owasp_processor = SimpleNamespace(get_owasp_categories_for_cwes=lambda cwes: set())
    proc.kev_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.vulnrichment_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.apt_processor = SimpleNamespace(lookup_attributions=lambda c: [])
    proc.get_defend_techniques = lambda tid: []  # type: ignore[method-assign]
    proc.technique_revocations = revocations
    return proc


def test_cve_chain_carries_only_live_techniques():
    rec = _bare_processor(build_revocation_map(BUNDLE)).process_cve_pipeline(
        {"CVE-2024-0004": {"CWE": ["CWE-79"]}})["CVE-2024-0004"]
    assert rec["TECHNIQUES"] == ["1002", "1059", "1690"]
    assert "1562.003" not in rec["TECHNIQUES"] and "1003" not in rec["TECHNIQUES"]


def test_cve_chain_without_a_map_keeps_capec_ids_as_given():
    rec = _bare_processor(None).process_cve_pipeline(
        {"CVE-2024-0004": {"CWE": ["CWE-79"]}})["CVE-2024-0004"]
    assert rec["TECHNIQUES"] == ["1000", "1001", "1003", "1059", "1562.003"]


# The entity index ---------------------------------------------------------

def _write_index_fixture(base: Path, revocations=None):
    data = base / "docs" / "data"
    db = base / "docs" / "database"
    data.mkdir(parents=True)
    db.mkdir(parents=True)
    (data / "cwe_db.json").write_text(json.dumps(CWE_DB))
    (data / "capec_db.json").write_text(json.dumps(CAPEC_DB))
    (data / "techniques_db.json").write_text(json.dumps({
        "1059": {"name": "Command Interpreter"}, "1690": {"name": "Impair History"},
        "1002": {"name": "Live"},
    }))
    (data / "groups_db.json").write_text(json.dumps({"groups": {}, "technique_to_groups": {}}))
    (data / "campaigns_db.json").write_text(json.dumps({}))
    (data / "kev_db.json").write_text(json.dumps({"CVE-2024-0004": {"inKEV": True}}))
    (data / "vulnrichment_db.json").write_text(json.dumps({}))
    (data / "defend_db.jsonl").write_text(
        json.dumps({"T1690": {"defensive_techniques": [{"id": "D3-SCF", "name": "Filtering"}]}}) + "\n")
    if revocations is not None:
        (data / "technique_revocations.json").write_text(json.dumps(revocations))
    # A shard record written before the fix, still carrying the revoked ID.
    with gzip.open(db / "CVE-2024.jsonl.gz", "wt") as f:
        f.write(json.dumps({"CVE-2024-0004": {
            "CWE": ["CWE-79"], "CAPEC": ["152"], "TECHNIQUES": ["1562.003", "1059"]}}) + "\n")


def test_index_links_capec_and_cve_to_the_replacement(tmp_path):
    _write_index_fixture(tmp_path, build_revocation_map(BUNDLE))
    ei, _, _ = generate_entity_index(tmp_path)
    ents = ei["entities"]
    assert ents["CAPEC-152"]["rels"]["technique"]["ids"] == ["T1002", "T1690"]
    assert ents["CVE-2024-0004"]["rels"]["technique"]["ids"] == ["T1059", "T1690"]
    # D3FEND is keyed by live techniques, so the replacement reaches a defense.
    assert ents["CVE-2024-0004"]["rels"]["defend"]["ids"] == ["D3-SCF"]


def test_index_drops_fewer_dangling_targets_with_the_map(tmp_path):
    with_map, without_map = tmp_path / "with", tmp_path / "without"
    _write_index_fixture(with_map, build_revocation_map(BUNDLE))
    _write_index_fixture(without_map)
    dropped_with = generate_entity_index(with_map)[0]["meta"]["dropped_dangling_rels"]
    dropped_without = generate_entity_index(without_map)[0]["meta"]["dropped_dangling_rels"]
    assert dropped_with < dropped_without


# Dangling growth gate -----------------------------------------------------

def _index_with_dangling(n):
    return {"meta": {"dropped_dangling_rels": n}, "entities": {}}


@pytest.mark.parametrize("previous, new, fails", [
    (961, 961, False),
    (961, 100, False),        # shrinking always passes
    (961, 961 + 96, False),   # 10% of 961
    (961, 961 + 97, True),
    (0, 25, False),           # the 25 floor on the allowance
    (0, 26, True),
])
def test_dangling_growth_gate(tmp_path, previous, new, fails):
    existing = tmp_path / "entity_index.json"
    existing.write_text(json.dumps(_index_with_dangling(previous)))
    if fails:
        with pytest.raises(DanglingGrowthError):
            check_dangling_growth(existing, _index_with_dangling(new))
    else:
        check_dangling_growth(existing, _index_with_dangling(new))


def test_dangling_growth_gate_passes_without_a_previous_count(tmp_path):
    check_dangling_growth(tmp_path / "missing.json", _index_with_dangling(10_000))
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"meta": {}, "entities": {}}))
    check_dangling_growth(legacy, _index_with_dangling(10_000))


def test_write_outputs_refuses_a_dangling_jump_and_writes_nothing(tmp_path):
    from tip.core.entity_index_generator import write_outputs
    out = tmp_path / "data"
    out.mkdir()
    old = {"meta": {"dropped_dangling_rels": 10}, "entities": {"T1059": {"type": "technique"}}}
    (out / "entity_index.json").write_text(json.dumps(old))
    (out / "search_index.json").write_text("{}")
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    new = {"meta": {"dropped_dangling_rels": 500}, "entities": {"T1059": {"type": "technique"}}}

    with pytest.raises(DanglingGrowthError):
        write_outputs(new, {"t1059": ["T1059"]}, tmp_path, out_dir=out)
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before
