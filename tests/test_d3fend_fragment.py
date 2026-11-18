"""Audit 2026-11-18 M2: D3FEND entities carry the fragment D3FEND's pages use.

d3fend.mitre.org serves /technique/d3f:SystemCallFiltering/, not
/technique/d3f:D3-SCF/ (404), and the entity index carried only the D3 ID,
so every D3FEND "view on source" link on the site was a 404. The generator
now copies d3fend_fragment from defend_db.jsonl onto each D3FEND entity, and
the site links with it (smoke test: test_d3fend_source_link.py).
"""
import gzip
import json
from pathlib import Path

from tip.core.entity_index_generator import generate_entity_index


def _fixture(base: Path, defenses: list[dict]) -> None:
    data = base / "docs" / "data"
    db = base / "docs" / "database"
    data.mkdir(parents=True)
    db.mkdir(parents=True)
    (data / "cwe_db.json").write_text(json.dumps({"79": {"name": "XSS", "ChildOf": [], "RelatedAttackPatterns": []}}))
    (data / "capec_db.json").write_text(json.dumps({}))
    (data / "techniques_db.json").write_text(json.dumps({"1059": {"name": "Command Interpreter"}}))
    (data / "groups_db.json").write_text(json.dumps({"groups": {}, "technique_to_groups": {}}))
    (data / "campaigns_db.json").write_text(json.dumps({}))
    (data / "kev_db.json").write_text(json.dumps({"CVE-2024-0001": {"inKEV": True}}))
    (data / "vulnrichment_db.json").write_text(json.dumps({}))
    (data / "defend_db.jsonl").write_text(
        json.dumps({"T1059": {"attack_technique": "T1059", "defensive_techniques": defenses}}) + "\n")
    with gzip.open(db / "CVE-2024.jsonl.gz", "wt") as f:
        f.write(json.dumps({"CVE-2024-0001": {"CWE": ["CWE-79"], "TECHNIQUES": ["1059"]}}) + "\n")


def test_defend_entities_carry_their_fragment(tmp_path):
    _fixture(tmp_path, [
        {"id": "D3-SCF", "d3fend_fragment": "SystemCallFiltering", "name": "System Call Filtering"},
        {"id": "D3-EAL", "name": "Executable Allowlisting"},  # a file written before fragments
    ])
    ents = generate_entity_index(tmp_path)[0]["entities"]
    assert ents["D3-SCF"]["d3fend_fragment"] == "SystemCallFiltering"
    assert "d3fend_fragment" not in ents["D3-EAL"]
    # Only D3FEND entities gain the field.
    assert all("d3fend_fragment" not in e for e in ents.values() if e["type"] != "defend")
