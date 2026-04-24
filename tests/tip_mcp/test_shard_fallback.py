"""Tests for MCP shard fallback in lookup_entity_impl.

These verify that a CVE ID which is not in the enriched entity graph
(entity_index.json) is still discoverable by scanning the per-year JSONL
shard on disk. The fixture shard at fixtures/database/CVE-2024.jsonl.gz
contains CVE-2024-31337 and CVE-2024-99999.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from tip_mcp.loader import IndexLoader
from tip_mcp.tools import lookup_entity_impl, pivot_from_entity_impl


def test_shard_fallback_returns_ok_for_cve_not_in_entity_index(loader):
    resp = lookup_entity_impl(loader, "CVE-2024-31337")
    assert resp["ok"] is True, resp
    assert resp["meta"]["source"] == "shard"
    assert resp["meta"]["shard"].startswith("CVE-2024.jsonl")
    data = resp["data"]
    assert data["id"] == "CVE-2024-31337"
    assert data["type"] == "cve"
    assert "cross-site scripting" in data["description"].lower()
    assert data["name"].startswith("A cross-site scripting")


def test_shard_fallback_exposes_cvss_and_dates(loader):
    resp = lookup_entity_impl(loader, "CVE-2024-31337")
    data = resp["data"]
    assert data["cvss_score"] == 6.5
    assert data["severity"] == "MEDIUM"
    assert data["cvss_vector"].startswith("CVSS:3.1")
    assert data["published"] == "2024-06-15T12:00:00.000"
    assert data["last_modified"] == "2024-06-20T08:00:00.000"
    assert data["references"] == [
        "https://example.com/advisory-1",
        "https://example.com/cve-2024-31337",
    ]


def test_shard_fallback_emits_cwe_and_technique_rels(loader):
    resp = lookup_entity_impl(loader, "CVE-2024-31337")
    rels = resp["data"]["rels"]
    target_ids = {r["target_id"] for r in rels}
    assert "CWE-79" in target_ids
    assert "CAPEC-86" in target_ids
    assert "T1059" in target_ids


def test_shard_fallback_case_insensitive_cve_id(loader):
    resp = lookup_entity_impl(loader, "cve-2024-31337")
    assert resp["ok"] is True
    assert resp["data"]["id"] == "CVE-2024-31337"


def test_shard_fallback_not_found_for_missing_cve(loader):
    resp = lookup_entity_impl(loader, "CVE-2024-00001")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"


def test_shard_fallback_not_found_when_shard_file_missing(
    fixture_data_dir: Path, tmp_path: Path
):
    ld = IndexLoader(fixture_data_dir, shards_dir=tmp_path / "does-not-exist")
    ld.load()
    resp = lookup_entity_impl(ld, "CVE-2024-31337")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"


def test_shard_fallback_skipped_for_non_cve_ids(loader):
    # Bogus ID that is not a CVE pattern must NOT trigger shard scanning,
    # even if the entity graph does not contain it.
    resp = lookup_entity_impl(loader, "NOT-AN-ID")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"


def test_shard_fallback_handles_plain_jsonl_without_gzip(
    fixture_data_dir: Path, tmp_path: Path
):
    shards = tmp_path / "database"
    shards.mkdir()
    payload = {
        "CVE-2023-42424": {
            "CWE": ["CWE-22"],
            "CAPEC": [],
            "TECHNIQUES": [],
            "DEFEND": [],
            "OWASP": [],
            "DESCRIPTION": "Path traversal in ExampleApp.",
        }
    }
    (shards / "CVE-2023.jsonl").write_text(json.dumps(payload) + "\n")

    ld = IndexLoader(fixture_data_dir, shards_dir=shards)
    ld.load()
    resp = lookup_entity_impl(ld, "CVE-2023-42424")
    assert resp["ok"] is True
    assert resp["meta"]["source"] == "shard"
    assert resp["meta"]["shard"] == "CVE-2023.jsonl"


def test_entity_index_lookup_surfaces_cvss_when_present(
    fixture_data_dir: Path, tmp_path: Path
):
    # Build a tiny entity_index that includes a CVE entity carrying the new
    # enriched fields, then confirm lookup_entity_impl surfaces them.
    enriched = {
        "meta": {"sample": True, "entity_count": 1},
        "entities": {
            "CVE-2025-12345": {
                "type": "cve",
                "id": "CVE-2025-12345",
                "name": "Sample buffer overflow.",
                "phase": "vulnerability",
                "description": "Sample buffer overflow. Remote attackers can crash the service.",
                "cvss_score": 9.1,
                "severity": "CRITICAL",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "published": "2025-03-04T00:00:00.000",
                "last_modified": "2025-03-05T00:00:00.000",
                "references": ["https://example.com/advisory"],
                "rels": {},
            }
        },
    }
    (tmp_path / "entity_index.json").write_text(json.dumps(enriched))
    (tmp_path / "search_index.json").write_text("{}")
    ld = IndexLoader(tmp_path, shards_dir=tmp_path / "no-shards")
    ld.load()
    resp = lookup_entity_impl(ld, "CVE-2025-12345")
    assert resp["ok"] is True
    data = resp["data"]
    assert data["cvss_score"] == 9.1
    assert data["severity"] == "CRITICAL"
    assert data["cvss_vector"].startswith("CVSS:3.1")
    assert data["description"].startswith("Sample buffer overflow")
    assert data["published"] == "2025-03-04T00:00:00.000"
    assert data["references"] == ["https://example.com/advisory"]
    assert resp["meta"]["source"] == "entity_index.json"


def test_pivot_shard_fallback_returns_ok_for_cve_not_in_entity_index(loader):
    resp = pivot_from_entity_impl(loader, "CVE-2024-31337")
    assert resp["ok"] is True, resp
    assert resp["meta"]["source"] == "shard"
    assert resp["meta"]["shard"].startswith("CVE-2024.jsonl")
    target_ids = {h["target_id"] if "target_id" in h else h["id"] for h in resp["data"]}
    # Fixture CVE-2024-31337 has CWE-79, CAPEC-86, T1059, A03:2021
    assert "CWE-79" in target_ids
    assert "CAPEC-86" in target_ids
    assert "T1059" in target_ids


def test_pivot_shard_fallback_filters_by_target_type(loader):
    resp = pivot_from_entity_impl(loader, "CVE-2024-31337", target_type="cwe")
    assert resp["ok"] is True
    assert resp["meta"]["source"] == "shard"
    for hit in resp["data"]:
        assert hit["rel_type"] == "cwe" or hit["type"] == "cwe"


def test_pivot_shard_fallback_rejects_invalid_target_type(loader):
    # invalid_type check must fire BEFORE the shard fallback, same as the
    # entity_index path.
    resp = pivot_from_entity_impl(loader, "CVE-2024-31337", target_type="bogus")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "invalid_type"


def test_pivot_shard_fallback_hits_use_entity_name_when_target_indexed(
    fixture_data_dir: Path, tmp_path: Path
):
    # Build a custom entity_index containing the target CWE so we can confirm
    # the hit uses the indexed name rather than the bare ID.
    ei = {
        "meta": {"sample": True, "entity_count": 1},
        "entities": {
            "CWE-79": {
                "type": "cwe",
                "id": "CWE-79",
                "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                "phase": "weakness",
                "rels": {},
            }
        },
    }
    (tmp_path / "entity_index.json").write_text(json.dumps(ei))
    (tmp_path / "search_index.json").write_text("{}")
    # Reuse the fixture shard so CVE-2024-31337 resolves.
    shards_dir = Path(__file__).parent / "fixtures" / "database"
    ld = IndexLoader(tmp_path, shards_dir=shards_dir)
    ld.load()

    resp = pivot_from_entity_impl(ld, "CVE-2024-31337", target_type="cwe")
    assert resp["ok"] is True
    cwe_hit = next((h for h in resp["data"] if h["id"] == "CWE-79"), None)
    assert cwe_hit is not None
    assert "Cross-site Scripting" in cwe_hit["name"]
    assert cwe_hit["type"] == "cwe"


def test_pivot_shard_fallback_falls_back_to_bare_id_when_target_missing(
    fixture_data_dir: Path, tmp_path: Path
):
    # Empty entity_index: no CWE-79 lookup will succeed. The pivot should
    # still return the CWE-79 hit with the bare ID and inferred type.
    (tmp_path / "entity_index.json").write_text(
        json.dumps({"meta": {"entity_count": 0}, "entities": {}})
    )
    (tmp_path / "search_index.json").write_text("{}")
    shards_dir = Path(__file__).parent / "fixtures" / "database"
    ld = IndexLoader(tmp_path, shards_dir=shards_dir)
    ld.load()

    resp = pivot_from_entity_impl(ld, "CVE-2024-31337", target_type="cwe")
    assert resp["ok"] is True
    target_ids = [h["id"] for h in resp["data"]]
    assert "CWE-79" in target_ids
    hit = next(h for h in resp["data"] if h["id"] == "CWE-79")
    assert hit["type"] == "cwe"
    assert hit["name"] == "CWE-79"  # bare ID fallback


def test_pivot_shard_fallback_not_found_for_non_cve_ids(loader):
    resp = pivot_from_entity_impl(loader, "NOT-A-CVE")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"


def test_pivot_shard_fallback_not_found_when_shard_missing(
    fixture_data_dir: Path, tmp_path: Path
):
    ld = IndexLoader(fixture_data_dir, shards_dir=tmp_path / "does-not-exist")
    ld.load()
    resp = pivot_from_entity_impl(ld, "CVE-2024-31337")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"


def test_pivot_entity_index_precedence_over_shard(fixture_data_dir: Path, tmp_path: Path):
    # If the CVE is in entity_index, pivot must use that (source=entity_index.json)
    # even when a shard also contains the ID.
    shards = tmp_path / "database"
    shards.mkdir()
    with (fixture_data_dir / "entity_index.json").open() as f:
        ei = json.load(f)
    real_cve_id = next(
        (eid for eid, e in ei["entities"].items()
         if e.get("type") == "cve" and eid.upper().startswith("CVE-")),
        None,
    )
    if real_cve_id is None:
        pytest.skip("fixture has no CVE entities to shadow")
    year = real_cve_id.split("-")[1]
    import gzip as gz
    with gz.open(shards / f"CVE-{year}.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({real_cve_id: {"CWE": ["CWE-00"]}}) + "\n")

    ld = IndexLoader(fixture_data_dir, shards_dir=shards)
    ld.load()
    resp = pivot_from_entity_impl(ld, real_cve_id)
    assert resp["ok"] is True
    assert resp["meta"]["source"] == "entity_index.json"


def test_shard_fallback_preserves_entity_index_precedence(
    fixture_data_dir: Path, tmp_path: Path
):
    # Build a shard that shadows an ID already present in entity_index.json.
    shards = tmp_path / "database"
    shards.mkdir()
    # Any real CVE ID from fixture entity_index.json; pick one by reading.
    with (fixture_data_dir / "entity_index.json").open() as f:
        ei = json.load(f)
    real_cve_id = next(
        (eid for eid, e in ei["entities"].items()
         if e.get("type") == "cve" and eid.upper().startswith("CVE-")),
        None,
    )
    if real_cve_id is None:
        pytest.skip("fixture has no CVE entities to shadow")

    year = real_cve_id.split("-")[1]
    with gzip.open(shards / f"CVE-{year}.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({real_cve_id: {"DESCRIPTION": "FROM SHARD ONLY"}}) + "\n")

    ld = IndexLoader(fixture_data_dir, shards_dir=shards)
    ld.load()
    resp = lookup_entity_impl(ld, real_cve_id)
    assert resp["ok"] is True
    assert resp["meta"]["source"] == "entity_index.json"
