"""Tests for I22: MCP data-contract passthrough.

The pipeline stores rich threat-intel in the per-year CVE shards (full KEV
detail, CISA SSVC decisions, CISA CVSS override, CVSS version/source, and
D3FEND relationship semantics). Before I22 the MCP layer stripped all of it.
These tests assert it now round-trips through ``lookup_entity_impl`` for both
a shard-only CVE and a curated CVE that takes the entity-index path.

Fixtures are built inline via tmp_path so the assertions do not depend on the
shared fixture corpus carrying these fields.
"""

from __future__ import annotations

import json
from pathlib import Path

from tip_mcp.loader import IndexLoader
from tip_mcp.tools import lookup_entity_impl


def _write_indexes(tmp_path: Path, entities: dict) -> Path:
    (tmp_path / "entity_index.json").write_text(
        json.dumps({"meta": {"entity_count": len(entities)}, "entities": entities})
    )
    (tmp_path / "search_index.json").write_text("{}")
    return tmp_path


def _write_shard(tmp_path: Path, cve_id: str, payload: dict) -> Path:
    shards = tmp_path / "database"
    shards.mkdir(exist_ok=True)
    year = cve_id.split("-")[1]
    (shards / f"CVE-{year}.jsonl").write_text(json.dumps({cve_id: payload}) + "\n")
    return shards


_RICH_PAYLOAD = {
    "DESCRIPTION": "The HTTP/2 protocol allows a denial of service. Exploited in the wild.",
    "CVSS": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "severity": "HIGH",
        "version": "3.1",
        "source": "cisa_vulnrichment",
    },
    "CWE": ["CWE-400"],
    "CAPEC": [],
    "TECHNIQUES": ["T1499"],
    "OWASP": [],
    "DEFEND": [
        {
            "id": "D3-ABPI",
            "d3fend_fragment": "Application-basedProcessIsolation",
            "name": "Application-based Process Isolation",
            "relationship": "isolates",
        }
    ],
    "APT_GROUPS": ["G0007"],
    "KEV": {
        "inKEV": True,
        "dateAdded": "2023-10-10",
        "dueDate": "2023-10-31",
        "knownRansomwareCampaignUse": "Unknown",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "vendorProject": "IETF",
        "product": "HTTP/2",
    },
    "VULNRICHMENT": {
        "ssvcExploitStatus": "active",
        "ssvcAutomatable": "no",
        "ssvcTechnicalImpact": "total",
        "cisaCVSS": {"baseScore": 8.7, "vector": "CVSS:4.0/AV:N/AC:L/..."},
    },
}


def test_shard_only_cve_exposes_kev_detail_ssvc_and_cvss_meta(tmp_path: Path) -> None:
    _write_indexes(tmp_path, {})  # CVE not in entity_index -> shard fallback
    shards = _write_shard(tmp_path, "CVE-2023-44487", _RICH_PAYLOAD)
    ld = IndexLoader(tmp_path, shards_dir=shards)
    ld.load()

    resp = lookup_entity_impl(ld, "CVE-2023-44487")
    assert resp["ok"] is True, resp
    assert resp["meta"]["source"] == "shard"
    data = resp["data"]

    assert data["kev_detail"]["dueDate"] == "2023-10-31"
    assert data["kev_detail"]["knownRansomwareCampaignUse"] == "Unknown"
    assert data["ssvc"]["ssvcExploitStatus"] == "active"
    assert data["ssvc"]["ssvcAutomatable"] == "no"
    assert data["ssvc"]["ssvcTechnicalImpact"] == "total"
    assert data["cisa_cvss"]["baseScore"] == 8.7
    assert data["cvss_version"] == "3.1"
    assert data["cvss_source"] == "cisa_vulnrichment"


def test_shard_fallback_adds_d3fend_and_apt_rels_with_semantics(tmp_path: Path) -> None:
    _write_indexes(tmp_path, {})
    shards = _write_shard(tmp_path, "CVE-2023-44487", _RICH_PAYLOAD)
    ld = IndexLoader(tmp_path, shards_dir=shards)
    ld.load()

    rels = lookup_entity_impl(ld, "CVE-2023-44487")["data"]["rels"]
    by_type: dict = {}
    for rel in rels:
        by_type.setdefault(rel["rel_type"], []).append(rel)

    assert "D3-ABPI" in {r["target_id"] for r in by_type.get("d3fend", [])}
    d3 = next(r for r in by_type["d3fend"] if r["target_id"] == "D3-ABPI")
    assert d3["relationship"] == "isolates"
    assert d3["name"] == "Application-based Process Isolation"
    assert "G0007" in {r["target_id"] for r in by_type.get("apt", [])}


def test_curated_cve_entity_path_enriched_from_shard(tmp_path: Path) -> None:
    # CVE present in entity_index with a bare D3FEND rel; the shard supplies
    # the detail. Lookup must keep source=entity_index.json AND gain kev_detail
    # plus the relationship verb on the existing defend rel.
    entities = {
        "CVE-2023-44487": {
            "type": "cve",
            "id": "CVE-2023-44487",
            "name": "HTTP/2 Rapid Reset",
            "phase": "vulnerability",
            "kev": True,
            "cvss_score": 7.5,
            "severity": "HIGH",
            "rels": {
                "defend": {"ids": ["D3-ABPI"], "source": "Pipeline (Technique->D3FEND)"},
                "technique": {"ids": ["T1499"], "source": "Pipeline"},
            },
        }
    }
    _write_indexes(tmp_path, entities)
    shards = _write_shard(tmp_path, "CVE-2023-44487", _RICH_PAYLOAD)
    ld = IndexLoader(tmp_path, shards_dir=shards)
    ld.load()

    resp = lookup_entity_impl(ld, "CVE-2023-44487")
    assert resp["ok"] is True
    assert resp["meta"]["source"] == "entity_index.json"
    assert resp["meta"]["enriched_from_shard"] is True

    data = resp["data"]
    assert data["kev_detail"]["dueDate"] == "2023-10-31"
    assert data["ssvc"]["ssvcExploitStatus"] == "active"
    defend_rel = next(r for r in data["rels"] if r["target_id"] == "D3-ABPI")
    assert defend_rel["relationship"] == "isolates"


def test_null_vulnrichment_and_no_kev_is_graceful(tmp_path: Path) -> None:
    payload = {
        "DESCRIPTION": "Minimal record.",
        "CVSS": {"score": 5.0, "vector": "CVSS:3.1/...", "severity": "MEDIUM", "version": "3.1"},
        "CWE": ["CWE-20"],
        "CAPEC": [],
        "TECHNIQUES": [],
        "OWASP": [],
        "DEFEND": [],
        "KEV": None,
        "VULNRICHMENT": None,
    }
    _write_indexes(tmp_path, {})
    shards = _write_shard(tmp_path, "CVE-2023-10001", payload)
    ld = IndexLoader(tmp_path, shards_dir=shards)
    ld.load()

    resp = lookup_entity_impl(ld, "CVE-2023-10001")
    assert resp["ok"] is True, resp
    data = resp["data"]
    assert "kev_detail" not in data
    assert "ssvc" not in data
    assert "cisa_cvss" not in data
    assert data["cvss_version"] == "3.1"
    assert "cvss_source" not in data  # absent in payload, must not be invented


def test_envelope_shape_unchanged(tmp_path: Path) -> None:
    _write_indexes(tmp_path, {})
    shards = _write_shard(tmp_path, "CVE-2023-44487", _RICH_PAYLOAD)
    ld = IndexLoader(tmp_path, shards_dir=shards)
    ld.load()

    resp = lookup_entity_impl(ld, "CVE-2023-44487")
    assert set(resp.keys()) == {"ok", "data", "meta"}
    assert resp["ok"] is True
    assert isinstance(resp["data"], dict)
    assert resp["data"]["type"] == "cve"
