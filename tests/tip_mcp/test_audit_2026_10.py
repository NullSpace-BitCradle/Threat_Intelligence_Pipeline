"""MCP fixes from the 2026-10-29 audit: KEV answers come from the daily
catalog everywhere, IDs take ASCII digits only, and search splits a query
the way the index split names."""

from __future__ import annotations

import json

from tip_mcp.loader import IndexLoader
from tip_mcp.tools import (
    kev_status_impl,
    lookup_entity_impl,
    pivot_from_entity_impl,
    search_threat_intel_impl,
)

from .test_phase_b import _graph

CATALOG = {"CVE-2026-0001": {"inKEV": True, "dateAdded": "2026-10-28", "dueDate": "2026-11-11"}}


def _kev_graph(tmp_path):
    """CVE-2026-0001 was added to KEV after the weekly graph and shard were
    built; CVE-2026-0002 is kev=true in the graph but no longer listed."""
    ents = {
        "CWE-1": {"type": "cwe", "rels": {"cve": {"ids": ["CVE-2026-0001", "CVE-2026-0002"]}}},
        "CVE-2026-0001": {"type": "cve", "kev": False},
        "CVE-2026-0002": {"type": "cve", "kev": True, "kev_detail": {"dateAdded": "2020-01-01"}},
    }
    shard = {
        "CVE-2026-0003": {"DESCRIPTION": "x", "KEV": {"inKEV": False}},
        # The weekly shard still carries the dropped CVE's old KEV block.
        "CVE-2026-0002": {"DESCRIPTION": "y", "KEV": {"inKEV": True, "dateAdded": "2020-01-01"}},
    }
    catalog = {**CATALOG, "CVE-2026-0003": {"inKEV": True, "dateAdded": "2026-10-27"}}
    return _graph(tmp_path, ents, kev_db=catalog, shard=shard)


def test_lookup_takes_kev_from_catalog_not_the_weekly_graph(tmp_path):
    ld = _kev_graph(tmp_path)
    added = lookup_entity_impl(ld, "CVE-2026-0001")
    assert added["data"]["kev"] is True
    assert added["data"]["kev_detail"] == {"dateAdded": "2026-10-28", "dueDate": "2026-11-11"}
    assert added["meta"]["kev_source"] == "kev_db.json"
    dropped = lookup_entity_impl(ld, "CVE-2026-0002")
    assert dropped["data"]["kev"] is False and "kev_detail" not in dropped["data"]
    shard_only = lookup_entity_impl(ld, "CVE-2026-0003")
    assert shard_only["meta"]["source"] == "shard"
    assert shard_only["data"]["kev"] is True
    for cve in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"):
        assert lookup_entity_impl(ld, cve)["data"]["kev"] == kev_status_impl(ld, cve)["data"]["in_kev"]


def test_kev_filters_use_the_catalog(tmp_path):
    ld = _kev_graph(tmp_path)
    assert [h["id"] for h in pivot_from_entity_impl(ld, "CWE-1", "kev")["data"]] == ["CVE-2026-0001"]
    index = {"cve-2026-0001": ["CVE-2026-0001"], "cve-2026-0002": ["CVE-2026-0002"]}
    (tmp_path / "search_index.json").write_text(json.dumps(index))
    ld = IndexLoader(tmp_path, shards_dir=tmp_path / "database")
    ld.load()
    hits = search_threat_intel_impl(ld, "CVE-2026-0001 CVE-2026-0002", types=["kev"])["data"]
    assert [h["id"] for h in hits] == ["CVE-2026-0001"]


def test_non_ascii_digits_are_rejected_not_answered(loader):
    arabic = "CVE-2002-٠٣٦٧"  # 0367 in Arabic-Indic digits
    assert kev_status_impl(loader, arabic)["error"]["code"] == "bad_param"
    assert lookup_entity_impl(loader, arabic)["ok"] is False


def test_search_splits_punctuation_like_the_index(tmp_path):
    (tmp_path / "entity_index.json").write_text(json.dumps({"meta": {}, "entities": {
        "CVE-2023-44487": {"id": "CVE-2023-44487", "type": "cve", "name": "HTTP/2 Rapid Reset"},
        "T1059.001": {"id": "T1059.001", "type": "technique", "name": "PowerShell"},
    }}))
    (tmp_path / "search_index.json").write_text(json.dumps({
        "http": ["CVE-2023-44487"], "rapid": ["CVE-2023-44487"], "reset": ["CVE-2023-44487"],
        "t1059.001": ["T1059.001"],
    }))
    ld = IndexLoader(tmp_path, shards_dir=tmp_path)
    ld.load()
    for query in ("HTTP/2", "Rapid Reset.", "T1059.001"):
        assert search_threat_intel_impl(ld, query)["data"], query
    # A word the index holds whole is not split into weaker pieces.
    assert search_threat_intel_impl(ld, "T1059.001")["meta"]["query_tokens"] == ["t1059.001"]


def test_lookup_warns_on_a_malformed_catalog_entry_like_kev_status(tmp_path):
    ld = _graph(tmp_path, {"CVE-2026-0009": {"type": "cve", "kev": False}}, kev_db={"CVE-2026-0009": "listed"})
    resp = lookup_entity_impl(ld, "CVE-2026-0009")
    assert resp["data"]["kev"] is True
    assert resp["meta"]["warnings"] == kev_status_impl(ld, "CVE-2026-0009")["meta"]["warnings"]
