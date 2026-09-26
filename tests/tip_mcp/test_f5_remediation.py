"""F5 remediation tests (ISA ISC-32..37): type vocabulary, id normalization,
intel from the index, per-year shard cache plus miss short-circuit, and
envelopes for corrupt inputs."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from tip_mcp.loader import IndexLoader, IndexNotLoadedError
from tip_mcp.tools import (
    lookup_entity_impl,
    pivot_from_entity_impl,
    search_threat_intel_impl,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _data_dir(tmp_path: Path, entities: dict, search: object = None, cve_ids: object = None) -> Path:
    d = tmp_path / "data"
    d.mkdir(exist_ok=True)
    (d / "entity_index.json").write_text(json.dumps({"entities": entities}))
    (d / "search_index.json").write_text(json.dumps({} if search is None else search))
    if cve_ids is not None:
        (d / "cve_ids_index.json").write_text(json.dumps(cve_ids))
    return d


# ISC-32: graph names and legacy aliases


@pytest.mark.parametrize("name", ["defend", "d3fend", "D3FEND", " defend "])
def test_pivot_accepts_defend_and_alias(loader, name):
    resp = pivot_from_entity_impl(loader, "T1548", name)
    assert resp["ok"] is True, resp
    ids = {h["id"] for h in resp["data"]}
    assert ids == {
        "AccessModeling",
        "ApplicationExceptionMonitoring",
        "ConfigurationInventory",
        "ExecutableAllowlisting",
        "ExecutableDenylisting",
    }
    assert all(h["type"] == "defend" for h in resp["data"])


@pytest.mark.parametrize("name", ["apt_group", "apt"])
def test_pivot_accepts_apt_group_and_alias(loader, name):
    resp = pivot_from_entity_impl(loader, "T1053.005", name)
    assert resp["ok"] is True
    assert {h["id"] for h in resp["data"]} == {"G0016", "G0019", "G0021"}
    assert all(h["type"] == "apt_group" for h in resp["data"])


def test_pivot_kev_filter_returns_only_kev_cves(loader):
    resp = pivot_from_entity_impl(loader, "A09:2021", "kev")
    assert resp["ok"] is True
    assert {h["id"] for h in resp["data"]} == {"CVE-2018-13382", "CVE-2019-7192", "CVE-2021-30533"}


@pytest.mark.parametrize("types", [["apt_group"], ["apt"], ["APT"]])
def test_search_types_accept_graph_names_and_aliases(loader, types):
    resp = search_threat_intel_impl(loader, "g0016 g0019 g0021 privilege", types=types)
    assert resp["ok"] is True
    assert resp["data"], "expected apt_group hits"
    assert all(h["type"] == "apt_group" for h in resp["data"])


def test_search_rejects_unknown_type(loader):
    resp = search_threat_intel_impl(loader, "privilege", types=["bogus"])
    assert resp["ok"] is False
    assert resp["error"]["code"] == "invalid_type"


# ISC-33: shard path speaks the graph vocabulary


def test_shard_path_uses_graph_vocabulary(loader):
    graph_types = {"cve", "cwe", "capec", "technique", "defend", "apt_group", "owasp", "campaign"}
    lk = lookup_entity_impl(loader, "CVE-2024-99999")
    pv = pivot_from_entity_impl(loader, "CVE-2024-99999")
    assert lk["meta"]["source"] == pv["meta"]["source"] == "shard"
    rel_types = {r["rel_type"] for r in lk["data"]["rels"]}
    assert rel_types <= graph_types
    # Fixture stores CWE ["CWE-89", "564"] and TECHNIQUES ["1053.005"]; groups
    # come from the graph's technique overlap, like the generator.
    by_type: dict = {}
    for r in lk["data"]["rels"]:
        by_type.setdefault(r["rel_type"], set()).add(r["target_id"])
    assert by_type["cwe"] == {"CWE-89", "CWE-564"}
    assert by_type["technique"] == {"T1053.005"}
    assert by_type["apt_group"] == {"G0016", "G0019", "G0021"}
    assert {h["rel_type"] for h in pv["data"]} <= graph_types


def test_shard_pivot_defend_filter_via_alias(loader):
    for name in ("defend", "d3fend"):
        resp = pivot_from_entity_impl(loader, "CVE-2024-31337", name)
        assert resp["ok"] is True
        assert [h["id"] for h in resp["data"]] == ["D3-PSA"]
        assert resp["data"][0]["type"] == "defend"
        assert resp["data"][0]["name"] == "Process Spawn Analysis"


def test_entity_and_shard_paths_share_rel_vocabulary(loader):
    entity_types = {r["rel_type"] for r in lookup_entity_impl(loader, "CVE-2002-0367")["data"]["rels"]}
    shard_types = {r["rel_type"] for r in lookup_entity_impl(loader, "CVE-2024-31337")["data"]["rels"]}
    assert "defend" in entity_types and "defend" in shard_types


# ISC-34: id normalization


@pytest.mark.parametrize(
    "raw,expected",
    [
        (" cve-2002-0367 ", "CVE-2002-0367"),
        ("t1548", "T1548"),
        ("capec-233\n", "CAPEC-233"),
        (" cwe-269", "CWE-269"),
        ("g0016", "G0016"),
        ("a09:2021", "A09:2021"),
        ("accessmodeling", "AccessModeling"),
    ],
)
def test_ids_normalized_on_entity_path(loader, raw, expected):
    resp = lookup_entity_impl(loader, raw)
    assert resp["ok"] is True, resp
    assert resp["data"]["id"] == expected
    assert resp["meta"]["source"] == "entity_index.json"
    assert resp == lookup_entity_impl(loader, expected)


def test_ids_normalized_on_pivot(loader):
    assert pivot_from_entity_impl(loader, " t1548 ") == pivot_from_entity_impl(loader, "T1548")


def test_ids_normalized_on_shard_path(loader):
    resp = lookup_entity_impl(loader, "  cve-2024-31337\t")
    assert resp["ok"] is True
    assert resp["data"]["id"] == "CVE-2024-31337"
    assert resp == lookup_entity_impl(loader, "CVE-2024-31337")


# ISC-35: intel blocks served from entity_index.json


def test_entity_path_returns_intel_with_shards_absent(tmp_path):
    entity = {
        "type": "cve",
        "id": "CVE-2023-44487",
        "name": "HTTP/2 Rapid Reset",
        "phase": "vulnerability",
        "kev": True,
        "kev_detail": {"dateAdded": "2023-10-10", "dueDate": "2023-10-31"},
        "ssvc": {"ssvcExploitStatus": "active"},
        "cisa_cvss": {"baseScore": 7.5},
        "cvss_version": "3.1",
        "cvss_source": "nvd",
        "prov": {"source": "NVD", "tier": "authoritative"},
        "rels": {"defend": {"ids": ["D3-ABPI"], "source": "MITRE D3FEND", "tier": "derived"}},
    }
    d = _data_dir(tmp_path, {"CVE-2023-44487": entity})
    ld = IndexLoader(d, shards_dir=tmp_path / "missing-shards")
    ld.load()
    resp = lookup_entity_impl(ld, "CVE-2023-44487")
    assert resp["ok"] is True
    data = resp["data"]
    for field in ("kev_detail", "ssvc", "cisa_cvss", "cvss_version", "cvss_source"):
        assert data[field] == entity[field]
    assert data["prov"] == entity["prov"]
    assert data["rels"][0]["tier"] == "derived"
    assert "enriched_from_shard" not in resp["meta"]


# ISC-36: per-year cache and miss short-circuit


def test_year_shard_read_once(loader):
    assert loader.shard_loads == 0
    assert lookup_entity_impl(loader, "CVE-2024-31337")["ok"]
    assert lookup_entity_impl(loader, "CVE-2024-99999")["ok"]
    assert pivot_from_entity_impl(loader, "CVE-2024-31337")["ok"]
    assert loader.shard_loads == 1


def test_miss_short_circuits_without_reading_shard(loader):
    resp = lookup_entity_impl(loader, "CVE-2024-00001")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"
    assert "cve_ids_index" in resp["error"]["hint"]
    assert loader.shard_loads == 0


def test_miss_short_circuit_skips_corrupt_shard(tmp_path):
    # The year shard is corrupt, but the index says the CVE was never
    # ingested, so the shard is never opened: not_found, not data_corrupt.
    shards = tmp_path / "db"
    shards.mkdir()
    (shards / "CVE-2024.jsonl.gz").write_bytes(b"\x1f\x8b garbage")
    d = _data_dir(tmp_path, {}, cve_ids={"years": {"2024": [31337]}})
    ld = IndexLoader(d, shards_dir=shards)
    ld.load()
    resp = lookup_entity_impl(ld, "CVE-2024-00001")
    assert resp["error"]["code"] == "not_found"


def test_lru_bounds_cached_years(tmp_path):
    shards = tmp_path / "db"
    shards.mkdir()
    for year in ("2020", "2021", "2022"):
        (shards / f"CVE-{year}.jsonl").write_text(json.dumps({f"CVE-{year}-1000": {"CWE": ["79"]}}) + "\n")
    d = _data_dir(tmp_path, {})
    ld = IndexLoader(d, shards_dir=shards, shard_cache_years=2)
    ld.load()
    for year in ("2020", "2021", "2022", "2022"):
        assert lookup_entity_impl(ld, f"CVE-{year}-1000")["ok"]
    assert ld.shard_loads == 3
    assert lookup_entity_impl(ld, "CVE-2020-1000")["ok"]  # evicted, reread
    assert ld.shard_loads == 4


def test_malformed_cve_ids_index_falls_back_to_scan(tmp_path):
    shards = tmp_path / "db"
    shards.mkdir()
    (shards / "CVE-2021.jsonl").write_text(json.dumps({"CVE-2021-1000": {"CWE": ["79"]}}) + "\n")
    d = _data_dir(tmp_path, {}, cve_ids=["not", "a", "dict"])
    ld = IndexLoader(d, shards_dir=shards)
    ld.load()
    assert lookup_entity_impl(ld, "CVE-2021-1000")["ok"] is True


# ISC-37: corrupt inputs give envelopes, never exceptions


def _truncated_gzip(path: Path) -> None:
    raw = gzip.compress((json.dumps({"CVE-2024-31337": {"CWE": ["79"]}}) + "\n").encode() * 200)
    path.write_bytes(raw[: len(raw) // 2])


def _bad_utf8_gzip(path: Path) -> None:
    path.write_bytes(gzip.compress(b'{"CVE-2024-31337": {"DESCRIPTION": "\xff\xfe bad"}}\n'))


@pytest.mark.parametrize("corrupt", [_truncated_gzip, _bad_utf8_gzip])
def test_corrupt_shard_returns_data_corrupt_envelope(tmp_path, corrupt):
    shards = tmp_path / "db"
    shards.mkdir()
    corrupt(shards / "CVE-2024.jsonl.gz")
    ld = IndexLoader(_data_dir(tmp_path, {}), shards_dir=shards)
    ld.load()
    for fn in (lookup_entity_impl, pivot_from_entity_impl):
        resp = fn(ld, "CVE-2024-31337")
        assert resp["ok"] is False
        assert resp["error"]["code"] == "data_corrupt"
        assert "CVE-2024.jsonl.gz" in resp["error"]["message"]


def test_corrupt_shard_does_not_break_entity_path(tmp_path):
    shards = tmp_path / "db"
    shards.mkdir()
    _truncated_gzip(shards / "CVE-2024.jsonl.gz")
    entity = {"type": "cve", "id": "CVE-2024-31337", "name": "x", "phase": "vulnerability", "rels": {}}
    ld = IndexLoader(_data_dir(tmp_path, {"CVE-2024-31337": entity}), shards_dir=shards)
    ld.load()
    resp = lookup_entity_impl(ld, "CVE-2024-31337")
    assert resp["ok"] is True
    assert "CVE-2024.jsonl.gz" in resp["meta"]["shard_error"]


def _write(d: Path, name: str, content: bytes) -> None:
    (d / name).write_bytes(content)


@pytest.mark.parametrize(
    "entity_bytes,search_bytes",
    [
        (b"[]", b"{}"),  # list-shaped entity index
        (b'{"entities": []}', b"{}"),  # entities not an object
        (b'{"entities": {"X": 1}}', b"{}"),  # entity not an object
        (b'{"entities": {}}', b"[]"),  # list-shaped search index
        (b'{"entities": {}}', b'{"term": "CVE-1"}'),  # search values not lists
        (b'{"entities": {}}', b'{"a": ["\xff"]}'),  # bad UTF-8
        (gzip.compress(b"{}")[:5], b"{}"),  # binary garbage
        (b'{"entities": {', b"{}"),  # truncated JSON
    ],
)
def test_wrong_shaped_or_corrupt_index_returns_envelope(tmp_path, entity_bytes, search_bytes):
    _write(tmp_path, "entity_index.json", entity_bytes)
    _write(tmp_path, "search_index.json", search_bytes)
    ld = IndexLoader(tmp_path, shards_dir=tmp_path / "db")
    with pytest.raises(IndexNotLoadedError):
        ld.load()
    for resp in (
        lookup_entity_impl(ld, "CVE-2024-31337"),
        pivot_from_entity_impl(ld, "T1548"),
        search_threat_intel_impl(ld, "privilege"),
    ):
        assert resp["ok"] is False
        assert resp["error"]["code"] == "index_not_loaded"


def test_missing_index_returns_envelope(tmp_path):
    ld = IndexLoader(tmp_path)
    resp = lookup_entity_impl(ld, "T1548")
    assert resp["error"]["code"] == "index_not_loaded"
    assert "not found" in resp["error"]["message"]


def test_unloaded_loader_loads_lazily(fixture_data_dir, fixture_shards_dir):
    ld = IndexLoader(fixture_data_dir, shards_dir=fixture_shards_dir)
    resp = lookup_entity_impl(ld, "T1548")
    assert resp["ok"] is True
