"""I1 ISC-10: lookup_entity and kev_status carry an epss block, null when unknown.

The daily epss_curated.json wins over the weekly value on the entity record
or shard. A missing or malformed daily file falls back without failing.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tip_mcp.loader import IndexLoader
from tip_mcp.tools import kev_status_impl, lookup_entity_impl

CURATED = "CVE-2022-23748"   # in the fixture entity graph, no shard year
SHARD_ONLY = "CVE-2024-31337"  # only in the 2024 fixture shard
WEEKLY = {"score": 0.2, "percentile": 0.9, "date": "2026-09-20"}


@pytest.fixture
def data_dir(tmp_path: Path, fixture_data_dir: Path) -> Path:
    out = tmp_path / "data"
    shutil.copytree(fixture_data_dir, out, ignore=shutil.ignore_patterns("database"))
    shutil.copytree(fixture_data_dir / "database", tmp_path / "database")
    return out


def _daily(data_dir: Path, scores: dict, date: str = "2026-09-26") -> None:
    (data_dir / "epss_curated.json").write_text(json.dumps({
        "meta": {"date": date, "model_version": "v2026.06.15", "total_count": 379842},
        "scores": scores,
    }))


def _weekly_on_entity(data_dir: Path, cve_id: str) -> None:
    path = data_dir / "entity_index.json"
    idx = json.loads(path.read_text())
    idx["entities"][cve_id]["epss"] = WEEKLY
    path.write_text(json.dumps(idx))


def _load(data_dir: Path) -> IndexLoader:
    ld = IndexLoader(data_dir, shards_dir=data_dir.parent / "database")
    ld.load()
    return ld


def test_legacy_data_reports_null(data_dir: Path) -> None:
    ld = _load(data_dir)
    for cid in (CURATED, SHARD_ONLY):
        resp = lookup_entity_impl(ld, cid)
        assert resp["ok"] is True
        assert "epss" in resp["data"] and resp["data"]["epss"] is None
        assert resp["meta"]["epss_source"] is None
    kev = kev_status_impl(ld, CURATED)
    assert kev["data"]["epss"] is None
    assert kev["meta"]["epss_source"] is None


def test_non_cve_entities_do_not_gain_epss(data_dir: Path) -> None:
    ld = _load(data_dir)
    tech = next(k for k, v in ld.entities.items() if v.get("type") == "technique")
    assert "epss" not in lookup_entity_impl(ld, tech)["data"]


def test_daily_file_serves_curated_cve(data_dir: Path) -> None:
    _daily(data_dir, {CURATED: {"score": 0.97, "percentile": 0.999}})
    ld = _load(data_dir)
    resp = lookup_entity_impl(ld, CURATED.lower())
    assert resp["data"]["epss"] == {"score": 0.97, "percentile": 0.999, "date": "2026-09-26"}
    assert resp["meta"]["epss_source"] == "epss_curated.json"
    kev = kev_status_impl(ld, CURATED)
    assert kev["data"]["epss"]["score"] == 0.97
    assert kev["meta"]["epss_source"] == "epss_curated.json"


def test_daily_file_wins_over_weekly_entity_value(data_dir: Path) -> None:
    _weekly_on_entity(data_dir, CURATED)
    _daily(data_dir, {CURATED: {"score": 0.97, "percentile": 0.999}})
    ld = _load(data_dir)
    assert lookup_entity_impl(ld, CURATED)["data"]["epss"]["date"] == "2026-09-26"


def test_weekly_entity_value_when_daily_lacks_the_cve(data_dir: Path) -> None:
    _weekly_on_entity(data_dir, CURATED)
    _daily(data_dir, {})
    ld = _load(data_dir)
    resp = lookup_entity_impl(ld, CURATED)
    assert resp["data"]["epss"] == WEEKLY
    assert resp["meta"]["epss_source"] == "entity_index.json"
    kev = kev_status_impl(ld, CURATED)
    assert kev["data"]["epss"] == WEEKLY
    assert kev["meta"]["epss_source"] == "entity_index.json"


def _shard_with_epss(data_dir: Path) -> None:
    import gzip

    shard = data_dir.parent / "database" / "CVE-2024.jsonl.gz"
    lines = [json.loads(l) for l in gzip.open(shard, "rt") if l.strip()]
    for rec in lines:
        if SHARD_ONLY in rec:
            rec[SHARD_ONLY]["EPSS"] = WEEKLY
    with gzip.open(shard, "wt") as f:
        for rec in lines:
            f.write(json.dumps(rec) + "\n")


def test_shard_value_for_shard_only_cve(data_dir: Path) -> None:
    _shard_with_epss(data_dir)
    ld = _load(data_dir)
    resp = lookup_entity_impl(ld, SHARD_ONLY)
    assert resp["meta"]["source"] == "shard"
    assert resp["data"]["epss"] == WEEKLY
    assert resp["meta"]["epss_source"] == "shard"
    kev = kev_status_impl(ld, SHARD_ONLY)
    assert kev["data"]["epss"] == WEEKLY
    assert kev["meta"]["epss_source"] == "shard"


@pytest.mark.parametrize("content", [
    "not json",
    json.dumps([1, 2]),
    json.dumps({"meta": {}, "scores": {}}),                     # no date
    json.dumps({"meta": {"date": "2026-09-26"}, "scores": []}),  # wrong scores shape
])
def test_malformed_daily_file_falls_back(data_dir: Path, content: str) -> None:
    _weekly_on_entity(data_dir, CURATED)
    (data_dir / "epss_curated.json").write_text(content)
    ld = _load(data_dir)
    assert ld.epss_curated is None
    resp = lookup_entity_impl(ld, CURATED)
    assert resp["ok"] is True
    assert resp["data"]["epss"] == WEEKLY


def test_malformed_daily_entry_is_ignored(data_dir: Path) -> None:
    _daily(data_dir, {CURATED: {"score": "high", "percentile": 0.5}})
    ld = _load(data_dir)
    assert lookup_entity_impl(ld, CURATED)["data"]["epss"] is None


def test_daily_file_loaded_once(data_dir: Path) -> None:
    _daily(data_dir, {CURATED: {"score": 0.97, "percentile": 0.999}})
    ld = _load(data_dir)
    first = ld.epss_curated
    (data_dir / "epss_curated.json").unlink()
    assert ld.epss_curated is first
