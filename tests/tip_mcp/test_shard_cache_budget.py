"""The shard cache enforces a byte budget as well as a year count.

LRU years are evicted until the compressed cache is under budget, and a year
larger than the whole budget is served by a streaming scan without caching.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from tip_mcp import loader as loader_mod
from tip_mcp.loader import IndexLoader
from tip_mcp.tools import lookup_entity_impl


def _year(shards: Path, year: str, n: int) -> None:
    # Random descriptions keep compressed lines near their raw size.
    lines = [
        json.dumps({f"CVE-{year}-{1000 + i}": {"DESCRIPTION": os.urandom(200).hex()}})
        for i in range(n)
    ]
    (shards / f"CVE-{year}.jsonl").write_text("\n".join(lines) + "\n")


def _loader(tmp_path: Path, **kw) -> IndexLoader:
    data = tmp_path / "data"
    data.mkdir(parents=True)
    (data / "entity_index.json").write_text(json.dumps({"entities": {}}))
    (data / "search_index.json").write_text("{}")
    kw.setdefault("shards_dir", tmp_path / "db")
    ld = IndexLoader(data, **kw)
    ld.load()
    return ld


def test_default_budget_is_400_mb():
    assert loader_mod.DEFAULT_SHARD_CACHE_BYTES == 400 * 1024 * 1024
    assert IndexLoader("/nonexistent").shard_cache_bytes == 400 * 1024 * 1024


def test_lru_years_evicted_to_stay_under_budget(tmp_path):
    shards = tmp_path / "db"
    shards.mkdir()
    for year in ("2020", "2021", "2022"):
        _year(shards, year, 10)
    probe = _loader(tmp_path / "probe", shards_dir=shards)
    assert lookup_entity_impl(probe, "CVE-2020-1000")["ok"] is True
    one_year = probe.shard_cache_used_bytes
    budget = int(one_year * 2.5)  # room for two years, not three
    ld = _loader(tmp_path, shard_cache_bytes=budget, shard_cache_years=10)

    for year in ("2020", "2021", "2022"):
        assert lookup_entity_impl(ld, f"CVE-{year}-1000")["ok"] is True
        assert ld.shard_cache_used_bytes <= budget
    assert list(ld.cached_years) == ["2021", "2022"]  # 2020 evicted by bytes
    assert ld.shard_loads == 3
    assert lookup_entity_impl(ld, "CVE-2022-1005")["ok"] is True
    assert ld.shard_loads == 3  # still cached
    assert lookup_entity_impl(ld, "CVE-2020-1005")["ok"] is True
    assert ld.shard_loads == 4  # evicted year reread


def test_year_over_budget_is_streamed_not_cached(tmp_path):
    shards = tmp_path / "db"
    shards.mkdir()
    _year(shards, "2024", 50)  # about 12 KB compressed
    with (shards / "CVE-2024.jsonl").open("a") as f:
        f.write("not json\n")
    ld = _loader(tmp_path, shard_cache_bytes=5_000)

    resp = lookup_entity_impl(ld, "CVE-2024-1049")
    assert resp["ok"] is True
    assert resp["meta"]["shard"] == "CVE-2024.jsonl"
    assert list(ld.cached_years) == []
    assert ld.shard_cache_used_bytes == 0
    # The corrupt-line rule holds on the streaming path too.
    miss = lookup_entity_impl(ld, "CVE-2024-9999")
    assert miss["error"]["code"] == "data_corrupt"
    assert "CVE-2024.jsonl" in miss["error"]["message"]
    assert lookup_entity_impl(ld, "CVE-2024-1000")["ok"] is True
    assert list(ld.cached_years) == []
