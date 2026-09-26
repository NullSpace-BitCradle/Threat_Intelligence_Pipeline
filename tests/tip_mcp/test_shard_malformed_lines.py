"""Malformed JSONL lines in a shard surface as data_corrupt, never not_found.

A line whose key cannot be parsed marks the shard corrupt. A CVE not
otherwise found in a corrupt shard returns data_corrupt naming the file, and
a malformed line that decodes to the requested CVE returns data_corrupt too.
A good line in the same shard is still served.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tip_mcp.loader import IndexLoader
from tip_mcp.tools import lookup_entity_impl, pivot_from_entity_impl

GOOD = json.dumps({"CVE-2024-1000": {"CWE": ["CWE-79"], "DESCRIPTION": "ok"}})


def _loader(tmp_path: Path, lines: list[str]) -> IndexLoader:
    data = tmp_path / "data"
    data.mkdir()
    (data / "entity_index.json").write_text(json.dumps({"entities": {}}))
    (data / "search_index.json").write_text("{}")
    shards = tmp_path / "db"
    shards.mkdir()
    (shards / "CVE-2024.jsonl").write_text("\n".join(lines) + "\n")
    ld = IndexLoader(data, shards_dir=shards)
    ld.load()
    return ld


def _assert_corrupt(resp: dict) -> None:
    assert resp["ok"] is False, resp
    assert resp["error"]["code"] == "data_corrupt"
    assert "CVE-2024.jsonl" in resp["error"]["message"]


@pytest.mark.parametrize("fn", [lookup_entity_impl, pivot_from_entity_impl])
def test_miss_in_shard_with_unparseable_line_is_data_corrupt(tmp_path, fn):
    ld = _loader(tmp_path, [GOOD, "this is not json", "[1, 2, 3]"])
    _assert_corrupt(fn(ld, "CVE-2024-2000"))
    assert "2 malformed" in fn(ld, "CVE-2024-2000")["error"]["message"]


@pytest.mark.parametrize("fn", [lookup_entity_impl, pivot_from_entity_impl])
def test_good_line_in_corrupt_shard_is_still_served(tmp_path, fn):
    ld = _loader(tmp_path, [GOOD, "this is not json"])
    assert fn(ld, "CVE-2024-1000")["ok"] is True


@pytest.mark.parametrize("bad", [
    '{"CVE-2024-3000": {"CWE": ["CWE-79"], "DESC',   # key parses, payload does not
    '{"CVE-2024-3000": "not an object"}',
])
@pytest.mark.parametrize("fn", [lookup_entity_impl, pivot_from_entity_impl])
def test_malformed_line_for_requested_cve_is_data_corrupt(tmp_path, fn, bad):
    ld = _loader(tmp_path, [GOOD, bad])
    resp = fn(ld, "CVE-2024-3000")
    _assert_corrupt(resp)
    assert "CVE-2024-3000" in resp["error"]["message"]


def test_clean_shard_miss_is_still_not_found(tmp_path):
    ld = _loader(tmp_path, [GOOD])
    resp = lookup_entity_impl(ld, "CVE-2024-2000")
    assert resp["error"]["code"] == "not_found"
