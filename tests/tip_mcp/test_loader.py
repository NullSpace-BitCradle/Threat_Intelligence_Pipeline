"""Tests for tip_mcp.loader."""

from pathlib import Path

import pytest

from tip_mcp.loader import IndexLoader, IndexNotLoadedError


def test_loader_loads_entities(loader):
    assert isinstance(loader.entities, dict)
    assert len(loader.entities) > 0


def test_loader_loads_search_index(loader):
    assert isinstance(loader.search_index, dict)
    assert len(loader.search_index) > 0


def test_loader_raises_before_load(tmp_path: Path):
    ld = IndexLoader(tmp_path)
    with pytest.raises(IndexNotLoadedError):
        _ = ld.entities


def test_loader_raises_on_missing_file(tmp_path: Path):
    ld = IndexLoader(tmp_path)
    with pytest.raises(IndexNotLoadedError):
        ld.load()


def test_loader_raises_on_malformed_json(tmp_path: Path):
    (tmp_path / "entity_index.json").write_text("{not valid json")
    (tmp_path / "search_index.json").write_text("{}")
    ld = IndexLoader(tmp_path)
    with pytest.raises(IndexNotLoadedError):
        ld.load()
