"""Pytest fixtures for tip_mcp tests."""

from pathlib import Path

import pytest

from tip_mcp.loader import IndexLoader


@pytest.fixture
def fixture_data_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_shards_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "database"


@pytest.fixture
def loader(fixture_data_dir: Path, fixture_shards_dir: Path) -> IndexLoader:
    ld = IndexLoader(fixture_data_dir, shards_dir=fixture_shards_dir)
    ld.load()
    return ld
