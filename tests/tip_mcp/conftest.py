"""Pytest fixtures for tip_mcp tests."""

from pathlib import Path

import pytest

from tip_mcp.loader import IndexLoader


@pytest.fixture
def fixture_data_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def loader(fixture_data_dir: Path) -> IndexLoader:
    ld = IndexLoader(fixture_data_dir)
    ld.load()
    return ld
