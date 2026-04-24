"""Index loader for TIP MCP.

Reads the pre-built entity_index.json and search_index.json from TIP's
docs/data directory and holds them as in-memory dicts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


class IndexNotLoadedError(RuntimeError):
    """Raised when an index file is missing, malformed, or accessed before load()."""


class IndexLoader:
    """Loads and holds the TIP entity graph and search index in memory."""

    def __init__(self, data_dir: "Path | str") -> None:
        self.data_dir = Path(data_dir)
        self._entities: Optional[dict] = None
        self._search_index: Optional[dict] = None

    def load(self) -> None:
        """Load both indexes from disk."""
        entity_path = self.data_dir / "entity_index.json"
        search_path = self.data_dir / "search_index.json"

        if not entity_path.is_file():
            raise IndexNotLoadedError(f"entity_index.json not found at {entity_path}")
        if not search_path.is_file():
            raise IndexNotLoadedError(f"search_index.json not found at {search_path}")

        try:
            with entity_path.open() as f:
                data = json.load(f)
            self._entities = data.get("entities", {}) if isinstance(data, dict) else {}
        except json.JSONDecodeError as exc:
            raise IndexNotLoadedError(f"entity_index.json malformed: {exc}") from exc

        try:
            with search_path.open() as f:
                self._search_index = json.load(f)
        except json.JSONDecodeError as exc:
            raise IndexNotLoadedError(f"search_index.json malformed: {exc}") from exc

    @property
    def entities(self) -> dict:
        if self._entities is None:
            raise IndexNotLoadedError("load() not called yet")
        return self._entities

    @property
    def search_index(self) -> dict:
        if self._search_index is None:
            raise IndexNotLoadedError("load() not called yet")
        return self._search_index
