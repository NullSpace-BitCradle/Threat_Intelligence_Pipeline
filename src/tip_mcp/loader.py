"""Index loader for TIP MCP.

Reads the pre-built entity_index.json and search_index.json from TIP's
docs/data directory and holds them as in-memory dicts. Also exposes
on-demand lookup into the per-year CVE JSONL shards so callers can find
any CVE by ID even when it is not in the enriched entity graph.
"""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path
from typing import Optional


class IndexNotLoadedError(RuntimeError):
    """Raised when an index file is missing, malformed, or accessed before load()."""


_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$", re.IGNORECASE)


class IndexLoader:
    """Loads and holds the TIP entity graph and search index in memory."""

    def __init__(
        self,
        data_dir: "Path | str",
        shards_dir: "Path | str | None" = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        # Shards live alongside the data dir by default (docs/database/
        # sibling to docs/data/). Tests can override with a fixture path.
        if shards_dir is not None:
            self.shards_dir: Path = Path(shards_dir)
        else:
            self.shards_dir = self.data_dir.parent / "database"
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

    def find_cve_in_shards(self, cve_id: str) -> Optional[tuple[dict, str]]:
        """Scan the per-year JSONL shard for a CVE ID.

        Returns (record, shard_filename) if found, None otherwise. Accepts
        CVE IDs case-insensitively; returned record uses the CVE ID as stored
        in the shard. Silently returns None if the shards directory is
        absent, the year's shard is absent, or the CVE ID is malformed.
        """
        match = _CVE_ID_RE.match(cve_id.strip())
        if not match:
            return None
        year = match.group(1)
        canonical_id = cve_id.upper()

        gz_path = self.shards_dir / f"CVE-{year}.jsonl.gz"
        plain_path = self.shards_dir / f"CVE-{year}.jsonl"

        if gz_path.is_file():
            shard_path = gz_path
            opener = gzip.open
        elif plain_path.is_file():
            shard_path = plain_path
            opener = open
        else:
            return None

        try:
            with opener(shard_path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # Shards store one CVE per line, keyed by CVE ID.
                    for key, payload in record.items():
                        if key.upper() == canonical_id:
                            return payload, shard_path.name
        except OSError:
            return None
        return None
