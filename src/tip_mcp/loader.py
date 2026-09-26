"""Index loader for TIP MCP.

Reads the pre-built entity_index.json and search_index.json from TIP's
docs/data directory and holds them as in-memory dicts. Also exposes
on-demand lookup into the per-year CVE JSONL shards so callers can find
any CVE by ID even when it is not in the enriched entity graph.

Shard lookups are cached per year. A year shard is streamed once and each
line is held zlib-compressed, keyed by CVE ID, so later lookups in that year
cost one small decompress plus one json.loads. Parsing a whole year into
dicts would need over 1 GB for CVE-2026 (303 MB of decompressed JSONL); the
compressed line cache holds that year in about 100 MB. An LRU over years
bounds the total by year count and by compressed bytes (400 MB default); a
year larger than the byte budget is streamed per lookup instead of cached. A miss is short-circuited through cve_ids_index.json, so a
CVE ID the pipeline never ingested costs no shard scan at all.
"""

from __future__ import annotations

import bisect
import gzip
import json
import re
import zlib
from collections import OrderedDict
from pathlib import Path
from typing import IO, Any, Optional


class IndexNotLoadedError(RuntimeError):
    """Raised when an index file is missing, malformed, or accessed before load()."""


class ShardReadError(RuntimeError):
    """Raised when a CVE year shard exists but cannot be read (truncated gzip,
    bad UTF-8, zlib corruption). The message names the file."""


_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)

# Errors a corrupt JSON or gzip file can raise while being read.
_READ_ERRORS = (OSError, EOFError, UnicodeDecodeError, zlib.error, ValueError)

DEFAULT_SHARD_CACHE_YEARS = 3
# Budget for the compressed shard cache across all cached years.
DEFAULT_SHARD_CACHE_BYTES = 400 * 1024 * 1024


def _read_json(path: Path, label: str) -> Any:
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise IndexNotLoadedError(f"{label} malformed: {exc}") from exc
    except _READ_ERRORS as exc:
        raise IndexNotLoadedError(f"{label} unreadable: {exc}") from exc


class IndexLoader:
    """Loads and holds the TIP entity graph and search index in memory."""

    def __init__(
        self,
        data_dir: "Path | str",
        shards_dir: "Path | str | None" = None,
        shard_cache_years: int = DEFAULT_SHARD_CACHE_YEARS,
        shard_cache_bytes: int = DEFAULT_SHARD_CACHE_BYTES,
    ) -> None:
        self.data_dir = Path(data_dir)
        # Shards live alongside the data dir by default (docs/database/
        # sibling to docs/data/). Tests can override with a fixture path.
        if shards_dir is not None:
            self.shards_dir: Path = Path(shards_dir)
        else:
            self.shards_dir = self.data_dir.parent / "database"
        self.shard_cache_years = max(1, int(shard_cache_years))
        self._entities: Optional[dict] = None
        self._entities_ci: Optional[dict[str, str]] = None
        self._search_index: Optional[dict] = None
        # year -> sorted CVE tail ints, from cve_ids_index.json. None when the
        # index is absent or malformed; lookups then fall back to scanning.
        self._cve_ids: Optional[dict[str, list[int]]] = None
        self.shard_cache_bytes = max(1, int(shard_cache_bytes))
        # year -> (shard filename, {CVE-ID upper: zlib-compressed line},
        # malformed line count, compressed bytes); LRU order.
        self._shard_cache: "OrderedDict[str, tuple[str, dict[str, bytes], int, int]]" = OrderedDict()
        self._cache_bytes = 0
        # Years whose compressed lines exceed the whole byte budget; they are
        # streamed on every lookup instead of cached.
        self._oversize_years: set[str] = set()
        # Number of shard files read from disk; tests use it to prove caching
        # and the miss short-circuit.
        self.shard_loads = 0

    @property
    def loaded(self) -> bool:
        return self._entities is not None and self._search_index is not None

    def load(self) -> None:
        """Load both indexes from disk (and cve_ids_index.json if present).

        Raises IndexNotLoadedError for a missing, unreadable, or wrong-shaped
        entity or search index. Never leaves a half-loaded state.
        """
        entity_path = self.data_dir / "entity_index.json"
        search_path = self.data_dir / "search_index.json"

        if not entity_path.is_file():
            raise IndexNotLoadedError(f"entity_index.json not found at {entity_path}")
        if not search_path.is_file():
            raise IndexNotLoadedError(f"search_index.json not found at {search_path}")

        data = _read_json(entity_path, "entity_index.json")
        if not isinstance(data, dict) or not isinstance(data.get("entities"), dict):
            raise IndexNotLoadedError(
                "entity_index.json has the wrong shape: expected an object with an 'entities' object"
            )
        entities = data["entities"]
        if not all(isinstance(v, dict) for v in entities.values()):
            raise IndexNotLoadedError(
                "entity_index.json has the wrong shape: every entity must be an object"
            )

        search = _read_json(search_path, "search_index.json")
        if not isinstance(search, dict) or not all(isinstance(v, list) for v in search.values()):
            raise IndexNotLoadedError(
                "search_index.json has the wrong shape: expected an object of term to id list"
            )

        self._entities = entities
        self._entities_ci = None
        self._search_index = search
        self._cve_ids = self._load_cve_ids()
        self._shard_cache.clear()
        self._cache_bytes = 0
        self._oversize_years.clear()

    def _load_cve_ids(self) -> Optional[dict[str, list[int]]]:
        """Load the Layer 1 all-IDs index. Absent or malformed means None,
        which disables the miss short-circuit rather than failing."""
        path = self.data_dir / "cve_ids_index.json"
        if not path.is_file():
            return None
        try:
            data = _read_json(path, "cve_ids_index.json")
        except IndexNotLoadedError:
            return None
        years = data.get("years") if isinstance(data, dict) else None
        if not isinstance(years, dict):
            return None
        out: dict[str, list[int]] = {}
        for year, tails in years.items():
            if not isinstance(tails, list) or not all(isinstance(t, int) for t in tails):
                return None
            # The generator writes sorted lists; sorting again is cheap and
            # keeps bisect correct if that ever changes.
            out[str(year)] = sorted(tails)
        return out

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

    def resolve_entity_key(self, entity_id: str) -> Optional[str]:
        """Return the entity-graph key for entity_id: exact match first, then
        a case-insensitive match. None when the graph has no such entity."""
        entities = self.entities
        if entity_id in entities:
            return entity_id
        if self._entities_ci is None:
            self._entities_ci = {k.lower(): k for k in entities}
        return self._entities_ci.get(entity_id.lower())

    def cve_known(self, cve_id: str) -> Optional[bool]:
        """Whether cve_ids_index.json lists this CVE ID. None when the index
        is unavailable (the caller must then scan)."""
        if self._cve_ids is None:
            return None
        match = _CVE_ID_RE.match(cve_id.strip())
        if not match:
            return False
        tails = self._cve_ids.get(match.group(1))
        if not tails:
            return False
        tail = int(match.group(2))
        i = bisect.bisect_left(tails, tail)
        return i < len(tails) and tails[i] == tail

    def _shard_path(self, year: str) -> Optional[Path]:
        gz_path = self.shards_dir / f"CVE-{year}.jsonl.gz"
        plain_path = self.shards_dir / f"CVE-{year}.jsonl"
        if gz_path.is_file():
            return gz_path
        if plain_path.is_file():
            return plain_path
        return None

    @property
    def cached_years(self) -> list[str]:
        """Years currently held in the shard cache, least recently used first."""
        return list(self._shard_cache)

    @property
    def shard_cache_used_bytes(self) -> int:
        """Compressed bytes the shard cache holds now."""
        return self._cache_bytes

    def _year_lookup(self, year: str, canonical_id: str) -> Optional[tuple[str, Optional[bytes], int]]:
        """Return (shard filename, compressed line for canonical_id or None,
        malformed line count) for a year. None if the shard is absent.

        The first read of a year caches every line zlib-compressed, keyed by
        CVE ID. The cache is bounded by shard_cache_years and by
        shard_cache_bytes: least recently used years are evicted until both
        hold. A year whose compressed lines alone exceed the byte budget is
        not cached; it is streamed on every lookup, keeping only the line
        asked for. A line whose key cannot be parsed is counted as malformed
        rather than skipped silently. Raises ShardReadError if the shard
        exists but cannot be read; a partially read year is never cached.
        """
        cached = self._shard_cache.get(year)
        if cached is not None:
            self._shard_cache.move_to_end(year)
            return cached[0], cached[1].get(canonical_id), cached[2]
        shard_path = self._shard_path(year)
        if shard_path is None:
            return None

        caching = year not in self._oversize_years
        lines: dict[str, bytes] = {}
        size = 0
        hit: Optional[bytes] = None
        corrupt = 0
        try:
            fh: IO[str]
            if shard_path.suffix == ".gz":
                fh = gzip.open(shard_path, "rt", encoding="utf-8")
            else:
                fh = shard_path.open("r", encoding="utf-8")
            with fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    keys = [k.upper() for k in _line_keys(line)]
                    if not keys:
                        corrupt += 1
                        continue
                    if caching:
                        blob = zlib.compress(line.encode("utf-8"), 1)
                        for key in keys:
                            lines[key] = blob
                        size += len(blob)
                        if size > self.shard_cache_bytes:
                            # Too big for the whole budget: stop caching and
                            # keep scanning for the one line asked for.
                            caching = False
                            self._oversize_years.add(year)
                            hit = lines.get(canonical_id)
                            lines = {}
                    elif canonical_id in keys:
                        hit = zlib.compress(line.encode("utf-8"), 1)
        except _READ_ERRORS as exc:
            raise ShardReadError(
                f"shard {shard_path.name} unreadable: {type(exc).__name__}: {exc}"
            ) from exc

        self.shard_loads += 1
        if not caching:
            return shard_path.name, hit, corrupt

        self._shard_cache[year] = (shard_path.name, lines, corrupt, size)
        self._cache_bytes += size
        while len(self._shard_cache) > 1 and (
            len(self._shard_cache) > self.shard_cache_years
            or self._cache_bytes > self.shard_cache_bytes
        ):
            _, (_, _, _, evicted) = self._shard_cache.popitem(last=False)
            self._cache_bytes -= evicted
        return shard_path.name, lines.get(canonical_id), corrupt

    def find_cve_in_shards(self, cve_id: str) -> Optional[tuple[dict, str]]:
        """Look up a CVE ID in its per-year JSONL shard.

        Returns (record, shard_filename) if found, None otherwise. Accepts
        CVE IDs case-insensitively and with surrounding whitespace. Returns
        None without touching the shard when cve_ids_index.json says the ID
        was never ingested, when the shards directory or the year's shard is
        absent, or when the ID is malformed. Raises ShardReadError when the
        shard exists but cannot be read, when the requested CVE's line is
        malformed, or when the CVE is not found and the shard has malformed
        lines (it may be on one of them).
        """
        match = _CVE_ID_RE.match(cve_id.strip())
        if not match:
            return None
        if self.cve_known(cve_id) is False:
            return None
        year = match.group(1)
        canonical_id = cve_id.strip().upper()

        found = self._year_lookup(year, canonical_id)
        if found is None:
            return None
        shard_name, blob, corrupt = found
        if blob is None:
            if corrupt:
                # The CVE may be on one of the unparseable lines, so "not
                # found" would be a guess. Report the shard as corrupt.
                raise ShardReadError(
                    f"shard {shard_name} has {corrupt} malformed line(s); "
                    f"{canonical_id} not found among the readable lines"
                )
            return None
        return _parse_hit(blob, canonical_id, shard_name), shard_name


def _parse_hit(blob: bytes, canonical_id: str, shard_name: str) -> dict:
    """Decode the shard line keyed by canonical_id. A line that is keyed by
    the CVE but does not decode to an object payload raises ShardReadError."""
    try:
        record = json.loads(zlib.decompress(blob))
    except (json.JSONDecodeError, zlib.error) as exc:
        raise ShardReadError(
            f"shard {shard_name}: record for {canonical_id} is malformed: {exc}"
        ) from exc
    if isinstance(record, dict):
        for key, payload in record.items():
            if key.upper() == canonical_id and isinstance(payload, dict):
                return payload
    raise ShardReadError(
        f"shard {shard_name}: record for {canonical_id} is not a JSON object"
    )


def _line_keys(line: str) -> list[str]:
    """CVE IDs a shard line is keyed by. Shards store one CVE per line as
    {"CVE-...": {...}}; read the key from the prefix without parsing the
    (often multi-KB) payload, falling back to a full parse. A malformed line
    yields no keys; the caller counts it and marks the shard corrupt."""
    if line.startswith('{"'):
        end = line.find('"', 2)
        if end > 2 and line[end + 1 : end + 2] == ":":
            key = line[2:end]
            if _CVE_ID_RE.match(key):
                return [key]
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return []
    if not isinstance(record, dict):
        return []
    return [k for k in record if isinstance(k, str)]
