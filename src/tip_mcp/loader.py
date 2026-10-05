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


_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,19})$", re.IGNORECASE)

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


# Per-link fields a rel body's link_prov entry may carry besides source and
# tier (I21): CTID mapping_type and analyst comment, the inference rule; and
# the ATT&CK object citing a CVE for an APT group (I32): via, via_type,
# via_target.
LINK_EXTRA_FIELDS = ("mapping_type", "rule", "comment", "via", "via_type", "via_target")


def drop_overlap_apt_links(entities: dict) -> int:
    """Remove CVE to APT group rels, both directions, from an index written
    before I32. Those links came from technique overlap, not from any
    source's statement. Technique and campaign links to groups stay.
    Returns the number of rel bodies removed."""
    removed = 0
    for ent in entities.values():
        rels = ent.get("rels")
        if not isinstance(rels, dict):
            continue
        other = {"cve": "apt_group", "apt_group": "cve"}.get(ent.get("type"))
        if other is not None and other in rels:
            del rels[other]
            removed += 1
    return removed


def link_provenance(body: Any, target_id: Any) -> dict:
    """{source, tier, ...} of one link in a rel body.

    I21 indexes carry an additive ``link_prov`` map (id -> {source, tier,
    mapping_type | rule | comment}) for links whose provenance differs from
    the body's: CTID official and inferred technique links and the D3FEND
    defenses reached only through them. When such links change the body's
    own label (it describes all its links, weakest tier), the chain label
    for the other ids is kept in ``default_prov``. Every other link, and
    every link of an older index, takes the body's source and tier.
    """
    if not isinstance(body, dict):
        return {"source": None, "tier": None}
    per = body.get("link_prov")
    entry = per.get(str(target_id)) if isinstance(per, dict) else None
    if isinstance(entry, dict) and entry.get("tier") is not None:
        out = {"source": entry.get("source"), "tier": entry.get("tier")}
        for key in LINK_EXTRA_FIELDS:
            if entry.get(key) is not None:
                out[key] = entry[key]
        return out
    default = body.get("default_prov")
    if isinstance(default, dict) and default.get("tier") is not None:
        return {"source": default.get("source"), "tier": default.get("tier")}
    return {"source": body.get("source"), "tier": body.get("tier")}


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
        # Built lazily from the entity graph; see reverse_adjacency.
        self._reverse: Optional[dict[str, dict[str, list[tuple[str, str, Any, Any]]]]] = None
        # kev_db.json keyed by CVE ID; False means "tried and unavailable".
        self._kev_db: "Optional[dict[str, dict] | bool]" = None
        # kev_db.json keys whose entry is not an object; set when it loads.
        self.kev_malformed: list[str] = []
        # cwe_db.json RelatedAttackPatterns by bare CWE number; False means
        # "tried and unavailable".
        self._cwe_capecs: "Optional[dict[str, frozenset[str]] | bool]" = None
        # epss_curated.json as {"date", "scores"}; False means "tried and
        # unavailable".
        self._epss: "Optional[dict] | bool" = None
        # changes.json.gz as {"since", "window_days", "events"}; False means
        # "tried and unavailable", with the reason in _changes_error.
        self._changes: "Optional[dict] | bool" = None
        self._changes_error: Optional[str] = None
        # entity_index.json "meta" object ({} when absent).
        self._meta: dict = {}

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

        meta = data.get("meta")
        meta = meta if isinstance(meta, dict) else {}
        if meta.get("apt_attribution") is not True:
            drop_overlap_apt_links(entities)
        self._entities = entities
        self._meta = meta
        self._entities_ci = None
        self._search_index = search
        self._cve_ids = self._load_cve_ids()
        self._shard_cache.clear()
        self._cache_bytes = 0
        self._oversize_years.clear()
        self._reverse = None
        self._kev_db = None
        self._cwe_capecs = None
        self._epss = None
        self._changes = None
        self._changes_error = None

    @property
    def reverse_adjacency(self) -> dict[str, dict[str, list[tuple[str, str, Any, Any]]]]:
        """Incoming edges for every entity, built once from the graph.

        The entity index stores some edges in one direction only (a CAPEC
        names its techniques, a CWE names its CAPECs). This maps
        target_id -> source entity type -> [(source_id, rel_type, source,
        tier)] so a walk can follow those edges backwards. Order follows the
        index, so it is deterministic.
        """
        if self._reverse is None:
            rev: dict[str, dict[str, list[tuple[str, str, Any, Any]]]] = {}
            for eid, ent in self.entities.items():
                src_type = ent.get("type")
                if not isinstance(src_type, str):
                    continue
                for rel_type, body in (ent.get("rels") or {}).items():
                    if not isinstance(body, dict):
                        continue
                    for tid in body.get("ids", []) or []:
                        prov = link_provenance(body, tid)
                        rev.setdefault(str(tid), {}).setdefault(src_type, []).append(
                            (eid, rel_type, prov.get("source"), prov.get("tier"))
                        )
            self._reverse = rev
        return self._reverse

    @property
    def inherited_links(self) -> bool:
        """True when the index marks links reached only through an inherited
        parent CWE (I29): rel bodies carry an "inherited" id subset when any
        exist, and cwe -> capec bodies name the CAPECs not in the CWE's own
        RelatedAttackPatterns. Older indexes lack the marker."""
        return self._meta.get("inherited_links") is True

    @property
    def link_provenance(self) -> bool:
        """True when the index carries I21 per-link provenance (rel bodies
        may have link_prov). Tools add their I21 fields only then, so an
        older index gives exactly the output it gave before."""
        return self._meta.get("link_provenance") is True

    @property
    def kev_db(self) -> Optional[dict[str, dict]]:
        """CISA KEV catalog from kev_db.json, keyed by upper-case CVE ID.

        None when the file is absent or malformed; callers fall back to the
        entity graph and say so. Loaded once per load().
        """
        if self._kev_db is None:
            self._kev_db = False
            path = self.data_dir / "kev_db.json"
            if path.is_file():
                try:
                    data = _read_json(path, "kev_db.json")
                except IndexNotLoadedError:
                    data = None
                if isinstance(data, dict):
                    # A present entry that is not an object is kept as {} (listed,
                    # no details) and recorded, never silently dropped.
                    self._kev_db = {
                        str(k).strip().upper(): (v if isinstance(v, dict) else {})
                        for k, v in data.items()
                    }
                    self.kev_malformed = sorted(
                        str(k).strip().upper() for k, v in data.items() if not isinstance(v, dict)
                    )
        return self._kev_db if isinstance(self._kev_db, dict) else None

    @property
    def epss_curated(self) -> Optional[dict]:
        """The daily EPSS file for the curated tier (epss_curated.json) as
        {"date": score date, "model_version", "scores": {CVE ID upper:
        {score, percentile}}}. None when absent or malformed; callers then
        fall back to the weekly value on the entity record or shard. Loaded
        once per load()."""
        if self._epss is None:
            self._epss = False
            path = self.data_dir / "epss_curated.json"
            if path.is_file():
                try:
                    data = _read_json(path, "epss_curated.json")
                except IndexNotLoadedError:
                    data = None
                meta = data.get("meta") if isinstance(data, dict) else None
                scores = data.get("scores") if isinstance(data, dict) else None
                if isinstance(meta, dict) and isinstance(meta.get("date"), str) and isinstance(scores, dict):
                    self._epss = {
                        "date": meta["date"],
                        "model_version": meta.get("model_version"),
                        "scores": {
                            str(k).strip().upper(): v for k, v in scores.items() if isinstance(v, dict)
                        },
                    }
        return self._epss if isinstance(self._epss, dict) else None

    @property
    def changes(self) -> Optional[dict]:
        """The change event log (changes.json.gz, I8) as {"since",
        "window_days", "events"}, events newest first; malformed events are
        dropped. None when the file is absent or unreadable, with the reason
        in changes_error. Loaded once per load()."""
        if self._changes is None:
            self._changes = False
            path = self.data_dir / "changes.json.gz"
            if not path.is_file():
                self._changes_error = "changes.json.gz not found"
            else:
                try:
                    doc = json.loads(gzip.decompress(path.read_bytes()).decode("utf-8"))
                except _READ_ERRORS as exc:
                    doc = None
                    self._changes_error = f"changes.json.gz unreadable: {exc}"
                events = doc.get("events") if isinstance(doc, dict) else None
                if isinstance(events, list):
                    self._changes = {
                        "since": doc.get("since") if isinstance(doc.get("since"), str) else None,
                        "window_days": doc.get("window_days") if isinstance(doc.get("window_days"), int) else None,
                        "events": [e for e in events if _valid_event(e)],
                        "truncated": doc.get("truncated") if isinstance(doc.get("truncated"), int) else None,
                        "truncated_through": (
                            doc.get("truncated_through") if isinstance(doc.get("truncated_through"), str) else None
                        ),
                    }
                elif self._changes_error is None:
                    self._changes_error = "changes.json.gz has the wrong shape: expected an object with an 'events' list"
        return self._changes if isinstance(self._changes, dict) else None

    @property
    def changes_error(self) -> Optional[str]:
        return self._changes_error

    @property
    def cwe_related_capecs(self) -> Optional[dict[str, frozenset[str]]]:
        """Each CWE's own RelatedAttackPatterns from cwe_db.json (MITRE CWE),
        as bare CWE number -> bare CAPEC numbers.

        The entity graph's cwe -> capec edges also carry CAPECs inherited up
        the ChildOf chain; this is what tells the two apart. None when the
        file is absent or malformed. Loaded once per load().
        """
        if self._cwe_capecs is None:
            self._cwe_capecs = False
            path = self.data_dir / "cwe_db.json"
            if path.is_file():
                try:
                    data = _read_json(path, "cwe_db.json")
                except IndexNotLoadedError:
                    data = None
                if isinstance(data, dict):
                    self._cwe_capecs = {
                        str(k).strip(): frozenset(
                            str(c).strip() for c in (v.get("RelatedAttackPatterns") or [])
                        )
                        for k, v in data.items()
                        if isinstance(v, dict)
                    }
        return self._cwe_capecs if isinstance(self._cwe_capecs, dict) else None

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


def _valid_event(ev: Any) -> bool:
    return (
        isinstance(ev, dict)
        and all(isinstance(ev.get(k), str) for k in ("date", "type", "cve"))
        and (ev.get("related") is None or isinstance(ev.get("related"), dict))
    )


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
