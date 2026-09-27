"""
FIRST EPSS Processor

Downloads FIRST's daily EPSS bulk file (every scored CVE, gzipped CSV) and
turns it into per-CVE {score, percentile, date}. The full set is held in
memory for one run and never written under docs/: the daily run publishes
only docs/data/epss_curated.json (curated-tier CVEs from entity_index.json),
and the weekly run copies each CVE's score into its shard record.

Fail closed: a download error, a malformed header or row, or a row count
under half of the last good count (kept in the curated file's meta) raises,
and the previous curated file stays byte-identical.
"""
from __future__ import annotations

import gzip
import json
import re
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger, NetworkError, create_api_context
from tip.utils.atomic_io import write_reference_db

config = get_config()

DEFAULT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DEFAULT_FILE = "docs/data/epss_curated.json"
COLUMNS = "cve,epss,percentile"

_HEADER_RE = re.compile(
    r"^#model_version:(?P<model>[^,\s]+),score_date:(?P<date>\d{4}-\d{2}-\d{2}(?:T[0-9:.]+Z?)?)\s*$"
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class EPSSFormatError(ValueError):
    """The bulk file is not the shape FIRST publishes."""


@dataclass
class EPSSSnapshot:
    """One day's EPSS scores: CVE ID -> (score, percentile)."""

    model_version: str
    score_date: str
    scores: Dict[str, Tuple[float, float]] = field(default_factory=dict)

    @property
    def date(self) -> str:
        """Score date as YYYY-MM-DD; every published value carries it."""
        return self.score_date[:10]

    @property
    def row_count(self) -> int:
        return len(self.scores)

    def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        hit = self.scores.get(cve_id.strip().upper())
        if hit is None:
            return None
        return {"score": hit[0], "percentile": hit[1], "date": self.date}


def _probability(raw: str, what: str, line_no: int) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise EPSSFormatError(f"line {line_no}: {what} {raw!r} is not a number")
    if not 0.0 <= value <= 1.0:
        raise EPSSFormatError(f"line {line_no}: {what} {value} is outside [0, 1]")
    return value


def parse_bulk(content: bytes) -> EPSSSnapshot:
    """Parse the gzipped bulk CSV. Raises EPSSFormatError on any deviation."""
    try:
        text = gzip.decompress(content).decode("utf-8")
    except (OSError, EOFError, zlib.error, UnicodeDecodeError) as e:
        raise EPSSFormatError(f"EPSS bulk file is not gzipped UTF-8: {e}")

    lines = text.splitlines()
    if len(lines) < 2:
        raise EPSSFormatError("EPSS bulk file has no header")
    match = _HEADER_RE.match(lines[0].strip())
    if not match:
        raise EPSSFormatError(f"EPSS header line malformed: {lines[0][:120]!r}")
    score_date = match.group("date")
    try:
        datetime.strptime(score_date[:10], "%Y-%m-%d")
    except ValueError:
        raise EPSSFormatError(f"EPSS score_date {score_date!r} is not a date")
    if lines[1].strip() != COLUMNS:
        raise EPSSFormatError(f"EPSS column header is {lines[1][:80]!r}, expected {COLUMNS!r}")

    snap = EPSSSnapshot(model_version=match.group("model"), score_date=score_date)
    for line_no, line in enumerate(lines[2:], start=3):
        if not line.strip():
            continue
        parts = line.strip().split(",")
        if len(parts) != 3 or not _CVE_RE.match(parts[0]):
            raise EPSSFormatError(f"line {line_no}: malformed row {line[:80]!r}")
        snap.scores[parts[0]] = (
            _probability(parts[1], "epss", line_no),
            _probability(parts[2], "percentile", line_no),
        )
    if not snap.scores:
        raise EPSSFormatError("EPSS bulk file has no rows")
    return snap


def count_epss(data: Any) -> int:
    """Floor counter: the bulk row count recorded in the curated file's meta."""
    if isinstance(data, dict):
        meta = data.get("meta")
        if isinstance(meta, dict) and isinstance(meta.get("total_count"), int):
            return int(meta["total_count"])
    return 0


class EPSSProcessor:
    """Fetches the EPSS bulk file once per instance and publishes the curated tier."""

    def __init__(self) -> None:
        self.logger = get_logger('epss_processor')
        self.url: str = config.get('database.epss.url', DEFAULT_URL)
        self.db_path: str = config.get('database.epss.file', DEFAULT_FILE)
        self.snapshot: Optional[EPSSSnapshot] = None
        # A failed fetch is kept so a second caller in the same run gets the
        # same error instead of a second download.
        self.fetch_error: Optional[Exception] = None

    @property
    def entity_index_path(self) -> Path:
        return Path(self.db_path).parent / "entity_index.json"

    def fetch(self) -> EPSSSnapshot:
        """Download and parse the bulk file; later calls reuse the snapshot."""
        if self.snapshot is not None:
            return self.snapshot
        if self.fetch_error is not None:
            raise self.fetch_error
        try:
            self.snapshot = self._download()
        except Exception as e:
            self.fetch_error = e
            raise
        return self.snapshot

    def _download(self) -> EPSSSnapshot:
        context = create_api_context("download_epss", self.url)
        try:
            self.logger.info(f"Downloading EPSS bulk file from {self.url}")
            timeout = config.get('api.nvd.timeout', 60)
            response = requests.get(self.url, timeout=timeout)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Failed to download EPSS bulk file: {e}", url=self.url, context=context)
        snap = parse_bulk(response.content)
        self.logger.info(
            f"Parsed EPSS {snap.model_version} scored {snap.score_date}: {snap.row_count} CVEs"
        )
        return snap

    def build_curated(self, snap: EPSSSnapshot) -> Dict[str, Any]:
        """Scores for the curated CVE tier (entity_index.json cve entities)."""
        path = self.entity_index_path
        if not path.is_file():
            raise FileNotFoundError(f"{path} not found; cannot pick the curated EPSS tier")
        with open(path, "r", encoding="utf-8") as f:
            entities = json.load(f).get("entities", {})
        scores: Dict[str, Dict[str, float]] = {}
        for cve_id in sorted(k for k, v in entities.items() if isinstance(v, dict) and v.get("type") == "cve"):
            hit = snap.scores.get(cve_id)
            if hit is not None:
                scores[cve_id] = {"score": hit[0], "percentile": hit[1]}
        return {
            "meta": {
                "source": "FIRST EPSS",
                "model_version": snap.model_version,
                "score_date": snap.score_date,
                "date": snap.date,
                "total_count": snap.row_count,
                "curated_count": len(scores),
                "generated": datetime.now(timezone.utc).isoformat(),
            },
            "scores": scores,
        }

    def write_curated(self, snap: EPSSSnapshot) -> int:
        """Floor-check the row count against the last good file, then write atomically."""
        curated = self.build_curated(snap)
        write_reference_db(
            self.db_path, curated, counter=count_epss, indent=None, separators=(",", ":")
        )
        self.logger.info(
            f"Saved EPSS for {curated['meta']['curated_count']} curated CVEs to {self.db_path}"
        )
        return int(curated['meta']['curated_count'])

    def update(self) -> bool:
        """Fetch (once) and publish the curated file. False on any failure."""
        try:
            self.write_curated(self.fetch())
            return True
        except Exception as e:
            self.logger.error(f"Failed to update EPSS: {e}")
            return False
