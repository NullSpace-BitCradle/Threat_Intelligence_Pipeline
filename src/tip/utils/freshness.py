"""Per-source data freshness: docs/data/freshness.json.

The site reads this file to say how old its data is, and the daily canary
reads the deployed copy to notice runs that failed or never happened. It only
ever records successes: a source advances when its step in this run was
clean, and a failed, degraded or partial step leaves its entry untouched,
even inside a run where other sources succeeded.

Format (additive; readers ignore keys they do not know)::

    {"schema": 1,
     "sources": {"kev": {"label": "CISA KEV",
                         "last_success": "2026-09-26T06:04:11Z",
                         "cadence_hours": 24,
                         "stale_after_hours": 36}, ...}}
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from tip.utils.atomic_io import PathLike, atomic_write_text

SCHEMA_VERSION = 1

# Daily sources go stale after 36 hours, weekly ones after 8 days
# (MASTER_PLAN I16).
DAILY_HOURS = 24
WEEKLY_HOURS = 168
STALE_AFTER = {DAILY_HOURS: 36, WEEKLY_HOURS: 192}


@dataclass(frozen=True)
class Source:
    label: str
    cadence_hours: int

    @property
    def stale_after_hours(self) -> int:
        return STALE_AFTER[self.cadence_hours]


SOURCES: Dict[str, Source] = {
    "nvd": Source("NVD CVE shards", WEEKLY_HOURS),
    "entity_index": Source("Entity index", WEEKLY_HOURS),
    "kev": Source("CISA KEV", DAILY_HOURS),
    "vulnrichment": Source("CISA Vulnrichment", DAILY_HOURS),
    "epss": Source("EPSS", DAILY_HOURS),
    "cwe": Source("CWE", DAILY_HOURS),
    "capec": Source("CAPEC", DAILY_HOURS),
    "attack": Source("MITRE ATT&CK", DAILY_HOURS),
    "d3fend": Source("D3FEND", DAILY_HOURS),
    "ctid": Source("MITRE CTID KEV mappings", DAILY_HOURS),
}

# Source key -> reference database steps that must all have succeeded.
_DB_STEPS: Dict[str, tuple[str, ...]] = {
    "kev": ("kev",),
    "vulnrichment": ("vulnrichment",),
    "epss": ("epss",),
    "cwe": ("cwe",),
    "capec": ("capec",),
    "attack": ("techniques", "groups"),
    "d3fend": ("defend",),
    "ctid": ("ctid",),
}


def _status(results: Mapping[str, Any], step: str) -> Optional[str]:
    entry = results.get(step)
    if isinstance(entry, Mapping):
        status = entry.get("status")
        return status if isinstance(status, str) else None
    return None


def succeeded_sources(results: Mapping[str, Any]) -> List[str]:
    """Source keys whose steps were clean in this run's orchestrator results."""
    done: List[str] = []

    # A reference source advances only when every step behind it succeeded
    # AND wrote fresh data ("fresh" in the step). A success that kept the
    # existing file, or wrote degraded data, is not fresh.
    db = results.get("database_updates")
    db_results = db.get("results") if isinstance(db, Mapping) else None
    fresh_list = db.get("fresh") if isinstance(db, Mapping) else None
    fresh = set(fresh_list) if isinstance(fresh_list, list) else set()
    if isinstance(db_results, Mapping):
        for key, steps in _DB_STEPS.items():
            if all(db_results.get(step) is True and step in fresh for step in steps):
                done.append(key)
        # The curated EPSS file is republished after the entity index; a
        # failed republish means the published file is not this run's.
        if "epss" in done and _status(results, "epss_curated") == "failed":
            done.remove("epss")

    # NVD: retrieval clean, and processing clean or not needed (no new CVEs).
    if _status(results, "cve_retrieval") == "success" and _status(
        results, "cve_processing"
    ) in (None, "success"):
        done.append("nvd")

    if _status(results, "entity_index") == "success":
        done.append("entity_index")

    return [key for key in SOURCES if key in done]


def _existing_sources(path: Path) -> Dict[str, Any]:
    """The current file's sources, or {} when it is missing or malformed."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    sources = data.get("sources") if isinstance(data, dict) else None
    if not isinstance(sources, dict):
        return {}
    return {k: v for k, v in sources.items() if isinstance(v, dict)}


def _iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_freshness(
    results: Mapping[str, Any],
    path: PathLike,
    now: Optional[datetime] = None,
) -> List[str]:
    """Advance ``last_success`` for every source that succeeded in ``results``.

    Returns the advanced keys. When nothing advanced the file is not touched.
    The write is atomic; an existing malformed file is replaced.
    """
    advanced = succeeded_sources(results)
    if not advanced:
        return []
    target = Path(path)
    stamp = _iso(now or datetime.now(timezone.utc))
    sources = _existing_sources(target)
    for key in advanced:
        src = SOURCES[key]
        sources[key] = {
            "label": src.label,
            "last_success": stamp,
            "cadence_hours": src.cadence_hours,
            "stale_after_hours": src.stale_after_hours,
        }
    ordered = {k: sources[k] for k in SOURCES if k in sources}
    ordered.update({k: v for k, v in sources.items() if k not in SOURCES})
    doc = {"schema": SCHEMA_VERSION, "sources": ordered}
    atomic_write_text(target, json.dumps(doc, indent=2) + "\n")
    return advanced
