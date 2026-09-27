"""Change events (I8): docs/data/changes.json.gz.

Each data run compares the state it is about to replace with the state it
wrote, and records what changed as dated events. The data files are replaced
in place, so the previous published state is snapshotted in process before
any step runs (the workflows sync to main first, so the working tree is the
latest published state). Nothing here reads git history or the network.

Rules the log keeps:

* Only observed facts. A source with no before-state (first run, missing or
  unreadable file) or no after-state yields zero events, never a flood of
  "added" events.
* Only successful steps. The orchestrator passes the sources whose step
  succeeded and wrote fresh data; every other source adds nothing.
* Bounded. Events older than ``WINDOW_DAYS`` are pruned on every write, then
  at most ``MAX_EVENTS`` are kept, newest first. When the cap drops events,
  meta ``truncated`` counts the dropped events still inside the window and
  ``truncated_through`` is the newest date among them, so a reader knows the
  log is incomplete on and before that date. Both keys are absent otherwise.
* Deterministic and atomic. Sorted keys, compact JSON, fixed gzip header, one
  atomic replace; identical content gives identical bytes and no git change.

Format (additive; readers ignore keys they do not know)::

    {"schema": 1, "window_days": 30, "since": "2026-09-28",
     "truncated": 12, "truncated_through": "2026-09-02",
     "events": [{"date": "2026-09-28", "type": "kev_added",
                 "cve": "CVE-2026-1234", "before": null,
                 "after": {"date_added": "...", "due_date": "...", "ransomware": "..."},
                 "related": {"vendor": "Ivanti", "product": "Connect Secure",
                             "cwe": ["CWE-22"], "technique": ["T1190"],
                             "apt_group": ["G0001"]}}, ...]}
"""
from __future__ import annotations

import gzip
import json
import zlib
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from tip.utils.atomic_io import PathLike, atomic_write_bytes, deterministic_gzip
from tip.utils.error_handler import log_warning

SCHEMA_VERSION = 1
WINDOW_DAYS = 30

# Backstops on the log's size, applied after the window prune. The count cap
# keeps the newest events (within a day, KEV and SSVC outrank curated churn);
# the byte cap then drops whole days, oldest first, while the gzipped file is
# over MAX_BYTES. The stacked worst-case probe stays under both without
# truncation; they exist for cases the probe did not foresee.
MAX_EVENTS = 6500
MAX_BYTES = 150_000

# EPSS: a move of at least this much, or a crossing of EPSS_LINE, is a jump.
EPSS_JUMP = 0.1
EPSS_LINE = 0.5

# SSVC exploitation values that make a first-seen decision worth an event.
# A first "none" or "poc" is the daily norm for newly enriched CVEs (about 48
# first poc or active decisions a day), so only a first "active" is news.
# Changes between values, poc to active included, are always events.
SSVC_NOTABLE = ("active",)

EVENT_TYPES = (
    "kev_added",
    "kev_removed",
    "ssvc_exploitation_changed",
    "epss_jump",
    "cvss_changed",
    "curated_added",
    "curated_removed",
)

# "Added" events (kev_added, a first SSVC decision, curated_added) need a
# before-state that was a full baseline. One under this fraction of the
# after-state, and short of it by more than BASELINE_SLACK records, was
# partial (a wiped or half-built file, then a full rebuild), so its missing
# records cannot be told from backfill and add no events. The slack lets a
# small set grow by a normal week's worth (the curated tier from 1,728 to
# 1,950). It stays small so that a set recovering from a shrink the removal
# guard suppressed (a bad KEV feed at 1,300 of 1,726, then a good one) does
# not log the recovery as news; only a shrink of 10 to 14% can still do so.
# Symmetrically, an after-state under the fraction of the before-state
# emits no removal events (kev_removed, curated_removed): a set that shrank
# that far is more likely a bad build than news. Changes on records present
# in both states are always observed facts.
BASELINE_RATIO = 0.9
BASELINE_SLACK = 250

# Event sources, keyed as the orchestrator names the steps behind them.
SOURCES = ("kev", "vulnrichment", "epss", "entity_index")

# Related entity types carried on events, as the entity graph names them.
RELATED_TYPES = ("cwe", "technique", "apt_group")

Event = Dict[str, Any]


# ── Snapshots ──────────────────────────────────────────────────


def _read_json(path: PathLike) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def project_kev(data: Any) -> Optional[Dict[str, Dict[str, str]]]:
    """kev_db.json to {cve: {date_added, due_date, ransomware, vendor, product}}."""
    if not isinstance(data, dict):
        return None
    out: Dict[str, Dict[str, str]] = {}
    for cve, entry in data.items():
        if not isinstance(entry, dict) or entry.get("inKEV") is False:
            continue
        out[str(cve)] = {
            "date_added": str(entry.get("dateAdded") or ""),
            "due_date": str(entry.get("dueDate") or ""),
            "ransomware": str(entry.get("knownRansomwareCampaignUse") or ""),
            "vendor": str(entry.get("vendorProject") or ""),
            "product": str(entry.get("product") or ""),
        }
    return out


def project_ssvc(data: Any) -> Optional[Dict[str, str]]:
    """vulnrichment_db.json to {cve: SSVC exploitation value}."""
    if not isinstance(data, dict):
        return None
    out: Dict[str, str] = {}
    for cve, entry in data.items():
        if isinstance(entry, dict) and isinstance(entry.get("ssvcExploitStatus"), str):
            out[str(cve)] = entry["ssvcExploitStatus"]
    return out


def project_epss(data: Any) -> Optional[Dict[str, float]]:
    """epss_curated.json to {cve: score}."""
    scores = data.get("scores") if isinstance(data, dict) else None
    if not isinstance(scores, dict):
        return None
    out: Dict[str, float] = {}
    for cve, entry in scores.items():
        score = entry.get("score") if isinstance(entry, dict) else None
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            out[str(cve)] = float(score)
    return out


def project_entities(data: Any) -> Optional[Dict[str, Dict[str, Any]]]:
    """entity_index.json to {cve: {cvss, cwe, technique, apt_group}} for the
    curated CVE tier. apt_group holds the groups ATT&CK cites for the CVE."""
    entities = data.get("entities") if isinstance(data, dict) else None
    if not isinstance(entities, dict):
        return None
    # I32: an index without the apt_attribution flag linked CVEs to groups
    # by technique overlap; its groups are not taken as related ids.
    meta = data.get("meta")
    attributed = isinstance(meta, dict) and meta.get("apt_attribution") is True
    out: Dict[str, Dict[str, Any]] = {}
    for key, ent in entities.items():
        if not isinstance(ent, dict) or ent.get("type") != "cve":
            continue
        cvss = ent.get("cvss_score")
        rec: Dict[str, Any] = {
            "cvss": cvss if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) else None,
        }
        rels = ent.get("rels")
        if not isinstance(rels, dict):
            rels = {}
        for rel_type in RELATED_TYPES:
            if rel_type == "apt_group" and not attributed:
                continue
            body = rels.get(rel_type)
            ids = body.get("ids") if isinstance(body, dict) else None
            if isinstance(ids, list):
                rec[rel_type] = sorted({str(i) for i in ids if isinstance(i, str) and i})
        out[str(key)] = rec
    return out


PROJECTORS: Dict[str, Callable[[Any], Any]] = {
    "kev": project_kev,
    "vulnrichment": project_ssvc,
    "epss": project_epss,
    "entity_index": project_entities,
}


def snapshot_source(source: str, path: PathLike) -> Any:
    """Projected state of one source file, or None when it is missing or
    unreadable. Never raises: no state means no events for the source."""
    try:
        return PROJECTORS[source](_read_json(path))
    except (OSError, ValueError, KeyError):
        return None


def snapshot_sources(paths: Mapping[str, PathLike]) -> Dict[str, Any]:
    """Snapshot every source in ``paths`` ({source: file path})."""
    return {source: snapshot_source(source, path) for source, path in paths.items()}


# ── Diffs ──────────────────────────────────────────────────────


def _event(day: str, etype: str, cve: str, before: Any, after: Any) -> Event:
    return {"date": day, "type": etype, "cve": cve, "before": before, "after": after}


def _kev_value(entry: Mapping[str, str]) -> Dict[str, str]:
    return {k: entry[k] for k in ("date_added", "due_date", "ransomware") if entry.get(k)}


def is_baseline(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    """True when ``before`` is complete enough that a record missing from it
    and present in ``after`` is new, not backfill."""
    return len(before) >= BASELINE_RATIO * len(after) or len(after) - len(before) <= BASELINE_SLACK


def removals_trusted(before: Mapping[str, Any], after: Mapping[str, Any], what: str) -> bool:
    """False, with a warning, when ``after`` shrank under the baseline
    fraction of ``before``; the caller then emits no removal events."""
    if len(after) >= BASELINE_RATIO * len(before):
        return True
    log_warning(
        f"Change log: {what} shrank from {len(before)} to {len(after)} records; "
        "no removal events recorded for it this run"
    )
    return False


def diff_kev(before: Mapping[str, Any], after: Mapping[str, Any], day: str) -> List[Event]:
    events: List[Event] = []
    if is_baseline(before, after):
        events += [_event(day, "kev_added", c, None, _kev_value(after[c])) for c in after if c not in before]
    if removals_trusted(before, after, "KEV"):
        events += [_event(day, "kev_removed", c, _kev_value(before[c]), None) for c in before if c not in after]
    return events


def diff_ssvc(before: Mapping[str, str], after: Mapping[str, str], day: str) -> List[Event]:
    """A changed exploitation value, or a first decision of active."""
    events: List[Event] = []
    baseline = is_baseline(before, after)
    for cve, value in after.items():
        old = before.get(cve)
        if old == value:
            continue
        if old is None and (value not in SSVC_NOTABLE or not baseline):
            continue
        events.append(_event(day, "ssvc_exploitation_changed", cve, old, value))
    return events


def is_epss_jump(old: float, new: float) -> bool:
    return abs(new - old) >= EPSS_JUMP or (old >= EPSS_LINE) != (new >= EPSS_LINE)


def diff_epss(before: Mapping[str, float], after: Mapping[str, float], day: str) -> List[Event]:
    """Jumps on CVEs scored in both files. A CVE new to the curated tier has
    no before score, so it is a curated_added event, not a jump."""
    return [
        _event(day, "epss_jump", cve, before[cve], new)
        for cve, new in after.items()
        if cve in before and is_epss_jump(before[cve], new)
    ]


def diff_entities(before: Mapping[str, Any], after: Mapping[str, Any], day: str) -> List[Event]:
    events: List[Event] = []
    baseline = is_baseline(before, after)
    for cve, rec in after.items():
        old = before.get(cve)
        if old is None:
            if baseline:
                events.append(_event(day, "curated_added", cve, False, True))
        elif old.get("cvss") != rec.get("cvss"):
            events.append(_event(day, "cvss_changed", cve, old.get("cvss"), rec.get("cvss")))
    if removals_trusted(before, after, "the curated CVE set"):
        events += [_event(day, "curated_removed", c, True, False) for c in before if c not in after]
    return events


DIFFS: Dict[str, Callable[[Any, Any, str], List[Event]]] = {
    "kev": diff_kev,
    "vulnrichment": diff_ssvc,
    "epss": diff_epss,
    "entity_index": diff_entities,
}


def _related(cve: str, before: Mapping[str, Any], after: Mapping[str, Any]) -> Dict[str, Any]:
    """Entities an event touches: graph rels from the entity index (after,
    else before), KEV vendor and product from the catalog (after, else
    before). Empty lists and names are left out."""
    def pick(src: str) -> Mapping[str, Any]:
        return (after.get(src) or {}).get(cve) or (before.get(src) or {}).get(cve) or {}

    rel: Dict[str, Any] = {}
    kev = pick("kev")
    for key in ("vendor", "product"):
        if kev.get(key):
            rel[key] = kev[key]
    graph = pick("entity_index")
    for key in RELATED_TYPES:
        if graph.get(key):
            rel[key] = list(graph[key])
    return rel


def compute_events(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    succeeded: Iterable[str],
    day: str,
) -> List[Event]:
    """Events for every source that succeeded and has both states."""
    events: List[Event] = []
    for source in SOURCES:
        if source not in succeeded:
            continue
        old, new = before.get(source), after.get(source)
        # An empty state is no baseline (a wiped file), and an empty after
        # state would read as every record removed.
        if not old or not new:
            continue
        events.extend(DIFFS[source](old, new, day))
    for ev in events:
        related = _related(ev["cve"], before, after)
        if related:
            ev["related"] = related
    return events


# ── The log ────────────────────────────────────────────────────


def _valid_event(ev: Any) -> bool:
    return (
        isinstance(ev, dict)
        and isinstance(ev.get("date"), str)
        and isinstance(ev.get("type"), str)
        and isinstance(ev.get("cve"), str)
    )


def read_log(path: PathLike) -> Tuple[Optional[Dict[str, Any]], bool]:
    """(document, ok). A missing file is (None, True); an unreadable one is
    (None, False) so the caller can say it is starting over."""
    target = Path(path)
    if not target.exists():
        return None, True
    try:
        doc = json.loads(gzip.decompress(target.read_bytes()).decode("utf-8"))
    except (OSError, EOFError, zlib.error, UnicodeDecodeError, ValueError):
        return None, False
    if not isinstance(doc, dict) or not isinstance(doc.get("events"), list):
        return None, False
    return doc, True


def _key(ev: Event) -> Tuple[str, str, str]:
    return (ev["date"], ev["type"], ev["cve"])


def merge_events(existing: Iterable[Event], new: Iterable[Event], today: str) -> List[Event]:
    """Merge, dedupe on (date, type, cve), prune to the window, newest first.

    A second run on the same day that sees the same kind of change on the
    same CVE keeps the day's net change: the first before, the latest after,
    and drops the event when those are equal.
    """
    cutoff = window_start(today)
    merged: Dict[Tuple[str, str, str], Event] = {}
    for ev in existing:
        if _valid_event(ev) and ev["date"] >= cutoff:
            merged[_key(ev)] = ev
    for ev in new:
        key = _key(ev)
        old = merged.get(key)
        if old is not None:
            ev = {**ev, "before": old.get("before")}
            if ev.get("before") == ev.get("after"):
                del merged[key]
                continue
        merged[key] = ev
    # Within a day, EVENT_TYPES order, so a cut at the end of a day drops
    # curated churn before KEV and SSVC news.
    events = sorted(merged.values(), key=lambda e: (_type_rank(e["type"]), e["cve"]))
    return sorted(events, key=lambda e: e["date"], reverse=True)


def _type_rank(etype: str) -> int:
    return EVENT_TYPES.index(etype) if etype in EVENT_TYPES else len(EVENT_TYPES)


def backfill_related(events: List[Event], graph: Optional[Mapping[str, Any]]) -> int:
    """Fill missing CWE, technique, and APT group ids on events whose CVE is
    in the entity index now (a daily KEV add curated by a later weekly run).
    Existing keys are never overwritten. Returns the events changed."""
    if not graph:
        return 0
    changed = 0
    for ev in events:
        rec = graph.get(ev["cve"])
        if not rec:
            continue
        related = ev.get("related")
        if not isinstance(related, dict):
            related = {}
        missing = {k: list(rec[k]) for k in RELATED_TYPES if rec.get(k) and k not in related}
        if missing:
            ev["related"] = {**related, **missing}
            changed += 1
    return changed


def window_start(today: str) -> str:
    """First day inside the window that ends on ``today``."""
    return (date.fromisoformat(today) - timedelta(days=WINDOW_DAYS - 1)).isoformat()


def cap_events(events: List[Event]) -> Tuple[List[Event], List[Event]]:
    """(kept, dropped) for events ordered newest first."""
    return events[:MAX_EVENTS], events[MAX_EVENTS:]


def carry_drops(
    existing: Optional[Mapping[str, Any]], dropped: Iterable[Event], today: str
) -> Dict[str, int]:
    """Events dropped by a cap, per event date, for the days still inside the
    window: the previous file's counts plus this write's. Counting per day
    keeps the total honest when the log sits at the cap for weeks."""
    cutoff = window_start(today)
    days: Dict[str, int] = {}
    old = existing.get("truncated_days") if existing else None
    if isinstance(old, dict):
        for day, n in old.items():
            if isinstance(day, str) and day >= cutoff and isinstance(n, int) and not isinstance(n, bool) and n > 0:
                days[day] = n
    for ev in dropped:
        if ev["date"] >= cutoff:
            days[ev["date"]] = days.get(ev["date"], 0) + 1
    return days


def render_log(events: List[Event], since: str, drops: Optional[Mapping[str, int]] = None) -> bytes:
    doc: Dict[str, Any] = {"schema": SCHEMA_VERSION, "window_days": WINDOW_DAYS, "since": since, "events": events}
    if drops:
        doc["truncated"] = sum(drops.values())
        doc["truncated_through"] = max(drops)
        doc["truncated_days"] = dict(sorted(drops.items()))
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return deterministic_gzip(text.encode("utf-8"))


def fit_log(
    events: List[Event], since: str, existing: Optional[Mapping[str, Any]], today: str
) -> Tuple[bytes, List[Event], List[Event]]:
    """Apply the count cap, then drop whole days, oldest first, while the
    rendered file is over MAX_BYTES. Returns (bytes, kept, dropped)."""
    kept, dropped = cap_events(events)
    while True:
        data = render_log(kept, since, carry_drops(existing, dropped, today))
        if len(data) <= MAX_BYTES or not kept:
            return data, kept, dropped
        oldest = kept[-1]["date"]
        dropped = dropped + [e for e in kept if e["date"] == oldest]
        kept = [e for e in kept if e["date"] != oldest]


def today_utc(now: Optional[datetime] = None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).date().isoformat()


def record_changes(
    before: Mapping[str, Any],
    paths: Mapping[str, PathLike],
    succeeded: Iterable[str],
    log_path: PathLike,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Diff each succeeded source against its snapshot, merge into the log,
    and write it atomically. Returns a summary for update_summary.json.

    The file is written when at least one source was diffed and the bytes
    differ from what is on disk; otherwise it is left untouched.
    """
    day = today_utc(now)
    done = [s for s in SOURCES if s in set(succeeded) and s in paths]
    after = {s: snapshot_source(s, paths[s]) for s in done}
    diffed = [s for s in done if before.get(s) and after.get(s)]
    new = compute_events(before, after, diffed, day)

    summary: Dict[str, Any] = {"diffed": diffed, "new_events": len(new), "written": False}
    if not diffed:
        return summary
    existing, ok = read_log(log_path)
    if not ok:
        summary["note"] = "existing change log unreadable; started a new one"
    since = existing.get("since") if existing else None
    if not isinstance(since, str) or not since:
        since = day
    merged = merge_events((existing or {}).get("events", []), new, day)
    backfilled = backfill_related(merged, after.get("entity_index"))
    if backfilled:
        summary["related_backfilled"] = backfilled
    data, events, dropped = fit_log(merged, since, existing, day)
    if dropped:
        summary["truncated"] = len(dropped)
    target = Path(log_path)
    if target.exists() and ok and target.read_bytes() == data:
        return summary
    atomic_write_bytes(target, data)
    summary["written"] = True
    summary["total_events"] = len(events)
    return summary
