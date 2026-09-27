"""I8 change events: docs/data/changes.json.gz (ISC-1, ISC-2, ISC-3).

Each event type is computed from a before and an after state; the log is
merged, deduped on (date, type, cve), pruned to 30 days, and written
atomically; a source whose step did not succeed, or that has no before
state, adds nothing. No network and no git: states are fixture files.
"""
import gzip
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests

from tip.core import change_log as cl
from tip.core import pipeline_orchestrator as po

DAY = "2026-09-28"
NOW = datetime(2026, 9, 28, 6, 30, tzinfo=timezone.utc)


def _kev(**entries):
    return {
        cve: {"inKEV": True, "dateAdded": v[0], "dueDate": v[1], "knownRansomwareCampaignUse": "Unknown",
              "requiredAction": "Patch.", "vendorProject": v[2], "product": v[3]}
        for cve, v in entries.items()
    }


def _ssvc(**entries):
    return {cve: {"ssvcExploitStatus": v, "ssvcAutomatable": "no", "ssvcTechnicalImpact": "total"}
            for cve, v in entries.items()}


def _epss(**scores):
    return {"meta": {"total_count": 300000}, "scores": {c: {"score": s, "percentile": 0.5} for c, s in scores.items()}}


def _index(**cves):
    ents = {"CWE-79": {"type": "cwe", "id": "CWE-79", "rels": {}}}
    for cve, (cvss, rels) in cves.items():
        ents[cve] = {"type": "cve", "id": cve, "cvss_score": cvss,
                     "rels": {k: {"ids": v, "source": "chain"} for k, v in rels.items()}}
    return {"meta": {}, "entities": ents}


def _events(before, after, sources=cl.SOURCES):
    b = {s: cl.PROJECTORS[s](before[s]) for s in before}
    a = {s: cl.PROJECTORS[s](after[s]) for s in after}
    return cl.compute_events(b, a, sources, DAY)


def _one(events, etype):
    hits = [e for e in events if e["type"] == etype]
    assert len(hits) == 1, events
    return hits[0]


# ── ISC-1: one test per event type ─────────────────────────────

BASE_KEV = _kev(**{f"CVE-2024-{i:04d}": ("2024-01-01", "2024-01-22", "Acme", "Web") for i in range(1, 11)})


def test_kev_added_carries_dates_vendor_and_product():
    after = dict(BASE_KEV, **_kev(**{"CVE-2026-1234": ("2026-09-27", "2026-10-17", "Ivanti", "Connect Secure")}))
    ev = _one(_events({"kev": BASE_KEV}, {"kev": after}), "kev_added")
    assert ev["cve"] == "CVE-2026-1234" and ev["date"] == DAY and ev["before"] is None
    assert ev["after"] == {"date_added": "2026-09-27", "due_date": "2026-10-17", "ransomware": "Unknown"}
    assert ev["related"] == {"vendor": "Ivanti", "product": "Connect Secure"}


def test_kev_removed_keeps_the_before_value():
    after = {k: v for k, v in BASE_KEV.items() if k != "CVE-2024-0003"}
    ev = _one(_events({"kev": BASE_KEV}, {"kev": after}), "kev_removed")
    assert ev["cve"] == "CVE-2024-0003" and ev["after"] is None
    assert ev["before"]["date_added"] == "2024-01-01"
    assert ev["related"] == {"vendor": "Acme", "product": "Web"}


def test_unchanged_kev_is_no_event():
    assert _events({"kev": BASE_KEV}, {"kev": dict(BASE_KEV)}) == []


BASE_SSVC = _ssvc(**{f"CVE-2025-{i:04d}": "none" for i in range(1, 11)})


def test_ssvc_exploitation_change_is_an_event():
    after = dict(BASE_SSVC, **_ssvc(**{"CVE-2025-0002": "active"}))
    ev = _one(_events({"vulnrichment": BASE_SSVC}, {"vulnrichment": after}), "ssvc_exploitation_changed")
    assert (ev["cve"], ev["before"], ev["after"]) == ("CVE-2025-0002", "none", "active")


def test_ssvc_other_fields_changing_is_no_event():
    after = json.loads(json.dumps(BASE_SSVC))
    after["CVE-2025-0001"]["ssvcAutomatable"] = "yes"
    assert _events({"vulnrichment": BASE_SSVC}, {"vulnrichment": after}) == []


@pytest.mark.parametrize("value, expected", [("poc", 1), ("active", 1), ("none", 0)])
def test_first_ssvc_decision_is_an_event_only_when_notable(value, expected):
    after = dict(BASE_SSVC, **_ssvc(**{"CVE-2026-0001": value}))
    events = _events({"vulnrichment": BASE_SSVC}, {"vulnrichment": after})
    assert len(events) == expected
    if expected:
        assert events[0]["before"] is None and events[0]["after"] == value


@pytest.mark.parametrize("old, new, jump", [
    (0.02, 0.61, True),    # the Vision example
    (0.30, 0.40, True),    # exactly the 0.1 step
    (0.45, 0.52, True),    # crosses 0.5 upward by less than 0.1
    (0.55, 0.49, True),    # crosses 0.5 downward
    (0.70, 0.55, True),    # drops by 0.15
    (0.10, 0.19, False),   # under the step, no crossing
    (0.60, 0.65, False),
])
def test_epss_jump_rule(old, new, jump):
    events = _events({"epss": _epss(**{"CVE-2026-4321": old})}, {"epss": _epss(**{"CVE-2026-4321": new})})
    assert bool(events) is jump
    if jump:
        assert (events[0]["type"], events[0]["before"], events[0]["after"]) == ("epss_jump", old, new)


def test_epss_for_a_cve_new_to_the_tier_is_not_a_jump():
    events = _events({"epss": _epss(**{"CVE-2026-0001": 0.1})},
                     {"epss": _epss(**{"CVE-2026-0001": 0.1, "CVE-2026-0002": 0.9})})
    assert events == []


REL = {"cwe": ["CWE-79"], "technique": ["T1190"], "apt_group": ["G0016"]}
BASE_INDEX = _index(**{f"CVE-2023-{i:04d}": (7.5, REL) for i in range(1, 11)})


def test_cvss_changed_on_a_curated_cve():
    after = json.loads(json.dumps(BASE_INDEX))
    after["entities"]["CVE-2023-0004"]["cvss_score"] = 9.8
    ev = _one(_events({"entity_index": BASE_INDEX}, {"entity_index": after}), "cvss_changed")
    assert (ev["cve"], ev["before"], ev["after"]) == ("CVE-2023-0004", 7.5, 9.8)
    assert ev["related"] == REL


def test_curated_added_and_removed():
    after = json.loads(json.dumps(BASE_INDEX))
    del after["entities"]["CVE-2023-0001"]
    after["entities"].update(_index(**{"CVE-2026-0009": (5.0, {"cwe": ["CWE-22"]})})["entities"])
    events = _events({"entity_index": BASE_INDEX}, {"entity_index": after})
    added, removed = _one(events, "curated_added"), _one(events, "curated_removed")
    assert (added["cve"], added["before"], added["after"]) == ("CVE-2026-0009", False, True)
    assert added["related"] == {"cwe": ["CWE-22"]}
    # A CVE that left the graph keeps the rels it had, so watchers still match.
    assert (removed["cve"], removed["before"], removed["after"]) == ("CVE-2023-0001", True, False)
    assert removed["related"] == REL


def test_related_joins_kev_and_graph_for_any_event_type():
    after = dict(BASE_SSVC, **_ssvc(**{"CVE-2023-0002": "active"}))
    before_ssvc = dict(BASE_SSVC, **_ssvc(**{"CVE-2023-0002": "poc"}))
    kev = _kev(**{"CVE-2023-0002": ("2023-01-01", "2023-01-22", "Citrix", "ADC")})
    b = {"vulnrichment": cl.project_ssvc(before_ssvc), "kev": cl.project_kev(kev),
         "entity_index": cl.project_entities(BASE_INDEX)}
    a = {"vulnrichment": cl.project_ssvc(after)}
    ev = _one(cl.compute_events(b, a, ["vulnrichment"], DAY), "ssvc_exploitation_changed")
    assert ev["related"] == dict(REL, vendor="Citrix", product="ADC")


# ── ISC-3: only provable events ────────────────────────────────

@pytest.mark.parametrize("before", [None, {}])
def test_no_or_empty_before_state_is_zero_events(before):
    after = {"kev": cl.project_kev(BASE_KEV)}
    assert cl.compute_events({"kev": before}, after, ["kev"], DAY) == []


def test_empty_after_state_is_not_every_record_removed():
    before = {"kev": cl.project_kev(BASE_KEV)}
    assert cl.compute_events(before, {"kev": {}}, ["kev"], DAY) == []


def test_partial_baseline_adds_no_added_events_but_keeps_changes():
    """2026-09-27: vulnrichment_db.json went from a partial 2,567 records to
    a full 188,261 rebuild. The missing records were backfill, not news."""
    before = _ssvc(**{"CVE-2025-0001": "poc"})
    after = dict(_ssvc(**{f"CVE-2020-{i:04d}": "active" for i in range(1, 50)}), **_ssvc(**{"CVE-2025-0001": "active"}))
    events = _events({"vulnrichment": before}, {"vulnrichment": after})
    assert [(e["cve"], e["before"], e["after"]) for e in events] == [("CVE-2025-0001", "poc", "active")]
    kev_events = _events({"kev": _kev(**{"CVE-2024-0001": ("a", "b", "c", "d")})}, {"kev": BASE_KEV})
    assert kev_events == []


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj))


def _paths(root: Path) -> dict:
    data = root / "docs" / "data"
    return {"kev": data / "kev_db.json", "vulnrichment": data / "vulnrichment_db.json",
            "epss": data / "epss_curated.json", "entity_index": data / "entity_index.json"}


def _read_log(path: Path) -> dict:
    return json.loads(gzip.decompress(path.read_bytes()))


def test_first_run_without_prior_files_writes_nothing(tmp_path):
    paths = _paths(tmp_path)
    log = tmp_path / "docs" / "data" / "changes.json.gz"
    before = cl.snapshot_sources(paths)
    assert before == {s: None for s in cl.SOURCES}
    _write(paths["kev"], BASE_KEV)
    summary = cl.record_changes(before, paths, ["kev"], log, now=NOW)
    assert summary == {"diffed": [], "new_events": 0, "written": False}
    assert not log.exists()


def test_first_run_with_prior_state_and_no_log_records_only_real_changes(tmp_path):
    paths = _paths(tmp_path)
    log = tmp_path / "docs" / "data" / "changes.json.gz"
    _write(paths["kev"], BASE_KEV)
    before = cl.snapshot_sources(paths)
    _write(paths["kev"], dict(BASE_KEV, **_kev(**{"CVE-2026-1234": ("2026-09-27", "2026-10-17", "Ivanti", "ICS")})))
    summary = cl.record_changes(before, paths, ["kev"], log, now=NOW)
    doc = _read_log(log)
    assert summary["written"] and summary["new_events"] == 1
    assert doc["since"] == DAY and doc["window_days"] == 30 and doc["schema"] == 1
    assert [e["cve"] for e in doc["events"]] == ["CVE-2026-1234"]


@pytest.mark.parametrize("garbage", [b"not gzip", gzip.compress(b"{nope"), gzip.compress(b"[]")])
def test_snapshot_of_unreadable_file_is_no_state(tmp_path, garbage):
    path = tmp_path / "kev_db.json"
    path.write_bytes(garbage)
    assert cl.snapshot_source("kev", path) is None


# ── ISC-2: bounded, atomic, successful steps only ──────────────

def test_failed_or_partial_source_adds_no_events(tmp_path):
    paths = _paths(tmp_path)
    log = tmp_path / "docs" / "data" / "changes.json.gz"
    _write(paths["kev"], BASE_KEV)
    _write(paths["vulnrichment"], BASE_SSVC)
    before = cl.snapshot_sources(paths)
    # Both files changed on disk, but only vulnrichment's step succeeded.
    _write(paths["kev"], dict(BASE_KEV, **_kev(**{"CVE-2026-1234": ("x", "y", "V", "P")})))
    _write(paths["vulnrichment"], dict(BASE_SSVC, **_ssvc(**{"CVE-2025-0001": "poc"})))
    cl.record_changes(before, paths, ["vulnrichment"], log, now=NOW)
    types = {e["type"] for e in _read_log(log)["events"]}
    assert types == {"ssvc_exploitation_changed"}


def test_compute_events_skips_sources_not_listed_as_succeeded():
    after = dict(BASE_KEV, **_kev(**{"CVE-2026-1234": ("x", "y", "V", "P")}))
    assert _events({"kev": BASE_KEV}, {"kev": after}, sources=["vulnrichment"]) == []


def _ev(day, etype="kev_added", cve="CVE-2026-0001", before=None, after=None):
    return {"date": day, "type": etype, "cve": cve, "before": before, "after": after}


def test_merge_prunes_to_thirty_days_and_orders_newest_first():
    existing = [_ev("2026-08-29", cve="CVE-OLD"), _ev("2026-08-30", cve="CVE-EDGE"), _ev("2026-09-20", cve="CVE-MID")]
    merged = cl.merge_events(existing, [_ev(DAY, cve="CVE-NEW")], DAY)
    # 2026-08-30 is the 30th day counting today; 2026-08-29 is the 31st.
    assert [e["cve"] for e in merged] == ["CVE-NEW", "CVE-MID", "CVE-EDGE"]


def test_merge_dedupes_on_date_type_cve_keeping_the_day_net_change():
    first = [_ev(DAY, "ssvc_exploitation_changed", before="none", after="poc")]
    again = cl.merge_events(first, [_ev(DAY, "ssvc_exploitation_changed", before="poc", after="active")], DAY)
    assert [(e["before"], e["after"]) for e in again] == [("none", "active")]
    same = cl.merge_events(first, [_ev(DAY, "ssvc_exploitation_changed", before="none", after="poc")], DAY)
    assert len(same) == 1
    back = cl.merge_events(first, [_ev(DAY, "ssvc_exploitation_changed", before="poc", after="none")], DAY)
    assert back == []
    # A different day or type is a different event.
    other = cl.merge_events(first, [_ev("2026-09-27", "ssvc_exploitation_changed", before="x", after="none")], DAY)
    assert len(other) == 2


def test_merge_drops_malformed_existing_events():
    existing = [None, {"date": DAY}, _ev(DAY, cve="CVE-OK"), {"date": 1, "type": "t", "cve": "c"}]
    assert [e["cve"] for e in cl.merge_events(existing, [], DAY)] == ["CVE-OK"]


def _two_runs(tmp_path):
    paths = _paths(tmp_path)
    log = tmp_path / "docs" / "data" / "changes.json.gz"
    _write(paths["kev"], BASE_KEV)
    before = cl.snapshot_sources(paths)
    _write(paths["kev"], dict(BASE_KEV, **_kev(**{"CVE-2026-1234": ("x", "y", "V", "P")})))
    cl.record_changes(before, paths, ["kev"], log, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    return paths, log


def test_log_merges_across_runs_and_prunes(tmp_path):
    paths, log = _two_runs(tmp_path)
    before = cl.snapshot_sources(paths)
    _write(paths["kev"], dict(BASE_KEV, **_kev(**{"CVE-2026-1234": ("x", "y", "V", "P"),
                                                   "CVE-2026-9999": ("x", "y", "V", "P")})))
    cl.record_changes(before, paths, ["kev"], log, now=NOW)
    doc = _read_log(log)
    # 2026-09-01 is inside the window from 2026-09-28; since stays the first day.
    assert [(e["date"], e["cve"]) for e in doc["events"]] == [(DAY, "CVE-2026-9999"), ("2026-09-01", "CVE-2026-1234")]
    assert doc["since"] == "2026-09-01"
    later = cl.snapshot_sources(paths)
    cl.record_changes(later, paths, ["kev"], log, now=datetime(2026, 10, 20, tzinfo=timezone.utc))
    assert [e["cve"] for e in _read_log(log)["events"]] == ["CVE-2026-9999"]


def test_unchanged_log_is_not_rewritten_and_bytes_are_deterministic(tmp_path):
    paths, log = _two_runs(tmp_path)
    first = log.read_bytes()
    mtime = log.stat().st_mtime_ns
    before = cl.snapshot_sources(paths)
    summary = cl.record_changes(before, paths, ["kev"], log, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert summary["written"] is False and log.read_bytes() == first and log.stat().st_mtime_ns == mtime
    events = _read_log(log)["events"]
    assert cl.render_log(events, "2026-09-01") == first
    assert first[4:8] == b"\x00\x00\x00\x00"  # gzip mtime field is zero


def test_write_is_atomic(tmp_path, monkeypatch):
    paths, log = _two_runs(tmp_path)
    prior = log.read_bytes()
    before = cl.snapshot_sources(paths)
    _write(paths["kev"], BASE_KEV)

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        cl.record_changes(before, paths, ["kev"], log, now=NOW)
    assert log.read_bytes() == prior
    assert [p.name for p in log.parent.iterdir() if p.name.startswith(".")] == []


def test_unreadable_existing_log_starts_over_and_says_so(tmp_path):
    paths, log = _two_runs(tmp_path)
    log.write_bytes(b"garbage")
    before = cl.snapshot_sources(paths)
    _write(paths["kev"], BASE_KEV)
    summary = cl.record_changes(before, paths, ["kev"], log, now=NOW)
    assert "unreadable" in summary["note"]
    doc = _read_log(log)
    assert doc["since"] == DAY and [e["type"] for e in doc["events"]] == ["kev_removed"]


# ── Through the real orchestrator ──────────────────────────────

ALL_DB_OK = {k: True for k in ("capec", "cwe", "techniques", "defend", "kev", "vulnrichment", "groups", "epss", "ctid")}


@pytest.fixture
def orch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def _blocked(*_a, **_k):
        raise requests.exceptions.ConnectionError("network blocked in unit tests")

    monkeypatch.setattr(requests, "get", _blocked)
    paths = _paths(tmp_path)
    _write(paths["kev"], BASE_KEV)
    _write(paths["vulnrichment"], BASE_SSVC)
    return po.PipelineOrchestrator(), paths, tmp_path / "docs" / "data" / "changes.json.gz"


def _stub_db(orch, monkeypatch, paths, results, fresh):
    def update_all():
        # The steps overwrite their files in place, as the real ones do.
        _write(paths["kev"], dict(BASE_KEV, **_kev(**{"CVE-2026-1234": ("x", "y", "Ivanti", "ICS")})))
        _write(paths["vulnrichment"], dict(BASE_SSVC, **_ssvc(**{"CVE-2025-0001": "active"})))
        orch.db_manager.fresh_writes = set(fresh)
        return results

    monkeypatch.setattr(orch.db_manager, "update_all_databases", update_all)


def test_db_only_run_records_events_and_is_not_a_step(orch, monkeypatch):
    o, paths, log = orch
    _stub_db(o, monkeypatch, paths, dict(ALL_DB_OK), ALL_DB_OK)
    summary = o.run_database_updates_only()
    assert po.exit_code_for(summary) == 0
    assert "changes" not in summary["results"]
    assert summary["pipeline_session"]["total_steps"] == 1
    assert summary["changes"]["diffed"] == ["kev", "vulnrichment"]
    assert {e["type"] for e in _read_log(log)["events"]} == {"kev_added", "ssvc_exploitation_changed"}


def test_partial_db_run_records_only_the_steps_that_succeeded(orch, monkeypatch):
    o, paths, log = orch
    _stub_db(o, monkeypatch, paths, dict(ALL_DB_OK, kev=False), set(ALL_DB_OK) - {"kev"})
    summary = o.run_database_updates_only()
    assert po.exit_code_for(summary) == 1
    assert {e["type"] for e in _read_log(log)["events"]} == {"ssvc_exploitation_changed"}


def test_success_without_fresh_data_records_nothing(orch, monkeypatch):
    o, paths, log = orch
    _stub_db(o, monkeypatch, paths, dict(ALL_DB_OK), set())
    o.run_database_updates_only()
    assert not log.exists()


def test_change_log_failure_does_not_fail_the_run(orch, monkeypatch):
    o, paths, log = orch
    _stub_db(o, monkeypatch, paths, dict(ALL_DB_OK), ALL_DB_OK)

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(cl, "record_changes", boom)
    summary = o.run_database_updates_only()
    assert po.exit_code_for(summary) == 0
    assert summary["changes"] == {"error": "disk full"}


def test_snapshot_failure_means_no_events_not_a_red_run(orch, monkeypatch):
    o, paths, log = orch
    _stub_db(o, monkeypatch, paths, dict(ALL_DB_OK), ALL_DB_OK)

    def boom(*_a, **_k):
        raise MemoryError("too big")

    monkeypatch.setattr(cl, "snapshot_sources", boom)
    summary = o.run_database_updates_only()
    assert po.exit_code_for(summary) == 0
    assert "changes" not in summary and not log.exists()


def test_summary_without_a_snapshot_has_no_changes_key(orch):
    o, _paths_, log = orch
    assert "changes" not in o._create_summary()
