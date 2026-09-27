"""recent_changes (I8 F3, ISC-9): the change log over MCP, filtered by entity
and event type, in the standard envelopes. The log is built with the
pipeline's own writer, so the tool reads exactly what the pipeline writes."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from tip.core import change_log
from tip_mcp.loader import IndexLoader
from tip_mcp.tools import CHANGE_EVENT_TYPES, DEFAULT_CHANGES_LIMIT, recent_changes_impl

EVENTS = [
    {"date": "2026-09-28", "type": "kev_added", "cve": "CVE-2026-1234", "before": None,
     "after": {"date_added": "2026-09-27", "due_date": "2026-10-17"},
     "related": {"vendor": "Ivanti", "product": "Connect Secure", "cwe": ["CWE-22"], "technique": ["T1190"]}},
    {"date": "2026-09-27", "type": "ssvc_exploitation_changed", "cve": "CVE-2025-9999",
     "before": "poc", "after": "active", "related": {"apt_group": ["G0016"], "cwe": ["CWE-79"]}},
    {"date": "2026-09-26", "type": "epss_jump", "cve": "CVE-2026-4321", "before": 0.02, "after": 0.61},
]


def _loader(tmp_path: Path, raw: bytes | None) -> IndexLoader:
    if raw is not None:
        (tmp_path / "changes.json.gz").write_bytes(raw)
    return IndexLoader(tmp_path)


@pytest.fixture
def ld(tmp_path: Path) -> IndexLoader:
    return _loader(tmp_path, change_log.render_log(EVENTS, "2026-09-01"))


def _cves(res: dict) -> list[str]:
    assert res["ok"] is True, res
    return [e["cve"] for e in res["data"]["events"]]


def test_event_types_match_the_pipeline():
    assert CHANGE_EVENT_TYPES == change_log.EVENT_TYPES


def test_all_events_newest_first_with_meta(ld):
    res = recent_changes_impl(ld)
    assert _cves(res) == ["CVE-2026-1234", "CVE-2025-9999", "CVE-2026-4321"]
    assert res["meta"] == {"source": "changes.json.gz", "limit": DEFAULT_CHANGES_LIMIT,
                           "count": 3, "total": 3, "since": "2026-09-01", "window_days": 30}
    first = res["data"]["events"][0]
    assert first["before"] is None and first["after"]["due_date"] == "2026-10-17"


@pytest.mark.parametrize("entity_id, expected", [
    ("CVE-2026-1234", ["CVE-2026-1234"]),
    (" cve-2025-9999 ", ["CVE-2025-9999"]),
    ("CWE-22", ["CVE-2026-1234"]),
    ("cwe-79", ["CVE-2025-9999"]),
    ("T1190", ["CVE-2026-1234"]),
    ("g0016", ["CVE-2025-9999"]),
    ("Ivanti", ["CVE-2026-1234"]),
    ("connect secure", ["CVE-2026-1234"]),
    ("CWE-787", []),
])
def test_filter_by_entity(ld, entity_id, expected):
    assert _cves(recent_changes_impl(ld, entity_id=entity_id)) == expected


def test_filter_by_type_and_entity_together(ld):
    assert _cves(recent_changes_impl(ld, type="epss_jump")) == ["CVE-2026-4321"]
    assert _cves(recent_changes_impl(ld, entity_id="CWE-22", type="epss_jump")) == []


def test_limit_caps_and_total_counts(ld):
    res = recent_changes_impl(ld, limit=1)
    assert _cves(res) == ["CVE-2026-1234"]
    assert res["meta"]["count"] == 1 and res["meta"]["total"] == 3


@pytest.mark.parametrize("kwargs, message", [
    ({"entity_id": ""}, "entity_id"),
    ({"entity_id": "   "}, "entity_id"),
    ({"entity_id": 5}, "entity_id"),
    ({"type": "kev"}, "not a change event type"),
    ({"type": 3}, "not a change event type"),
    ({"limit": 0}, "limit"),
    ({"limit": True}, "limit"),
    ({"limit": "5"}, "limit"),
])
def test_bad_params(ld, kwargs, message):
    res = recent_changes_impl(ld, **kwargs)
    assert res["ok"] is False and res["error"]["code"] == "bad_param"
    assert message in res["error"]["message"]


def test_type_error_names_the_valid_types(ld):
    assert "kev_added" in recent_changes_impl(ld, type="nope")["error"]["hint"]


@pytest.mark.parametrize("raw, reason", [
    (None, "not found"),
    (b"not gzip", "unreadable"),
    (gzip.compress(b"{broken"), "unreadable"),
    (gzip.compress(b"[]"), "wrong shape"),
    (gzip.compress(b'{"events": 5}'), "wrong shape"),
])
def test_missing_or_malformed_log_is_ok_and_empty(tmp_path, raw, reason):
    res = recent_changes_impl(_loader(tmp_path, raw))
    assert res["ok"] is True and res["data"] == {"events": []}
    assert res["meta"]["count"] == 0 and reason in res["meta"]["note"]


def test_malformed_events_are_dropped(tmp_path):
    doc = {"events": [EVENTS[0], {"date": "x"}, None, dict(EVENTS[1], related=[1])], "since": 7}
    res = recent_changes_impl(_loader(tmp_path, gzip.compress(json.dumps(doc).encode())))
    assert _cves(res) == ["CVE-2026-1234"]
    assert res["meta"]["since"] is None and res["meta"]["window_days"] is None


def test_non_string_related_values_do_not_match(tmp_path):
    ev = dict(EVENTS[0], related={"vendor": 5, "cwe": "CWE-22", "technique": [None, "T1190"]})
    ld = _loader(tmp_path, change_log.render_log([ev], "2026-09-01"))
    assert _cves(recent_changes_impl(ld, entity_id="CWE-22")) == []
    assert _cves(recent_changes_impl(ld, entity_id="T1190")) == ["CVE-2026-1234"]


def test_log_is_read_once_and_reset_by_load(fixture_data_dir, tmp_path):
    ld = IndexLoader(fixture_data_dir)
    assert recent_changes_impl(ld)["meta"]["total"] == 0  # fixtures have no log
    ld.load()
    assert ld.changes is None and "not found" in (ld.changes_error or "")
