"""Smoke tests for I7 watchlists and I8 "what changed" (ISC-5 to ISC-8).

The change log is served from tests/smoke/fixtures/changes_sample.json,
gzipped in the test and fulfilled through a Playwright route, and the page
clock is fixed, so every test holds against a deployment with no log yet,
one with a log, and the live site. The last test reads whatever the server
has.

Run against a local server:
    cd docs && python3 -m http.server 8765 &
    BASE_URL=http://localhost:8765/ .venv/bin/pytest tests/smoke/ --browser chromium
"""

import gzip
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/",
)
TIMEOUT_MS = 30_000
CHANGES = "**/data/changes.json.gz"
NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "changes_sample.json").read_text())
KEV_CVE = "CVE-2023-44487"


def _errors(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    return errors


def _serve(page: Page, body: bytes | None = None, status: int = 200) -> None:
    page.clock.set_fixed_time(NOW)
    data = gzip.compress(json.dumps(FIXTURE).encode()) if body is None else body
    page.route(CHANGES, lambda r: r.fulfill(status=status, content_type="application/gzip", body=data))


def _watch(page: Page, value) -> None:
    raw = value if isinstance(value, str) else json.dumps(value)
    page.add_init_script(f"window.localStorage.setItem('tip-watchlist', {json.dumps(raw)});")


def _go(page: Page, route: str) -> None:
    page.goto(f"{BASE_URL}{route}")


# ISC-5: a watch toggle on every watchable page, persisted across reloads.

@pytest.mark.parametrize("route, wtype, wid", [
    (f"#/cve/{KEV_CVE}", "cve", KEV_CVE),
    ("#/cwe/CWE-79", "cwe", "CWE-79"),
    ("#/technique/T1190", "technique", "T1190"),
    ("#/apt_group/G0016", "apt_group", "G0016"),
])
def test_entity_page_watch_toggle_persists(page: Page, route: str, wtype: str, wid: str) -> None:
    errors = _errors(page)
    _serve(page)
    _go(page, route)
    toggle = page.locator(f".entity-header .watch-toggle[data-watch-type={wtype}]")
    expect(toggle).to_have_attribute("aria-pressed", "false", timeout=TIMEOUT_MS)
    toggle.click()
    expect(toggle).to_have_attribute("aria-pressed", "true")
    expect(toggle).to_contain_text("Watching")
    page.reload()
    expect(page.locator(f".entity-header .watch-toggle[data-watch-type={wtype}]")).to_have_attribute(
        "aria-pressed", "true", timeout=TIMEOUT_MS)
    stored = json.loads(page.evaluate("() => localStorage.getItem('tip-watchlist')"))
    assert stored == [{"type": wtype, "id": wid}]
    page.locator(f".entity-header .watch-toggle[data-watch-type={wtype}]").click()
    assert json.loads(page.evaluate("() => localStorage.getItem('tip-watchlist')")) == []
    assert errors == []


def test_non_watchable_page_has_no_toggle(page: Page) -> None:
    _serve(page)
    _go(page, "#/capec/CAPEC-126")
    expect(page.locator("#result-main .entity-header")).to_be_visible(timeout=TIMEOUT_MS)
    expect(page.locator(".entity-header .watch-toggle")).to_have_count(0)


def test_kev_block_watches_vendor_and_product(page: Page) -> None:
    errors = _errors(page)
    _serve(page)
    _go(page, f"#/cve/{KEV_CVE}")
    vendor = page.locator(".kev-watch .watch-toggle[data-watch-type=kev_vendor]")
    product = page.locator(".kev-watch .watch-toggle[data-watch-type=kev_product]")
    expect(vendor).to_contain_text("vendor IETF", timeout=TIMEOUT_MS)
    expect(product).to_have_attribute("data-watch-id", "IETF/HTTP/2")
    vendor.click()
    product.click()
    page.reload()
    expect(page.locator(".kev-watch .watch-toggle[aria-pressed=true]")).to_have_count(2, timeout=TIMEOUT_MS)
    stored = json.loads(page.evaluate("() => localStorage.getItem('tip-watchlist')"))
    assert stored == [{"type": "kev_vendor", "id": "IETF"}, {"type": "kev_product", "id": "IETF/HTTP/2"}]
    assert errors == []


# ISC-6: the Watching view.

WATCHLIST = [
    {"type": "kev_vendor", "id": "IETF"},
    {"type": "cwe", "id": "CWE-79"},
    {"type": "technique", "id": "T1190"},
]


def test_watching_lists_watches_and_matching_events_newest_first(page: Page) -> None:
    errors = _errors(page)
    # Served oldest first: the page orders them.
    shuffled = dict(FIXTURE, events=list(reversed(FIXTURE["events"])))
    _serve(page, gzip.compress(json.dumps(shuffled).encode()))
    _watch(page, WATCHLIST)
    _go(page, "#/watching")
    expect(page.locator("#watch-list .watch-chip")).to_have_count(3, timeout=TIMEOUT_MS)
    expect(page.locator("#watch-list")).to_contain_text("KEV vendor IETF")
    rows = page.locator("#change-list .change-row")
    expect(rows).to_have_count(5, timeout=TIMEOUT_MS)
    dates = rows.locator(".change-date").all_text_contents()
    assert dates == sorted(dates, reverse=True) == ["2026-09-26", "2026-09-25", "2026-09-24", "2026-09-20", "2026-09-05"]
    expect(rows.nth(0)).to_contain_text("Entered KEV (IETF HTTP/2), added 2026-09-26, due 2026-10-17")
    expect(rows.nth(0)).to_contain_text("watching KEV vendor IETF")
    expect(rows.nth(1)).to_contain_text("SSVC exploitation poc → active")
    expect(rows.nth(2)).to_contain_text("EPSS 0.02 → 0.61")
    expect(rows.nth(3)).to_contain_text("CVSS 5.3 → 7.5")
    expect(page.locator("#feed-body")).to_contain_text("5 changes for your watchlist")
    # Removing a watch updates the view.
    page.locator("#watch-list .watch-chip[data-watch-type=kev_vendor] .watch-remove").click()
    expect(page.locator("#change-list .change-row")).to_have_count(3, timeout=TIMEOUT_MS)
    assert errors == []


def test_landing_counts_this_weeks_watchlist_changes(page: Page) -> None:
    _serve(page)
    _watch(page, WATCHLIST)
    _go(page, "")
    # This week from 2026-09-27: 09-26, 09-25, 09-24 (09-20 and older are out).
    expect(page.locator("#watch-summary")).to_have_text("3 changes for your watchlist this week", timeout=TIMEOUT_MS)
    expect(page.locator("#watch-count")).to_have_text(" (3)")
    page.locator("#watch-summary a").click()
    expect(page.locator("#page-feed")).to_be_visible(timeout=TIMEOUT_MS)
    expect(page.locator("#feed-title")).to_have_text("Watching")


def test_empty_watchlist_says_how_to_watch(page: Page) -> None:
    _serve(page)
    _go(page, "#/watching")
    expect(page.locator("#feed-body")).to_contain_text("not watching anything yet", timeout=TIMEOUT_MS)
    expect(page.locator("#change-list")).to_have_count(0)
    _go(page, "")
    expect(page.locator("#stats-bar")).not_to_be_empty(timeout=TIMEOUT_MS)
    expect(page.locator("#watch-summary")).to_have_text("")


# ISC-7: the global What changed view, filterable by type.

def test_changes_lists_every_event_and_filters_by_type(page: Page) -> None:
    errors = _errors(page)
    _serve(page)
    _go(page, "#/changes")
    rows = page.locator("#change-list .change-row")
    expect(rows).to_have_count(7, timeout=TIMEOUT_MS)
    expect(page.locator("#feed-body")).to_contain_text("7 changes in the last 30 days (log started 2026-09-01)")
    expect(rows.nth(6)).to_contain_text("Left the curated entity graph")
    page.locator("#changes-type-filter").select_option("epss_jump")
    expect(page).to_have_url(f"{BASE_URL}#/changes/epss_jump", timeout=TIMEOUT_MS)
    expect(page.locator("#change-list .change-row")).to_have_count(1, timeout=TIMEOUT_MS)
    expect(page.locator("#change-list")).to_contain_text("CVE-2026-4321")
    _go(page, "#/changes/kev_removed")
    expect(page.locator("#change-list .change-row")).to_have_count(1, timeout=TIMEOUT_MS)
    expect(page.locator("#change-list")).to_contain_text("Removed from KEV (Acme Widget), listed since 2021-11-03")
    # An unknown type in the hash shows everything instead of nothing.
    _go(page, "#/changes/bogus")
    expect(page.locator("#change-list .change-row")).to_have_count(7, timeout=TIMEOUT_MS)
    page.locator("#change-list .change-cve").first.click()
    expect(page.locator("#result-main")).to_contain_text(KEV_CVE, timeout=TIMEOUT_MS)
    assert errors == []


# ISC-8: corrupt storage and a missing or malformed log render safely.

@pytest.mark.parametrize("raw", [
    "not json {",
    '{"type": "cve", "id": "CVE-2023-44487"}',
    '[1, "x", null, {"type": "evil", "id": "x"}, {"type": "cve", "id": 5}, {"type": "cve", "id": ""}]',
    '"just a string"',
])
def test_corrupt_watchlist_reads_as_empty(page: Page, raw: str) -> None:
    errors = _errors(page)
    _serve(page)
    _watch(page, raw)
    _go(page, "")
    expect(page.locator("#stats-bar")).not_to_be_empty(timeout=TIMEOUT_MS)
    expect(page.locator("#watch-summary")).to_have_text("")
    _go(page, "#/watching")
    expect(page.locator("#feed-body")).to_contain_text("not watching anything yet", timeout=TIMEOUT_MS)
    _go(page, f"#/cve/{KEV_CVE}")
    toggle = page.locator(".entity-header .watch-toggle")
    expect(toggle).to_have_attribute("aria-pressed", "false", timeout=TIMEOUT_MS)
    # Watching again replaces the corrupt value with a valid list.
    toggle.click()
    assert json.loads(page.evaluate("() => localStorage.getItem('tip-watchlist')")) == [{"type": "cve", "id": KEV_CVE}]
    assert errors == []


def test_valid_entries_survive_next_to_bad_ones(page: Page) -> None:
    _serve(page)
    _watch(page, '[{"type": "cwe", "id": "CWE-79"}, {"type": "nope", "id": "x"}, 7]')
    _go(page, "#/watching")
    expect(page.locator("#watch-list .watch-chip")).to_have_count(1, timeout=TIMEOUT_MS)
    expect(page.locator("#change-list .change-row")).to_have_count(2, timeout=TIMEOUT_MS)


@pytest.mark.parametrize("status, body, message", [
    (404, b"not found", "No change log has been published yet"),
    (500, b"oops", "Could not read the change log"),
    (200, b"not gzip at all", "Could not read the change log"),
    (200, gzip.compress(b"{broken"), "Could not read the change log"),
    (200, gzip.compress(b"[]"), "Could not read the change log"),
])
def test_missing_or_malformed_log_renders_safely(page: Page, status: int, body: bytes, message: str) -> None:
    errors = _errors(page)
    _serve(page, body, status)
    _watch(page, WATCHLIST)
    _go(page, "")
    expect(page.locator("#stats-bar")).not_to_be_empty(timeout=TIMEOUT_MS)
    expect(page.locator("#quick-grid .quick-card").first).to_be_visible(timeout=TIMEOUT_MS)
    page.wait_for_load_state("networkidle")
    expect(page.locator("#watch-summary")).to_have_text("")
    for route in ("#/changes", "#/watching"):
        page.evaluate("h => { window.location.hash = h; }", route)
        expect(page.locator("#feed-body")).to_contain_text(message, timeout=TIMEOUT_MS)
        expect(page.locator("#change-list")).to_have_count(0)
    page.evaluate("h => { window.location.hash = h; }", f"#/cve/{KEV_CVE}")
    expect(page.locator("#result-main")).to_contain_text("KEV Date Added", timeout=TIMEOUT_MS)
    assert errors == []


def test_truncated_log_says_older_changes_may_be_missing(page: Page) -> None:
    errors = _errors(page)
    _serve(page, gzip.compress(json.dumps(dict(FIXTURE, truncated=12, truncated_through="2026-09-02")).encode()))
    _watch(page, WATCHLIST)
    _go(page, "#/changes")
    expect(page.locator("#feed-truncated")).to_have_text(
        "12 older changes were dropped to keep the log under its size cap; "
        "changes on or before 2026-09-02 may be missing.", timeout=TIMEOUT_MS)
    _go(page, "#/watching")
    expect(page.locator("#feed-truncated")).to_be_visible(timeout=TIMEOUT_MS)
    _go(page, "#/changes/epss_jump")
    expect(page.locator("#change-list .change-row")).to_have_count(1, timeout=TIMEOUT_MS)
    assert errors == []


def test_untruncated_log_has_no_note(page: Page) -> None:
    _serve(page, gzip.compress(json.dumps(dict(FIXTURE, truncated="many")).encode()))
    _go(page, "#/changes")
    expect(page.locator("#change-list .change-row")).to_have_count(7, timeout=TIMEOUT_MS)
    expect(page.locator("#feed-truncated")).to_have_count(0)


def test_malformed_events_are_skipped(page: Page) -> None:
    doc = {"events": [FIXTURE["events"][0], {"date": "yesterday", "type": "kev_added", "cve": "CVE-2026-0001"},
                      {"date": "2026-09-26", "type": "unknown_type", "cve": "CVE-2026-0002"},
                      {"date": "2026-09-26", "type": "kev_added", "cve": "<img src=x>"}, None, [1]]}
    errors = _errors(page)
    _serve(page, gzip.compress(json.dumps(doc).encode()))
    _go(page, "#/changes")
    expect(page.locator("#change-list .change-row")).to_have_count(1, timeout=TIMEOUT_MS)
    expect(page.locator("#feed-body")).to_contain_text("1 change in the last 30 days")
    expect(page.locator("#feed-body")).not_to_contain_text("log started")
    assert errors == []


def test_served_log_as_is(page: Page) -> None:
    """Legacy data (no log) says so; published data lists its events."""
    errors = _errors(page)
    _go(page, "#/changes")
    body = page.locator("#feed-body")
    expect(body).to_contain_text("change", timeout=TIMEOUT_MS)
    if page.locator("#change-list").count() == 0:
        expect(body).to_contain_text("No change log has been published yet")
    else:
        expect(body).to_contain_text("in the last 30 days")
    assert errors == []
