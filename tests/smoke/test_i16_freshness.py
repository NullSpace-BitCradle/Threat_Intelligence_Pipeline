"""Smoke tests for I16 data freshness on the site (ISC-3, ISC-4, ISC-5).

freshness.json fixtures are served through Playwright routes and the page
clock is fixed, so the tests hold against any deployment: one without the
file yet, one with it, and the live site. The last test reads whatever file
the server actually has, and skips when there is none.

Run against a local server:
    cd docs && python3 -m http.server 8765 &
    BASE_URL=http://localhost:8765/ .venv/bin/pytest tests/smoke/ --browser chromium
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from playwright.sync_api import Page, expect

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/",
)

TIMEOUT_MS = 30_000
FRESHNESS_FILE = "**/data/freshness.json"
NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)

WEEKLY = {"nvd": "NVD CVE shards", "entity_index": "Entity index"}
DAILY = {
    "kev": "CISA KEV", "vulnrichment": "CISA Vulnrichment", "epss": "EPSS",
    "cwe": "CWE", "capec": "CAPEC", "attack": "MITRE ATT&CK", "d3fend": "D3FEND",
}


def _doc(ages_hours: dict[str, float]) -> str:
    sources = {}
    for key, label in {**WEEKLY, **DAILY}.items():
        weekly = key in WEEKLY
        when = NOW - timedelta(hours=ages_hours.get(key, 5.5))
        sources[key] = {
            "label": label,
            "last_success": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cadence_hours": 168 if weekly else 24,
            "stale_after_hours": 192 if weekly else 36,
        }
    return json.dumps({"schema": 1, "sources": sources})


def _serve(page: Page, body: str, status: int = 200) -> list[str]:
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.clock.set_fixed_time(NOW)
    page.route(FRESHNESS_FILE, lambda r: r.fulfill(status=status, content_type="application/json", body=body))
    return errors


def test_fresh_data_shows_data_as_of_on_every_page(page: Page) -> None:
    errors = _serve(page, _doc({"kev": 2}))
    page.goto(BASE_URL)
    line = page.locator("#data-freshness")
    # Newest source: KEV, two hours before NOW.
    expect(line.locator("summary")).to_have_text("Data as of 2026-09-27 10:00 UTC", timeout=TIMEOUT_MS)
    expect(page.locator("#stale-banner")).to_have_count(0)

    line.locator("summary").click()
    items = line.locator("li")
    expect(items).to_have_count(9)
    expect(line.locator("li[data-source=nvd]")).to_contain_text("NVD CVE shards")
    expect(line.locator("li[data-source=nvd]")).to_contain_text("weekly")
    expect(line.locator("li.is-stale")).to_have_count(0)

    for route in ("#/cve/CVE-2023-44487", "#/list/CVE-2023-44487", "#/search/apt"):
        page.evaluate("h => { window.location.hash = h; }", route)
        expect(page.locator("#data-freshness summary")).to_be_visible(timeout=TIMEOUT_MS)
    assert errors == []


def test_stale_source_raises_amber_banner_naming_it(page: Page) -> None:
    errors = _serve(page, _doc({"kev": 40, "nvd": 150}))
    page.goto(BASE_URL)
    banner = page.locator("#stale-banner")
    expect(banner).to_be_visible(timeout=TIMEOUT_MS)
    expect(banner).to_contain_text("CISA KEV")
    expect(banner).to_contain_text("expected daily")
    expect(banner).not_to_contain_text("NVD")  # 150 hours is inside 8 days
    bg = banner.evaluate("el => getComputedStyle(el).backgroundColor")
    assert bg == "rgba(187, 128, 9, 0.18)", bg  # amber
    expect(page.locator("#data-freshness li.is-stale")).to_have_count(1)
    expect(page.locator("#data-freshness li[data-source=kev]")).to_have_class("is-stale")
    # The landing page still works under the banner.
    expect(page.locator("#stats-bar")).not_to_be_empty(timeout=TIMEOUT_MS)
    assert errors == []


def test_weekly_source_past_eight_days_is_stale(page: Page) -> None:
    _serve(page, _doc({"nvd": 193}))
    page.goto(BASE_URL)
    banner = page.locator("#stale-banner")
    expect(banner).to_contain_text("NVD CVE shards", timeout=TIMEOUT_MS)
    expect(banner).to_contain_text("expected weekly")
    expect(banner).not_to_contain_text("CISA KEV")


@pytest.mark.parametrize("status, body", [
    (404, "not found"),
    (200, "not json {"),
    (200, "[]"),
    (200, '{"sources": 5}'),
    (200, '{"sources": {}}'),
])
def test_missing_or_malformed_file_renders_as_today(page: Page, status: int, body: str) -> None:
    errors = _serve(page, body, status)
    page.goto(BASE_URL)
    expect(page.locator("#stats-bar")).not_to_be_empty(timeout=TIMEOUT_MS)
    expect(page.locator("#quick-grid .quick-card").first).to_be_visible(timeout=TIMEOUT_MS)
    page.wait_for_load_state("networkidle")
    expect(page.locator("#data-freshness")).to_have_count(0)
    expect(page.locator("#stale-banner")).to_have_count(0)
    page.evaluate("() => { window.location.hash = '#/cve/CVE-2023-44487'; }")
    expect(page.locator("#result-main")).to_contain_text("KEV Date Added", timeout=TIMEOUT_MS)
    assert errors == []


def test_utc_offset_form_is_accepted(page: Page) -> None:
    """+00:00 reads the same as Z."""
    doc = json.loads(_doc({}))
    doc["sources"]["kev"]["last_success"] = "2026-09-27T10:00:00+00:00"
    errors = _serve(page, json.dumps(doc))
    page.goto(BASE_URL)
    expect(page.locator("#data-freshness summary")).to_have_text("Data as of 2026-09-27 10:00 UTC", timeout=TIMEOUT_MS)
    expect(page.locator("#stale-banner")).to_have_count(0)
    assert errors == []


@pytest.mark.parametrize("bad", ["yesterday", "", None, 12345, "2026-09-27"])
def test_unreadable_last_success_is_shown_stale_not_dropped(page: Page, bad) -> None:
    """Same rule as the canary: an entry whose time cannot be read is stale."""
    doc = json.loads(_doc({"nvd": 2}))
    doc["sources"]["kev"]["last_success"] = bad
    errors = _serve(page, json.dumps(doc))
    page.goto(BASE_URL)
    banner = page.locator("#stale-banner")
    expect(banner).to_contain_text("CISA KEV", timeout=TIMEOUT_MS)
    expect(banner).to_contain_text("update time unreadable")
    expect(page.locator("#data-freshness summary")).to_have_text("Data as of 2026-09-27 10:00 UTC")
    kev = page.locator("#data-freshness li[data-source=kev]")
    expect(kev).to_have_class("is-stale")
    expect(kev).to_contain_text("unknown")
    assert errors == []


def test_only_unreadable_entries_still_warn(page: Page) -> None:
    errors = _serve(page, '{"sources": {"kev": {"label": "CISA KEV", "last_success": "yesterday"}}}')
    page.goto(BASE_URL)
    expect(page.locator("#stale-banner")).to_contain_text("CISA KEV", timeout=TIMEOUT_MS)
    expect(page.locator("#data-freshness summary")).to_have_text("Data age unknown")
    assert errors == []


@pytest.mark.parametrize("width, height", [(1280, 560), (800, 480), (390, 640)])
def test_freshness_line_never_covers_the_last_landing_card(page: Page, width: int, height: int) -> None:
    page.set_viewport_size({"width": width, "height": height})
    _serve(page, _doc({}))
    page.goto(BASE_URL)
    card = page.locator("#quick-grid .quick-card").last
    expect(card).to_be_visible(timeout=TIMEOUT_MS)
    line = page.locator("#data-freshness")
    expect(line).to_be_visible()
    page.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight)")
    card_box = card.bounding_box()
    line_box = line.bounding_box()
    assert card_box and line_box
    # Clear by a margin, not by a hair: the line's height varies with font
    # rendering and zoom.
    assert card_box["y"] + card_box["height"] + 16 <= line_box["y"], (card_box, line_box)


def test_served_freshness_file_renders_when_present(page: Page) -> None:
    """Exercises the real generated file on a deployment that has one."""
    resp = page.request.get(f"{BASE_URL}data/freshness.json")
    if resp.status == 404:
        pytest.skip("this deployment has no freshness.json yet")
    assert resp.ok, resp.status
    json.loads(resp.text())
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.goto(BASE_URL)
    expect(page.locator("#data-freshness summary")).to_contain_text("Data as of", timeout=TIMEOUT_MS)
    assert errors == []
