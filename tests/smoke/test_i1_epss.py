"""Smoke tests for I1 EPSS on the site (ISC-8, ISC-9).

The daily epss_curated.json and the weekly shard value are served through
Playwright routes, so the tests hold against any deployment: one without EPSS
data yet, one with it, and the live site.

Run against a local server:
    cd docs && python3 -m http.server 8765 &
    BASE_URL=http://localhost:8765/ .venv/bin/pytest tests/smoke/ --browser chromium
"""

import gzip
import json
import os

from playwright.sync_api import Page, Route, expect

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/",
)

TIMEOUT_MS = 30_000
EPSS_FILE = "**/data/epss_curated.json"
SHARDS = "**/database/CVE-*.jsonl.gz"
INDEX_FILE = "**/data/entity_index.json"
SHARD_ONLY_CVE = "CVE-1999-0095"
CURATED_CVE = "CVE-2023-44487"


def _daily(scores: dict, date: str = "2026-09-26") -> str:
    return json.dumps({
        "meta": {"date": date, "model_version": "v2026.06.15", "total_count": 379842},
        "scores": scores,
    })


def _serve_daily(page: Page, scores: dict, date: str = "2026-09-26") -> None:
    page.route(EPSS_FILE, lambda r: r.fulfill(status=200, content_type="application/json", body=_daily(scores, date)))


def _no_daily(page: Page) -> None:
    page.route(EPSS_FILE, lambda r: r.fulfill(status=404, body="not found"))


def _serve_sources(page: Page, weekly: bool = False) -> None:
    """Serve the real entity index and shards with every EPSS value removed,
    so each test controls both the daily and the weekly value. Deployed data
    carries EPSS since the first weekly run with I1 (2026-09-27), and the site
    rightly prefers the newer of the two, which would otherwise override the
    routed daily fixture. With weekly=True, CVE-1999-0095 gets a weekly
    value dated 2026-09-20 in its shard, and the curated CVE-2023-44487 the
    same value in the entity index, which is where a curated page reads it."""

    def index_handler(route: Route) -> None:
        doc = json.loads(route.fetch().body())
        for entity_id, entity in doc.get("entities", {}).items():
            entity.pop("epss", None)
            if weekly and entity_id == CURATED_CVE:
                entity["epss"] = {"score": 0.1, "percentile": 0.2, "date": "2026-09-20"}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(doc))

    def shard_handler(route: Route) -> None:
        resp = route.fetch()
        lines = []
        for line in gzip.decompress(resp.body()).decode("utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            for cve_id, data in rec.items():
                if isinstance(data, dict):
                    data.pop("EPSS", None)
                    if weekly and cve_id == SHARD_ONLY_CVE:
                        data["EPSS"] = {"score": 0.1, "percentile": 0.2, "date": "2026-09-20"}
            lines.append(json.dumps(rec))
        route.fulfill(status=200, body=gzip.compress(("\n".join(lines) + "\n").encode("utf-8")))

    page.route(INDEX_FILE, index_handler)
    page.route(SHARDS, shard_handler)


def _serve_weekly_shard(page: Page) -> None:
    """Real sources without EPSS, plus a weekly value on CVE-1999-0095."""
    _serve_sources(page, weekly=True)


def _errors(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    return errors


def test_cve_page_shows_daily_epss(page: Page) -> None:
    _serve_sources(page)
    _serve_daily(page, {"CVE-2023-44487": {"score": 0.99999, "percentile": 0.99998}})
    errors = _errors(page)
    page.goto(f"{BASE_URL}#/cve/CVE-2023-44487")
    main = page.locator("#result-main")
    expect(main.locator(".badge-row").first).to_contain_text("EPSS 0.99999", timeout=TIMEOUT_MS)
    expect(main).to_contain_text("99.998th percentile")
    expect(main).to_contain_text("EPSS Score Date")
    expect(main).to_contain_text("2026-09-26 (daily)")
    badge = main.locator(".badge", has_text="EPSS")
    assert "model v2026.06.15" in (badge.get_attribute("title") or "")
    assert errors == []


def test_daily_file_wins_over_weekly_shard_value(page: Page) -> None:
    _serve_weekly_shard(page)
    _serve_daily(page, {SHARD_ONLY_CVE: {"score": 0.5, "percentile": 0.6}})
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    main = page.locator("#result-main")
    expect(main).to_contain_text("EPSS 0.5", timeout=TIMEOUT_MS)
    expect(main).to_contain_text("2026-09-26 (daily)")
    expect(main).not_to_contain_text("2026-09-20")


def test_weekly_shard_value_without_daily_file(page: Page) -> None:
    _serve_weekly_shard(page)
    _no_daily(page)
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    main = page.locator("#result-main")
    expect(main).to_contain_text("EPSS 0.1", timeout=TIMEOUT_MS)
    expect(main).to_contain_text("2026-09-20 (weekly)")


def test_curated_page_reads_weekly_value_from_the_index(page: Page) -> None:
    """A curated CVE takes its weekly EPSS from the entity index, not a shard."""
    _serve_weekly_shard(page)
    _no_daily(page)
    page.goto(f"{BASE_URL}#/cve/{CURATED_CVE}")
    main = page.locator("#result-main")
    expect(main).to_contain_text("EPSS 0.1", timeout=TIMEOUT_MS)
    expect(main).to_contain_text("2026-09-20 (weekly)")


def test_cve_page_renders_without_epss_file(page: Page) -> None:
    _no_daily(page)
    errors = _errors(page)
    page.goto(f"{BASE_URL}#/cve/CVE-2023-44487")
    expect(page.locator("#result-main")).to_contain_text("KEV Date Added", timeout=TIMEOUT_MS)
    expect(page.locator("#result-graph svg")).to_be_visible(timeout=TIMEOUT_MS)
    assert errors == []


def test_worklist_sorts_by_epss_and_shows_score_age(page: Page) -> None:
    """One daily-sourced row and one shard-sourced (weekly) row: the cell shows
    the score date as visible text and marks the weekly one. The clock is fixed
    inside the fixtures' year, so the dates show as MM-DD in any year."""
    page.clock.set_fixed_time("2026-09-27T12:00:00Z")
    _serve_weekly_shard(page)
    _serve_daily(page, {"CVE-1999-0001": {"score": 0.03351, "percentile": 0.88243}})
    page.goto(f"{BASE_URL}#/list/CVE-1999-0001,CVE-1999-0095")
    table = page.locator("#worklist-table table")
    expect(table).to_be_visible(timeout=TIMEOUT_MS)
    header = table.locator("th", has_text="EPSS")
    expect(header).to_have_count(1)
    rows = table.locator("tbody tr")
    first_id = rows.first.locator("td").first

    header.click()  # EPSS, highest first
    expect(first_id).to_have_text(SHARD_ONLY_CVE)
    expect(rows.nth(0).locator("td.worklist-epss")).to_have_text("0.1 · 09-20 weekly")
    expect(rows.nth(1).locator("td.worklist-epss")).to_have_text("0.03351 · 09-26")
    table.locator("th", has_text="EPSS").click()  # ascending
    expect(first_id).to_have_text("CVE-1999-0001")


def test_worklist_epss_date_shows_year_outside_current_year(page: Page) -> None:
    """I16 ISC-6 (I1 review LOW): a score date from another year keeps its year."""
    page.clock.set_fixed_time("2027-01-05T12:00:00Z")
    _serve_weekly_shard(page)
    _serve_daily(page, {"CVE-1999-0001": {"score": 0.03351, "percentile": 0.88243}})
    page.goto(f"{BASE_URL}#/list/CVE-1999-0001,CVE-1999-0095")
    table = page.locator("#worklist-table table")
    expect(table).to_be_visible(timeout=TIMEOUT_MS)
    table.locator("th", has_text="EPSS").click()  # highest first
    rows = table.locator("tbody tr")
    expect(rows.nth(0).locator("td.worklist-epss")).to_have_text("0.1 · 2026-09-20 weekly")
    expect(rows.nth(1).locator("td.worklist-epss")).to_have_text("0.03351 · 2026-09-26")


def test_weekly_value_newer_than_daily_wins(page: Page) -> None:
    """After a --cve-only run the shard can be newer than the daily file."""
    _serve_weekly_shard(page)  # weekly value dated 2026-09-20
    _serve_daily(page, {SHARD_ONLY_CVE: {"score": 0.5, "percentile": 0.6}}, date="2026-09-19")
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    main = page.locator("#result-main")
    expect(main).to_contain_text("EPSS 0.1", timeout=TIMEOUT_MS)
    expect(main).to_contain_text("2026-09-20 (weekly)")


def _ordinal(n: int) -> str:
    if 11 <= n % 100 <= 13:
        return f"{n}th"
    return f"{n}" + {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")


def test_percentile_ordinals(page: Page) -> None:
    page.goto(BASE_URL)
    expect(page.locator("#stats-bar")).not_to_be_empty(timeout=TIMEOUT_MS)
    got = page.evaluate("[...Array(101).keys()].map(i => formatEpssPercentile(i / 100))")
    assert got == [f"{_ordinal(i)} percentile" for i in range(101)]
    assert page.evaluate("formatEpssPercentile(0.99998)") == "99.998th percentile"


def test_failed_daily_fetch_is_not_repeated(page: Page) -> None:
    hits: list[str] = []

    def handler(route: Route) -> None:
        hits.append(route.request.url)
        route.fulfill(status=404, body="not found")

    page.route(EPSS_FILE, handler)
    page.goto(f"{BASE_URL}#/cve/CVE-2023-44487")
    expect(page.locator("#result-main")).to_contain_text("KEV Date Added", timeout=TIMEOUT_MS)
    page.evaluate("() => { window.location.hash = '#/cve/CVE-2021-44228'; }")
    expect(page.locator("#result-main")).to_contain_text("CVE-2021-44228", timeout=TIMEOUT_MS)
    page.evaluate("() => { window.location.hash = '#/cve/CVE-2023-44487'; }")
    expect(page.locator("#result-main")).to_contain_text("KEV Date Added", timeout=TIMEOUT_MS)
    assert len(hits) == 1, hits
