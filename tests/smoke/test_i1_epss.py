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
SHARD_1999 = "**/database/CVE-1999.jsonl.gz"
SHARD_ONLY_CVE = "CVE-1999-0095"


def _daily(scores: dict, date: str = "2026-09-26") -> str:
    return json.dumps({
        "meta": {"date": date, "model_version": "v2026.06.15", "total_count": 379842},
        "scores": scores,
    })


def _serve_daily(page: Page, scores: dict, date: str = "2026-09-26") -> None:
    page.route(EPSS_FILE, lambda r: r.fulfill(status=200, content_type="application/json", body=_daily(scores, date)))


def _no_daily(page: Page) -> None:
    page.route(EPSS_FILE, lambda r: r.fulfill(status=404, body="not found"))


def _serve_weekly_shard(page: Page) -> None:
    """The real 1999 shard with a weekly EPSS value on CVE-1999-0095."""

    def handler(route: Route) -> None:
        resp = route.fetch()
        lines = []
        for line in gzip.decompress(resp.body()).decode("utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if SHARD_ONLY_CVE in rec:
                rec[SHARD_ONLY_CVE]["EPSS"] = {"score": 0.1, "percentile": 0.2, "date": "2026-09-20"}
            lines.append(json.dumps(rec))
        route.fulfill(status=200, body=gzip.compress(("\n".join(lines) + "\n").encode("utf-8")))

    page.route(SHARD_1999, handler)


def _errors(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    return errors


def test_cve_page_shows_daily_epss(page: Page) -> None:
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


def test_cve_page_renders_without_epss_file(page: Page) -> None:
    _no_daily(page)
    errors = _errors(page)
    page.goto(f"{BASE_URL}#/cve/CVE-2023-44487")
    expect(page.locator("#result-main")).to_contain_text("KEV Date Added", timeout=TIMEOUT_MS)
    expect(page.locator("#result-graph svg")).to_be_visible(timeout=TIMEOUT_MS)
    assert errors == []


def test_worklist_sorts_by_epss_and_shows_score_age(page: Page) -> None:
    """One daily-sourced row and one shard-sourced (weekly) row: the cell shows
    the score date as visible text and marks the weekly one."""
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
