"""Smoke tests: the daily KEV catalog decides KEV status on the site.

Audit 2026-11-18 H1. A CVE CISA adds between weekly runs is in the daily
kev_db.json but not yet in its shard record or the curated graph, so the
CVE page and the worklist showed it as not in KEV for up to a week. The site
now reads kev_db.json on both paths (pickKev in entity-system.js), as the
MCP does, and falls back to the weekly value only when the file fails.

kev_db.json and the shard are served through Playwright routes, so the tests
hold against any deployment.

Run against a local server:
    cd docs && python3 -m http.server 8765 &
    BASE_URL=http://localhost:8765/ .venv/bin/pytest tests/smoke/ --browser chromium
"""

import gzip
import json
import os
import re

from playwright.sync_api import Page, Route, expect

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/",
)

TIMEOUT_MS = 30_000
KEV_FILE = "**/data/kev_db.json"
SHARD_1999 = "**/database/CVE-1999.jsonl.gz"
SHARD_ONLY_CVE = "CVE-1999-0095"   # in its shard, not in the curated graph, not in KEV
CURATED_KEV_CVE = "CVE-2023-44487"  # curated and in KEV

NEW_ENTRY = {
    "inKEV": True,
    "dateAdded": "2026-11-17",
    "dueDate": "2026-12-08",
    "knownRansomwareCampaignUse": "Known",
    "requiredAction": "Apply mitigations per vendor instructions.",
    "vendorProject": "Eric Allman",
    "product": "Sendmail",
}


def _kev_badge(page: Page):
    return page.locator("#result-main .badge", has_text=re.compile(r"^KEV$"))


def _serve_kev(page: Page, add: dict | None = None, drop: tuple[str, ...] = ()) -> None:
    """The deployed kev_db.json with entries added or removed."""

    def handler(route: Route) -> None:
        doc = json.loads(route.fetch().body())
        for cve_id in drop:
            doc.pop(cve_id, None)
        doc.update(add or {})
        route.fulfill(status=200, content_type="application/json", body=json.dumps(doc))

    page.route(KEV_FILE, handler)


def _shard_with_kev(page: Page) -> None:
    """The 1999 shard with a weekly KEV block on the shard-only CVE."""

    def handler(route: Route) -> None:
        lines = []
        for line in gzip.decompress(route.fetch().body()).decode("utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if SHARD_ONLY_CVE in rec:
                rec[SHARD_ONLY_CVE]["KEV"] = dict(NEW_ENTRY, dateAdded="2026-11-01")
            lines.append(json.dumps(rec))
        route.fulfill(status=200, body=gzip.compress(("\n".join(lines) + "\n").encode("utf-8")))

    page.route(SHARD_1999, handler)


def _errors(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    return errors


def test_cve_listed_since_the_weekly_run_shows_kev_on_its_page(page: Page) -> None:
    _serve_kev(page, add={SHARD_ONLY_CVE: NEW_ENTRY})
    errors = _errors(page)
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    main = page.locator("#result-main")
    expect(main).to_contain_text("Loaded on demand from CVE shard", timeout=TIMEOUT_MS)
    expect(_kev_badge(page)).to_have_count(1)
    assert "2026-12-08" in (_kev_badge(page).get_attribute("title") or "")
    expect(main).to_contain_text("Ransomware")
    assert errors == []


def test_cve_listed_since_the_weekly_run_shows_kev_in_the_worklist(page: Page) -> None:
    _serve_kev(page, add={SHARD_ONLY_CVE: NEW_ENTRY})
    page.goto(f"{BASE_URL}#/list/{SHARD_ONLY_CVE}")
    table = page.locator("#worklist-table")
    expect(table.locator(".worklist-summary")).to_contain_text("1 in KEV", timeout=TIMEOUT_MS)
    row = table.locator("tbody tr").first
    expect(row).to_contain_text("KEV")
    expect(row).to_contain_text("2026-12-08")


def test_daily_catalog_wins_over_a_weekly_kev_block(page: Page) -> None:
    """A CVE the daily catalog does not list is not in KEV, whatever the
    weekly shard says; with the catalog listing it, its entry is shown."""
    _shard_with_kev(page)
    _serve_kev(page)  # the deployed catalog, which does not list it
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    expect(page.locator("#result-main")).to_contain_text("Loaded on demand", timeout=TIMEOUT_MS)
    expect(_kev_badge(page)).to_have_count(0)


def test_weekly_kev_block_stands_when_the_catalog_fails(page: Page) -> None:
    _shard_with_kev(page)
    page.route(KEV_FILE, lambda r: r.fulfill(status=404, body="not found"))
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    expect(page.locator("#result-main")).to_contain_text("Loaded on demand", timeout=TIMEOUT_MS)
    expect(_kev_badge(page)).to_have_count(1)
    expect(page.locator("#result-main")).to_contain_text("2026-11-01")


def test_curated_cve_follows_the_daily_catalog(page: Page) -> None:
    page.goto(f"{BASE_URL}#/cve/{CURATED_KEV_CVE}")
    expect(_kev_badge(page)).to_have_count(1, timeout=TIMEOUT_MS)

    fresh = page.context.new_page()
    _serve_kev(fresh, drop=(CURATED_KEV_CVE,))
    fresh.goto(f"{BASE_URL}#/cve/{CURATED_KEV_CVE}")
    expect(fresh.locator("#result-main")).to_contain_text(CURATED_KEV_CVE, timeout=TIMEOUT_MS)
    fresh.wait_for_function("() => kevDb !== null", timeout=TIMEOUT_MS)
    expect(fresh.locator("#result-main .badge", has_text=re.compile(r"^KEV$"))).to_have_count(0)
