"""Playwright smoke test for the deployed TIP static site.

Runs against the live GitHub Pages deployment by default; point BASE_URL at a
local server to test pre-deploy. Asserts the search-first UI renders a known
KEV CVE (CVE-2023-44487, HTTP/2 Rapid Reset) end to end: severity badge,
description, KEV overview fields, and the relationship graph.

Run:
    .venv/bin/pytest tests/smoke/ --browser chromium
"""

import os

import pytest
from playwright.sync_api import Page, expect

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/",
)

SMOKE_CVE = "CVE-2023-44487"

# The entity index and shards load async after navigation; give the first
# render a generous ceiling so slow Pages cold-starts don't flake the build.
RENDER_TIMEOUT_MS = 30_000


@pytest.fixture()
def results_page(page: Page) -> Page:
    page.goto(f"{BASE_URL}#/cve/{SMOKE_CVE}")
    expect(page.locator("#page-results")).to_be_visible(timeout=RENDER_TIMEOUT_MS)
    return page


def test_landing_page_renders(page: Page) -> None:
    page.goto(BASE_URL)
    expect(page.locator("#landing-search")).to_be_visible(timeout=RENDER_TIMEOUT_MS)
    expect(page.locator("#stats-bar")).not_to_be_empty(timeout=RENDER_TIMEOUT_MS)


def test_cve_detail_shows_identity_and_description(results_page: Page) -> None:
    main = results_page.locator("#result-main")
    expect(main).to_contain_text(SMOKE_CVE, timeout=RENDER_TIMEOUT_MS)
    # Rapid Reset description always mentions the protocol.
    expect(main).to_contain_text("HTTP/2", timeout=RENDER_TIMEOUT_MS)


def test_cve_detail_shows_severity_badge(results_page: Page) -> None:
    badge_row = results_page.locator("#result-main .badge-row")
    expect(badge_row.first).to_be_visible(timeout=RENDER_TIMEOUT_MS)
    expect(badge_row.first).to_contain_text("HIGH", timeout=RENDER_TIMEOUT_MS)


def test_cve_detail_shows_kev_fields(results_page: Page) -> None:
    main = results_page.locator("#result-main")
    expect(main).to_contain_text("KEV Date Added", timeout=RENDER_TIMEOUT_MS)


def test_cve_detail_renders_relationship_graph(results_page: Page) -> None:
    svg = results_page.locator("#result-graph svg")
    expect(svg).to_be_visible(timeout=RENDER_TIMEOUT_MS)
    # At least one node rendered, not just an empty canvas.
    assert svg.locator("circle, g.node").count() >= 1
