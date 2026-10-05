"""T10.8 F4: a shard-served CVE page lists the shard's D3FEND defenses, with
inherited ones marked like the other inherited lists.

Run against a local server:
    cd docs && python3 -m http.server 8765 &
    BASE_URL=http://localhost:8765/ .venv/bin/pytest tests/smoke/test_t10_8_shard_defenses.py --browser chromium
"""

import os

from playwright.sync_api import Page, expect

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/",
)
TIMEOUT_MS = 30_000
SHARD_ONLY_CVE = "CVE-1999-0002"


def test_f4_shard_cve_page_lists_defenses_with_inherited_marked(page: Page) -> None:
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    expect(page.locator("#result-main .detail-tabs")).to_be_visible(timeout=TIMEOUT_MS)
    page.locator(".detail-tab", has_text="D3FEND").click()
    panel = page.locator("#tab-defend")
    cards = panel.locator(".entity-card")
    expect(cards.first).to_be_visible(timeout=TIMEOUT_MS)
    assert cards.count() >= 25
    expect(panel).to_contain_text("D3-ANCI")
    # Every shard defense for this CVE is inherited, so each card is marked.
    assert panel.locator(".inherited-badge").count() == cards.count()
