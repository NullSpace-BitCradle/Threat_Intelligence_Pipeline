"""Smoke tests for I29 (ISC-15 to ISC-17): a CVE page separates NVD-assigned
CWEs from inherited parents and marks links reached only through a parent.

The published data predates I29, so the inherited fields are injected into
the served index and shard; the unmodified data is the legacy case.

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
CVE = "CVE-2023-44487"
SHARD_ONLY_CVE = "CVE-1999-0095"


def _inject_index(page: Page) -> str:
    """Serve the real index with CVE-2023-44487 rewritten to I29 shape: CWE-400
    assigned, CWE-664 inherited, one technique reached only through it.
    Returns that technique id."""
    picked: dict = {}

    def handler(route: Route) -> None:
        resp = route.fetch()
        data = json.loads(resp.body())
        ent = data["entities"][CVE]
        ent["rels"]["cwe"]["ids"] = ["CWE-400"]
        ent["cwe_inherited"] = ["CWE-664"]
        tech = ent["rels"]["technique"]
        tech["inherited"] = [tech["ids"][0]]
        picked["tech"] = tech["ids"][0]
        data["meta"]["inherited_links"] = True
        route.fulfill(response=resp, body=json.dumps(data))

    page.route("**/data/entity_index.json", handler)
    page.goto(f"{BASE_URL}#/cve/{CVE}")
    expect(page.locator("#result-main")).to_contain_text("HTTP/2", timeout=TIMEOUT_MS)
    return picked["tech"]


def test_isc15_cve_page_lists_assigned_and_inherited_cwes_apart(page: Page) -> None:
    _inject_index(page)
    assigned = page.locator('[data-cwe-section="assigned"]')
    inherited = page.locator('[data-cwe-section="inherited"]')
    expect(assigned).to_contain_text("assigned by NVD", timeout=TIMEOUT_MS)
    expect(assigned).to_contain_text("CWE-400")
    expect(assigned).not_to_contain_text("CWE-664")
    expect(inherited).to_contain_text("Inherited parent weaknesses")
    expect(inherited).to_contain_text("CWE-664")
    assert "NVD did not assign" in (inherited.locator(".inherited-chip").first.get_attribute("title") or "")


def test_isc16_inherited_link_has_marker_and_tooltip_naming_parent(page: Page) -> None:
    tech = _inject_index(page)
    page.locator(".detail-tab", has_text="Technique").click()
    panel = page.locator("#tab-technique")
    card = panel.locator(".entity-card", has_text=tech).first
    badge = card.locator(".inherited-badge")
    expect(badge).to_be_visible(timeout=TIMEOUT_MS)
    expect(badge).to_have_text("inherited")
    assert "CWE-664" in (badge.get_attribute("title") or "")
    # Only the one inherited technique is marked.
    assert panel.locator(".inherited-badge").count() == 1


def test_isc16_shard_page_marks_inherited_lists(page: Page) -> None:
    def handler(route: Route) -> None:
        resp = route.fetch()
        lines = gzip.decompress(resp.body()).decode("utf-8").splitlines()
        out = []
        for line in lines:
            rec = json.loads(line) if line.strip() else None
            if rec and SHARD_ONLY_CVE in rec:
                payload = rec[SHARD_ONLY_CVE]
                payload["CWE_INHERITED"] = ["CWE-74"]
                payload["TECHNIQUES_INHERITED"] = ["1059"]
                line = json.dumps(rec)
            out.append(line)
        route.fulfill(response=resp, body=gzip.compress("\n".join(out).encode("utf-8")))

    page.route("**/database/CVE-1999.jsonl.gz", handler)
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    expect(page.locator("#result-main")).to_contain_text("Sendmail", timeout=TIMEOUT_MS)
    expect(page.locator('[data-cwe-section="inherited"]')).to_contain_text("CWE-74")
    page.locator(".detail-tab", has_text="Technique").click()
    badge = page.locator("#tab-technique .entity-card", has_text="T1059").locator(".inherited-badge")
    expect(badge).to_be_visible(timeout=TIMEOUT_MS)
    assert "CWE-74" in (badge.get_attribute("title") or "")


def test_isc17_legacy_data_renders_without_markers(page: Page) -> None:
    for target in (CVE, SHARD_ONLY_CVE):
        page.goto(f"{BASE_URL}#/cve/{target}")
        expect(page.locator("#result-main .detail-tabs")).to_be_visible(timeout=TIMEOUT_MS)
        page.wait_for_timeout(300)
        assert page.locator(".inherited-badge").count() == 0
        assert page.locator("[data-cwe-section]").count() == 0
        assert page.locator(".entity-card-inherited, .inherited-chip").count() == 0
