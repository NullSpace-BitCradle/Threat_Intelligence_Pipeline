"""Smoke tests: a D3FEND entity links to a D3FEND page that exists.

Audit 2026-11-18 M2. The link was built from the D3 ID
(https://d3fend.mitre.org/technique/d3f:D3-SCF/), which D3FEND answers with
a 404; its pages are keyed by the ontology fragment
(d3f:SystemCallFiltering). The entity index now carries d3fend_fragment on
D3FEND entities; an index from before that links to the D3FEND home page.

The entity index is served through a Playwright route, so the tests hold
against any deployment.

Run against a local server:
    cd docs && python3 -m http.server 8765 &
    BASE_URL=http://localhost:8765/ .venv/bin/pytest tests/smoke/ --browser chromium
"""

import json
import os

from playwright.sync_api import Page, Route

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/",
)

TIMEOUT_MS = 30_000
INDEX_FILE = "**/data/entity_index.json"
DEFEND_ID = "D3-SCF"


def _serve_index(page: Page, fragment: str | None) -> None:
    def handler(route: Route) -> None:
        doc = json.loads(route.fetch().body())
        entity = doc["entities"][DEFEND_ID]
        entity.pop("d3fend_fragment", None)
        if fragment is not None:
            entity["d3fend_fragment"] = fragment
        route.fulfill(status=200, content_type="application/json", body=json.dumps(doc))

    page.route(INDEX_FILE, handler)


def _source_link(page: Page) -> str:
    link = page.locator("#result-main .entity-id a")
    link.wait_for(timeout=TIMEOUT_MS)
    return link.get_attribute("href") or ""


def test_defend_entity_links_by_fragment(page: Page) -> None:
    _serve_index(page, "SystemCallFiltering")
    page.goto(f"{BASE_URL}#/defend/{DEFEND_ID}")
    assert _source_link(page) == "https://d3fend.mitre.org/technique/d3f:SystemCallFiltering/"


def test_defend_entity_without_fragment_links_to_the_d3fend_home(page: Page) -> None:
    _serve_index(page, None)
    page.goto(f"{BASE_URL}#/defend/{DEFEND_ID}")
    href = _source_link(page)
    assert href == "https://d3fend.mitre.org/"
    assert "D3-" not in href


def test_hyphenated_fragment_links(page: Page) -> None:
    """11 of the 147 fragments carry a hyphen, e.g. Multi-factorAuthentication."""
    _serve_index(page, "Multi-factorAuthentication")
    page.goto(f"{BASE_URL}#/defend/{DEFEND_ID}")
    assert _source_link(page) == "https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication/"


def test_odd_fragment_is_not_put_in_the_url(page: Page) -> None:
    _serve_index(page, "../../evil?x=1")
    page.goto(f"{BASE_URL}#/defend/{DEFEND_ID}")
    assert _source_link(page) == "https://d3fend.mitre.org/"
