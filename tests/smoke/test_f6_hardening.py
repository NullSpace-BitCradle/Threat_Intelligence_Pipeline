"""Smoke tests for the F6 frontend hardening (ISC-40 to ISC-46).

Covers the search route, malformed hash handling, corrupt localStorage,
index and shard fetch failures, the stale-render generation token, the
worklist cap and single build, and the Content Security Policy.

Run against a local server:
    cd docs && python3 -m http.server 8765 &
    BASE_URL=http://localhost:8765/ .venv/bin/pytest tests/smoke/ --browser chromium
"""

import json
import os

import pytest
from playwright.sync_api import Page, Route, expect

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/",
)

TIMEOUT_MS = 30_000

# A CVE that is in the 1999 shard but not in the curated entity_index, so
# its page is rendered from the shard (the smallest shard, fast to load).
SHARD_ONLY_CVE = "CVE-1999-0095"
SHARD_1999 = "**/database/CVE-1999.jsonl.gz"


def _collect_page_errors(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    return errors


def _wait_for_index(page: Page) -> None:
    expect(page.locator("#stats-bar")).not_to_be_empty(timeout=TIMEOUT_MS)


# ISC-40 ---------------------------------------------------------------


def test_search_route_renders_results_page(page: Page) -> None:
    page.goto(f"{BASE_URL}#/search/apache")
    expect(page.locator("#page-search-results")).to_be_visible(timeout=TIMEOUT_MS)
    body = page.locator("#search-results-body")
    expect(body).to_contain_text('Results for "apache"', timeout=TIMEOUT_MS)
    expect(body).not_to_contain_text("Entity not found")
    assert body.locator(".entity-card").count() >= 2


def test_enter_on_multi_result_query_opens_search_page(page: Page) -> None:
    page.goto(BASE_URL)
    _wait_for_index(page)
    page.locator("#landing-search").fill("apache")
    page.locator("#landing-search").press("Enter")
    expect(page).to_have_url(f"{BASE_URL}#/search/apache", timeout=TIMEOUT_MS)
    expect(page.locator("#page-search-results")).to_be_visible(timeout=TIMEOUT_MS)
    expect(page.locator("#search-results-body")).to_contain_text("Results for")


# ISC-43 ---------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_hash",
    ["#/cve/%E0%A4%A", "#/search/%E0%A4%A", "#/list/%E0%A4%A", "#/cwe/%"],
)
def test_malformed_percent_encoding_does_not_throw(page: Page, bad_hash: str) -> None:
    errors = _collect_page_errors(page)
    page.goto(BASE_URL)
    _wait_for_index(page)
    page.evaluate("h => { window.location.hash = h; }", bad_hash)
    page.wait_for_timeout(500)
    assert errors == []
    # Routing still works after the bad hash.
    page.evaluate("() => { window.location.hash = '#/cwe/CWE-79'; }")
    expect(page.locator("#result-main")).to_contain_text("CWE-79", timeout=TIMEOUT_MS)
    assert errors == []


def test_malformed_hash_on_initial_load(page: Page) -> None:
    errors = _collect_page_errors(page)
    page.goto(f"{BASE_URL}#/cve/%E0%A4%A")
    expect(page.locator("#page-results")).to_be_visible(timeout=TIMEOUT_MS)
    expect(page.locator("#result-main")).to_contain_text("%E0%A4%A", timeout=TIMEOUT_MS)
    assert errors == []


@pytest.mark.parametrize(
    "pinned,theme",
    [
        ("{not json", "garbage"),
        ('{"a": 1}', ""),
        ("[1, null, {}]", "dark; x"),
        ("null", "light"),
    ],
)
def test_corrupt_local_storage_does_not_blank_app(page: Page, pinned: str, theme: str) -> None:
    errors = _collect_page_errors(page)
    page.add_init_script(
        "try { localStorage.setItem('tip-pinned', %s);"
        " localStorage.setItem('tip-theme', %s); } catch (e) {}"
        % (json.dumps(pinned), json.dumps(theme))
    )
    page.goto(BASE_URL)
    expect(page.locator("#landing-search")).to_be_visible(timeout=TIMEOUT_MS)
    expect(page.locator("#stats-bar")).to_contain_text("entities indexed", timeout=TIMEOUT_MS)
    expect(page.locator("#pin-count")).to_have_text("0")
    assert page.evaluate("document.documentElement.getAttribute('data-theme')") in ("dark", "light")
    assert errors == []


# ISC-46 ---------------------------------------------------------------


def test_entity_index_failure_shows_error_state(page: Page) -> None:
    page.route("**/data/entity_index.json", lambda r: r.fulfill(status=500, body="boom"))
    page.goto(BASE_URL)
    stats = page.locator("#stats-bar")
    expect(stats).to_contain_text("Could not load the entity index", timeout=TIMEOUT_MS)
    expect(stats).not_to_contain_text("entities indexed")
    page.evaluate("() => { window.location.hash = '#/cwe/CWE-79'; }")
    main = page.locator("#result-main")
    expect(main).to_contain_text("Could not load the entity index", timeout=TIMEOUT_MS)
    expect(main).not_to_contain_text("Entity not found")


@pytest.mark.parametrize("mode", ["http500", "abort"])
def test_shard_failure_shows_error_not_not_found(page: Page, mode: str) -> None:
    def handler(route: Route) -> None:
        if mode == "abort":
            route.abort()
        else:
            route.fulfill(status=500, body="boom")

    page.route(SHARD_1999, handler)
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    main = page.locator("#result-main")
    expect(main).to_contain_text(f"Could not load {SHARD_ONLY_CVE}", timeout=TIMEOUT_MS)
    expect(main).not_to_contain_text("not found in any CVE shard")


def test_shard_failure_marks_worklist_row_as_load_failed(page: Page) -> None:
    page.route(SHARD_1999, lambda r: r.fulfill(status=503, body="down"))
    page.goto(f"{BASE_URL}#/list/{SHARD_ONLY_CVE},CWE-79")
    table = page.locator("#worklist-table")
    expect(table).to_contain_text("load failed", timeout=TIMEOUT_MS)
    expect(page.locator("#worklist-status")).to_contain_text("could not be loaded")


def test_shard_only_cve_still_renders(page: Page) -> None:
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    main = page.locator("#result-main")
    expect(main).to_contain_text("Sendmail", timeout=TIMEOUT_MS)


# ISC-44 ---------------------------------------------------------------


def test_stale_shard_render_does_not_overwrite_newer_page(page: Page) -> None:
    held: list[Route] = []
    page.route(SHARD_1999, lambda r: held.append(r))
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    main = page.locator("#result-main")
    expect(main).to_contain_text("Loading", timeout=TIMEOUT_MS)
    for _ in range(100):
        if held:
            break
        page.wait_for_timeout(100)
    assert held, "shard request was never issued"

    # Navigate on while the shard is still in flight.
    page.evaluate("() => { window.location.hash = '#/cwe/CWE-79'; }")
    expect(main).to_contain_text("CWE-79", timeout=TIMEOUT_MS)

    # Now let the slow shard land and give the stale render time to run.
    held[0].continue_()
    page.wait_for_function("() => shardCache.has('1999')", timeout=TIMEOUT_MS)
    page.wait_for_timeout(500)
    expect(main).to_contain_text("CWE-79")
    expect(main).not_to_contain_text(SHARD_ONLY_CVE)


# ISC-45 ---------------------------------------------------------------


def test_worklist_caps_at_25_and_says_so(page: Page) -> None:
    ids = ",".join(f"CWE-{n}" for n in range(1, 31))
    page.goto(f"{BASE_URL}#/list/{ids}")
    status = page.locator("#worklist-status")
    expect(status).to_contain_text("capped at 25", timeout=TIMEOUT_MS)
    expect(status).to_contain_text("first 25 of 30")
    expect(page.locator("#worklist-table .worklist-summary")).to_contain_text("25 entities")
    assert page.locator("#worklist-table tbody tr").count() == 25
    # The shareable URL carries only the capped cohort.
    decoded = page.evaluate("decodeURIComponent(location.hash)")
    assert decoded.count("CWE-") == 25


def test_worklist_build_runs_once(page: Page) -> None:
    page.goto(f"{BASE_URL}#/list")
    _wait_for_index(page)
    expect(page.locator("#page-worklist")).to_be_visible(timeout=TIMEOUT_MS)
    page.evaluate(
        """() => {
            window.__resolveCalls = 0;
            const orig = window.resolveWorklistRow;
            window.resolveWorklistRow = function(id) {
                window.__resolveCalls += 1;
                return orig(id);
            };
        }"""
    )
    page.locator("#worklist-input").fill("CWE-79 CWE-89")
    page.locator("#worklist-build").click()
    expect(page.locator("#worklist-table tbody tr")).to_have_count(2, timeout=TIMEOUT_MS)
    page.wait_for_timeout(500)
    assert page.evaluate("window.__resolveCalls") == 2
    assert "CWE-79" in page.evaluate("decodeURIComponent(location.hash)")
    # The textarea keeps what the user typed.
    assert page.locator("#worklist-input").input_value() == "CWE-79 CWE-89"


# ISC-41 / ISC-42 --------------------------------------------------------


def test_csp_present_and_no_violations(page: Page) -> None:
    console: list[str] = []
    page.on("console", lambda m: console.append(m.text))
    page.add_init_script(
        "window.__csp = []; document.addEventListener('securitypolicyviolation',"
        " e => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));"
    )
    page.goto(BASE_URL)
    _wait_for_index(page)

    csp = page.locator('meta[http-equiv="Content-Security-Policy"]').get_attribute("content")
    assert csp is not None and "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert page.evaluate("typeof d3") == "object"
    assert page.evaluate("d3.version") == "7.9.0"
    scripts = page.evaluate("[...document.scripts].map(s => s.src)")
    assert all(s.startswith(BASE_URL) for s in scripts), scripts

    for route in ["#/cve/CVE-2023-44487", f"#/cve/{SHARD_ONLY_CVE}", "#/search/apache", "#/list/CWE-79,T1059"]:
        page.evaluate("h => { window.location.hash = h; }", route)
        page.wait_for_timeout(1500)
    expect(page.locator("#page-worklist")).to_be_visible()
    page.evaluate("() => { window.location.hash = '#/cve/CVE-2023-44487'; }")
    expect(page.locator("#result-graph svg")).to_be_visible(timeout=TIMEOUT_MS)

    violations = page.evaluate("window.__csp")
    csp_console = [m for m in console if "Content Security Policy" in m or "Refused to" in m]
    assert violations == [], violations
    assert csp_console == [], csp_console
