"""Smoke tests: a rejected CVE carries a Rejected badge (audit 2026-11-18 L1).

The shard is served through a Playwright route that sets VULN_STATUS on a
shard-only CVE, so the tests hold against any deployment, including one whose
shards predate the field.

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
SHARD_1999 = "**/database/CVE-1999.jsonl.gz"
SHARD_ONLY_CVE = "CVE-1999-0095"


def _shard_with_status(page: Page, status: str | None) -> None:
    def handler(route: Route) -> None:
        lines = []
        for line in gzip.decompress(route.fetch().body()).decode("utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if SHARD_ONLY_CVE in rec:
                rec[SHARD_ONLY_CVE].pop("VULN_STATUS", None)
                if status is not None:
                    rec[SHARD_ONLY_CVE]["VULN_STATUS"] = status
            lines.append(json.dumps(rec))
        route.fulfill(status=200, body=gzip.compress(("\n".join(lines) + "\n").encode("utf-8")))

    page.route(SHARD_1999, handler)


def test_rejected_cve_shows_the_badge(page: Page) -> None:
    _shard_with_status(page, "Rejected")
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    badge = page.locator("#result-main .badge-rejected")
    expect(badge).to_have_text("Rejected", timeout=TIMEOUT_MS)


def test_analyzed_cve_has_no_badge(page: Page) -> None:
    _shard_with_status(page, "Analyzed")
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    expect(page.locator("#result-main")).to_contain_text("Loaded on demand", timeout=TIMEOUT_MS)
    expect(page.locator("#result-main .badge-rejected")).to_have_count(0)
