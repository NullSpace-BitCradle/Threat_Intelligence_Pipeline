"""Smoke tests for I32 (ISC-7, ISC-9): a CVE to APT group link shows the
ATT&CK object that cites the CVE, on the CVE page and on the group page.
An index from before I32 shows no CVE to group link at all, since those
were technique-overlap guesses.

Attribution is injected into the served index and shard, and the legacy
tests strip it, so every test passes against pre-I32 and I32 data. One test
reads the served data as is and runs only when it carries attribution.

Run against a local server:
    cd docs && python3 -m http.server 8765 &
    BASE_URL=http://localhost:8765/ .venv/bin/pytest tests/smoke/ --browser chromium
"""

import gzip
import json
import os
import re

import pytest
from playwright.sync_api import Page, Route, expect

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/",
)
TIMEOUT_MS = 30_000
CVE = "CVE-2023-44487"
SHARD_ONLY_CVE = "CVE-1999-0095"
GROUP = "G0007"
SOURCE = "MITRE ATT&CK"
CAMPAIGN_PROV = {"source": SOURCE, "tier": "official", "via": "C0051", "via_type": "campaign"}
REL_PROV = {"source": SOURCE, "tier": "official", "via": GROUP, "via_type": "relationship", "via_target": "T1068"}


def _inject(page: Page, attributed: bool) -> None:
    """Link CVE-2023-44487 and G0007 both ways. attributed=True writes the
    I32 shape (official, evidence per link, meta flag); False writes the old
    overlap shape and drops the flag."""

    def handler(route: Route) -> None:
        resp = route.fetch()
        data = json.loads(resp.body())
        ents = data["entities"]
        ents.setdefault(GROUP, {"type": "apt_group", "id": GROUP, "name": "APT28", "phase": "threat_actor",
                                "rels": {}})
        if attributed:
            fwd = {"ids": [GROUP], "source": SOURCE, "tier": "official", "link_prov": {GROUP: CAMPAIGN_PROV}}
            back = {"ids": [CVE], "source": SOURCE, "tier": "official", "link_prov": {CVE: REL_PROV}}
            data["meta"]["apt_attribution"] = True
        else:
            fwd = {"ids": [GROUP], "source": "Pipeline (technique overlap)", "tier": "derived"}
            back = dict(fwd, ids=[CVE])
            data["meta"].pop("apt_attribution", None)
        ents[CVE]["rels"]["apt_group"] = fwd
        ents[GROUP]["rels"]["cve"] = back
        route.fulfill(response=resp, body=json.dumps(data))

    page.route("**/data/entity_index.json", handler)


def _open(page: Page, route: str) -> None:
    page.goto(f"{BASE_URL}#/{route}")
    expect(page.locator("#result-main .detail-tabs")).to_be_visible(timeout=TIMEOUT_MS)


def _card(page: Page, tab: str, eid: str):
    return page.locator(f"#tab-{tab} .entity-card").filter(
        has=page.locator(".entity-card-id", has_text=re.compile(rf"^{re.escape(eid)}$")))


def test_cve_page_shows_the_citing_object(page: Page) -> None:
    _inject(page, attributed=True)
    _open(page, f"cve/{CVE}")
    page.locator(".detail-tab", has_text="APT").click()
    card = _card(page, "apt_group", GROUP)
    badge = card.locator(".cited-badge")
    expect(badge).to_be_visible(timeout=TIMEOUT_MS)
    expect(badge).to_have_text("ATT&CK: C0051")
    assert "campaign C0051" in (badge.get_attribute("title") or "")
    expect(card.locator(".prov-badge")).to_have_text("official")
    # The sidebar carries the same evidence.
    side = page.locator("#result-graph .related-item-tiered .cited-badge")
    expect(side).to_have_text("ATT&CK: C0051")
    # The summary card names the kind of link, not a chain.
    summary = page.locator(".summary-card", has=page.locator(".summary-card-label", has_text="Threat Actors"))
    expect(summary.locator(".summary-card-detail")).to_have_text("1 cited")


def test_group_page_shows_the_citing_relationship(page: Page) -> None:
    _inject(page, attributed=True)
    _open(page, f"apt_group/{GROUP}")
    page.locator(".detail-tab", has_text="CVE").click()
    badge = _card(page, "cve", CVE).locator(".cited-badge")
    expect(badge).to_be_visible(timeout=TIMEOUT_MS)
    expect(badge).to_have_text("ATT&CK: G0007 → T1068")
    assert "relationship from G0007 to T1068" in (badge.get_attribute("title") or "")


def test_legacy_index_shows_no_cve_to_group_link(page: Page) -> None:
    _inject(page, attributed=False)
    _open(page, f"cve/{CVE}")
    page.wait_for_timeout(300)
    assert page.locator(".detail-tab", has_text="APT").count() == 0
    assert page.locator(f"#result-graph .related-item:has-text('{GROUP}')").count() == 0
    assert page.locator(".cited-badge").count() == 0
    _open(page, f"apt_group/{GROUP}")
    page.wait_for_timeout(300)
    assert page.locator(".detail-tab", has_text="CVE").count() == 0
    # The group's official technique links still render.
    expect(page.locator(".detail-tab", has_text="Technique")).to_be_visible()


def _serve_shard(page: Page, groups: list) -> None:
    def handler(route: Route) -> None:
        resp = route.fetch()
        out = []
        for line in gzip.decompress(resp.body()).decode("utf-8").splitlines():
            rec = json.loads(line) if line.strip() else None
            if rec and SHARD_ONLY_CVE in rec:
                rec[SHARD_ONLY_CVE]["APT_GROUPS"] = groups
                line = json.dumps(rec)
            out.append(line)
        route.fulfill(response=resp, body=gzip.compress("\n".join(out).encode("utf-8")))

    page.route("**/database/CVE-1999.jsonl.gz", handler)


def test_shard_page_shows_attributed_groups_only(page: Page) -> None:
    _serve_shard(page, [
        {"id": GROUP, "name": "APT28", "via": GROUP, "via_type": "intrusion-set"},
        {"id": "G0016", "name": "APT29", "aliases": [], "techniques_overlap": ["T1190"]},
        "G0019",
    ])
    _open(page, f"cve/{SHARD_ONLY_CVE}")
    page.locator(".detail-tab", has_text="APT").click()
    cards = page.locator("#tab-apt_group .entity-card")
    expect(cards).to_have_count(1, timeout=TIMEOUT_MS)
    expect(_card(page, "apt_group", GROUP).locator(".cited-badge")).to_have_text("ATT&CK: G0007")


def test_served_attribution_renders_when_present(page: Page) -> None:
    """Against regenerated data: the first CVE with an attributed group shows
    its evidence on the CVE page and on the group page. Skipped on data
    generated before I32."""
    data = page.request.get(f"{BASE_URL}data/entity_index.json").json()
    if not data.get("meta", {}).get("apt_attribution"):
        pytest.skip("served index predates I32")
    target = gid = None
    for eid, ent in sorted(data["entities"].items()):
        prov = ((ent.get("rels") or {}).get("apt_group") or {}).get("link_prov") or {}
        if ent.get("type") == "cve" and prov:
            target, gid = eid, sorted(prov)[0]
            break
    if target is None:
        pytest.skip("served index has no attributed CVE")
    via = data["entities"][target]["rels"]["apt_group"]["link_prov"][gid]["via"]
    _open(page, f"cve/{target}")
    page.locator(".detail-tab", has_text="APT").click()
    expect(_card(page, "apt_group", gid).locator(".cited-badge")).to_contain_text(via, timeout=TIMEOUT_MS)
    _open(page, f"apt_group/{gid}")
    page.locator(".detail-tab", has_text="CVE").click()
    expect(_card(page, "cve", target).locator(".cited-badge")).to_contain_text(via, timeout=TIMEOUT_MS)
    # No group page lists a CVE without evidence.
    for body in (data["entities"][gid]["rels"].get("cve"),):
        assert body and set(body["ids"]) == set(body.get("link_prov") or {})
