"""Smoke tests for I21 (ISC-10): a CVE page marks technique links from MITRE
CTID (official, the analyst comment on hover) and inferred links (the rule on
hover) apart from chain and inherited links. Legacy data renders unmarked.

The I21 fields are injected into the served index and shard, and the legacy
test strips them, so every test passes against pre-I21 and I21 data. One
test reads the served data as is and runs only when it has CTID links.

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
CTID_SOURCE = "MITRE CTID Mappings Explorer (KEV)"
COMMENT = "Exploited by opening and resetting many HTTP/2 streams."
INFERRED_SOURCE = "TIP inference from the CVSS vector (AV:N and UI:N: T1190 Exploit Public-Facing Application)"
CTID_TECH = "T1499.004"
INFERRED_TECH = "T1190"


def _ensure_tech(data: dict, tid: str) -> None:
    data["entities"].setdefault(tid, {"type": "technique", "id": tid, "name": tid, "phase": "attack", "rels": {}})


def _inject_index(page: Page) -> None:
    """Rewrite CVE-2023-44487: one CTID technique and one inferred one, with
    per-link provenance, whatever the served index holds."""

    def handler(route: Route) -> None:
        resp = route.fetch()
        data = json.loads(resp.body())
        ent = data["entities"][CVE]
        for tid in (CTID_TECH, INFERRED_TECH):
            _ensure_tech(data, tid)
        tech = ent["rels"].setdefault("technique", {"ids": [], "source": "chain", "tier": "derived"})
        # First, so the graph and the sidebar (which show a few per type)
        # include them.
        tech["ids"] = [CTID_TECH, INFERRED_TECH] + [t for t in tech["ids"] if t not in (CTID_TECH, INFERRED_TECH)]
        tech["inherited"] = [t for t in tech.get("inherited", []) if t not in (CTID_TECH, INFERRED_TECH)]
        tech["link_prov"] = {
            CTID_TECH: {"source": CTID_SOURCE, "tier": "official",
                        "mapping_type": ["exploitation_technique"], "comment": COMMENT},
            INFERRED_TECH: {"source": INFERRED_SOURCE, "tier": "inferred", "rule": "network-no-interaction"},
        }
        # A clean control: no other rel of this CVE carries per-link
        # provenance, whatever the served index holds.
        for rel_type, body in ent["rels"].items():
            if rel_type != "technique" and isinstance(body, dict):
                body.pop("link_prov", None)
        data["meta"]["link_provenance"] = True
        route.fulfill(response=resp, body=json.dumps(data))

    page.route("**/data/entity_index.json", handler)
    page.goto(f"{BASE_URL}#/cve/{CVE}")
    expect(page.locator("#result-main")).to_contain_text("HTTP/2", timeout=TIMEOUT_MS)


def _card(page: Page, tid: str):
    panel = page.locator("#tab-technique")
    return panel.locator(".entity-card").filter(
        has=page.locator(".entity-card-id", has_text=re.compile(rf"^{re.escape(tid)}$")))


def test_ctid_link_has_marker_with_analyst_comment(page: Page) -> None:
    _inject_index(page)
    page.locator(".detail-tab", has_text="Technique").click()
    badge = _card(page, CTID_TECH).locator(".ctid-badge")
    expect(badge).to_be_visible(timeout=TIMEOUT_MS)
    expect(badge).to_have_text("CTID")
    title = badge.get_attribute("title") or ""
    assert COMMENT in title and "exploitation technique" in title, title
    expect(_card(page, CTID_TECH).locator(".prov-badge")).to_have_text("official")
    assert page.locator("#tab-technique .ctid-badge").count() == 1


def test_inferred_link_has_marker_naming_its_rule(page: Page) -> None:
    _inject_index(page)
    page.locator(".detail-tab", has_text="Technique").click()
    badge = _card(page, INFERRED_TECH).locator(".inferred-badge")
    expect(badge).to_be_visible(timeout=TIMEOUT_MS)
    expect(badge).to_have_text("inferred")
    title = badge.get_attribute("title") or ""
    assert "AV:N and UI:N" in title and "not a sourced mapping" in title, title
    expect(_card(page, INFERRED_TECH).locator(".prov-badge")).to_have_text("inferred")
    assert page.locator("#tab-technique .inferred-badge").count() == 1


def test_chain_links_stay_unmarked(page: Page) -> None:
    _inject_index(page)
    page.locator(".detail-tab", has_text="Technique").click()
    cards = page.locator("#tab-technique .entity-card")
    expect(cards.first).to_be_visible(timeout=TIMEOUT_MS)
    marked = page.locator("#tab-technique .ctid-badge, #tab-technique .inferred-badge")
    assert marked.count() == 2
    for i in range(cards.count()):
        card = cards.nth(i)
        cid = card.locator(".entity-card-id").text_content()
        if cid not in (CTID_TECH, INFERRED_TECH):
            assert card.locator(".ctid-badge, .inferred-badge").count() == 0, cid


def test_graph_and_sidebar_and_counts_mark_the_tiers(page: Page) -> None:
    _inject_index(page)
    ctid_node = page.locator(".graph-container svg g.graph-node-ctid")
    inferred_node = page.locator(".graph-container svg g.graph-node-inferred")
    expect(ctid_node).to_have_count(1, timeout=TIMEOUT_MS)
    expect(inferred_node).to_have_count(1)
    assert "MITRE CTID analyst mapping" in (ctid_node.first.locator("title").text_content() or "")
    assert "inferred from the CVSS vector" in (inferred_node.first.locator("title").text_content() or "")
    header = page.locator("#result-main .badge", has_text="1 CTID, 1 inferred")
    expect(header).to_have_count(1)
    tiers = page.locator(".summary-card .summary-card-tiers")
    expect(tiers).to_have_count(1)
    expect(tiers).to_have_text("1 CTID, 1 inferred")
    sidebar = page.locator("#result-graph .related-section")
    expect(sidebar.locator(".related-item-tiered .ctid-badge")).to_have_count(1)
    expect(sidebar.locator(".related-item-tiered .inferred-badge")).to_have_count(1)


def test_shard_page_marks_ctid_and_inferred_lists(page: Page) -> None:
    def handler(route: Route) -> None:
        resp = route.fetch()
        out = []
        for line in gzip.decompress(resp.body()).decode("utf-8").splitlines():
            rec = json.loads(line) if line.strip() else None
            if rec and SHARD_ONLY_CVE in rec:
                payload = rec[SHARD_ONLY_CVE]
                payload["TECHNIQUES_CTID"] = [{"id": CTID_TECH, "mapping_type": ["primary_impact"],
                                               "source": CTID_SOURCE, "comment": COMMENT}]
                payload["TECHNIQUES_INFERRED"] = [{"id": INFERRED_TECH, "rule": "network-no-interaction",
                                                   "source": INFERRED_SOURCE}]
                line = json.dumps(rec)
            out.append(line)
        route.fulfill(response=resp, body=gzip.compress("\n".join(out).encode("utf-8")))

    page.route("**/database/CVE-1999.jsonl.gz", handler)
    page.goto(f"{BASE_URL}#/cve/{SHARD_ONLY_CVE}")
    expect(page.locator("#result-main")).to_contain_text("Sendmail", timeout=TIMEOUT_MS)
    page.locator(".detail-tab", has_text="Technique").click()
    ctid = page.locator("#tab-technique .entity-card", has_text=CTID_TECH).locator(".ctid-badge")
    expect(ctid).to_be_visible(timeout=TIMEOUT_MS)
    assert "primary impact" in (ctid.get_attribute("title") or "")
    inf = page.locator("#tab-technique .entity-card", has_text=INFERRED_TECH).locator(".inferred-badge")
    expect(inf).to_be_visible()


def _serve_legacy(page: Page) -> None:
    """Strip every additive I21 field from the served index and shards."""

    def index_handler(route: Route) -> None:
        resp = route.fetch()
        data = json.loads(resp.body())
        data.get("meta", {}).pop("link_provenance", None)
        for ent in data["entities"].values():
            for body in (ent.get("rels") or {}).values():
                if isinstance(body, dict):
                    body.pop("link_prov", None)
        route.fulfill(response=resp, body=json.dumps(data))

    def shard_handler(route: Route) -> None:
        resp = route.fetch()
        out = []
        for line in gzip.decompress(resp.body()).decode("utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                for payload in rec.values():
                    payload.pop("TECHNIQUES_CTID", None)
                    payload.pop("TECHNIQUES_INFERRED", None)
                line = json.dumps(rec)
            out.append(line)
        route.fulfill(response=resp, body=gzip.compress("\n".join(out).encode("utf-8")))

    page.route("**/data/entity_index.json", index_handler)
    page.route("**/database/CVE-*.jsonl.gz", shard_handler)


def test_legacy_data_renders_without_tier_markers(page: Page) -> None:
    _serve_legacy(page)
    for target in (CVE, SHARD_ONLY_CVE):
        page.goto(f"{BASE_URL}#/cve/{target}")
        expect(page.locator("#result-main .detail-tabs")).to_be_visible(timeout=TIMEOUT_MS)
        page.wait_for_timeout(300)
        assert page.locator(".ctid-badge, .inferred-badge").count() == 0
        assert page.locator(".entity-card-official, .entity-card-inferred, .related-item-tiered").count() == 0
        assert page.locator(".graph-node-ctid, .graph-node-inferred").count() == 0
        assert page.locator(".prov-inferred, .summary-card-tiers").count() == 0
        assert page.locator("#result-main .badge", has_text=re.compile(r"CTID|inferred\)")).count() == 0


def test_served_ctid_links_render_when_present(page: Page) -> None:
    """Against regenerated data: the first KEV CVE whose technique rels carry
    a CTID link shows the CTID marker with the comment. Skipped on data
    generated before I21."""
    resp = page.request.get(f"{BASE_URL}data/entity_index.json")
    data = resp.json()
    if not data.get("meta", {}).get("link_provenance"):
        pytest.skip("served index predates I21")
    target = tid = None
    for eid, ent in data["entities"].items():
        prov = ((ent.get("rels") or {}).get("technique") or {}).get("link_prov") or {}
        hit = next((t for t, p in prov.items() if p.get("tier") == "official" and p.get("comment")), None)
        if ent.get("type") == "cve" and ent.get("kev") and hit:
            target, tid = eid, hit
            break
    if target is None:
        pytest.skip("served index has no CTID link")
    page.goto(f"{BASE_URL}#/cve/{target}")
    expect(page.locator("#result-main .detail-tabs")).to_be_visible(timeout=TIMEOUT_MS)
    page.locator(".detail-tab", has_text="Technique").click()
    badge = _card(page, tid).locator(".ctid-badge")
    expect(badge).to_be_visible(timeout=TIMEOUT_MS)
    comment = data["entities"][target]["rels"]["technique"]["link_prov"][tid]["comment"]
    assert comment in (badge.get_attribute("title") or "")
