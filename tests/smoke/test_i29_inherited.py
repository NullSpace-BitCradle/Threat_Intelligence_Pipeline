"""Smoke tests for I29 (ISC-15 to ISC-17): a CVE page separates NVD-assigned
CWEs from inherited parents and marks links reached only through a parent.

The inherited fields are injected into the served index and shard, and the
legacy test strips them, so every test passes against pre-I29 and I29 data.

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


def test_isc16_graph_marks_inherited_node(page: Page) -> None:
    tech = _inject_index(page)
    nodes = page.locator(".graph-container svg g.graph-node-inherited")
    expect(nodes).to_have_count(1, timeout=TIMEOUT_MS)
    title = nodes.first.locator("title").text_content() or ""
    assert tech in title and "inherited via parent CWE" in title
    # Direct nodes carry no marker.
    direct = page.locator(".graph-container svg g:not(.graph-node-inherited) > title")
    assert all("inherited" not in (t or "") for t in direct.all_text_contents())


def test_isc16_counts_show_inherited_subset(page: Page) -> None:
    _inject_index(page)
    header = page.locator("#result-main .badge", has_text="(1 inherited)")
    expect(header).to_have_count(1, timeout=TIMEOUT_MS)
    card = page.locator(".summary-card", has=page.locator(".summary-card-inherited"))
    expect(card).to_have_count(1)
    expect(card.locator(".summary-card-inherited")).to_have_text("1 inherited via parent CWE")


def test_isc16_cwe_capec_tooltip_names_only_leading_parents(page: Page) -> None:
    """CWE-78's ChildOf is CWE-77, CWE-74, CWE-77, CWE-77. CAPEC-136 comes only
    from CWE-77's chain; CAPEC-10 from CWE-74's, which CWE-77 also reaches."""

    def handler(route: Route) -> None:
        resp = route.fetch()
        data = json.loads(resp.body())
        body = data["entities"]["CWE-78"]["rels"]["capec"]
        for cid in ("CAPEC-136", "CAPEC-10"):
            if cid not in body["ids"]:
                body["ids"].append(cid)
        body["inherited"] = ["CAPEC-136", "CAPEC-10"]
        route.fulfill(response=resp, body=json.dumps(data))

    page.route("**/data/entity_index.json", handler)
    page.goto(f"{BASE_URL}#/cwe/CWE-78")
    page.locator(".detail-tab", has_text="CAPEC").click()
    panel = page.locator("#tab-capec")
    tips = {}
    for cid in ("CAPEC-136", "CAPEC-10"):
        card = panel.locator(".entity-card").filter(has=page.locator(f"text=/^{cid}$/"))
        badge = card.locator(".inherited-badge")
        expect(badge).to_be_visible(timeout=TIMEOUT_MS)
        tips[cid] = badge.get_attribute("title") or ""
    assert "(via CWE-77)" in tips["CAPEC-136"], tips
    assert "(via CWE-77, CWE-74)" in tips["CAPEC-10"], tips


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


def _strip_inherited_rel_bodies(ent: dict) -> None:
    for body in (ent.get("rels") or {}).values():
        if isinstance(body, dict):
            body.pop("inherited", None)


def _serve_legacy(page: Page) -> None:
    """Strip every additive I29 field from the served index and shards, so the
    page sees pre-I29 data whatever the server has."""

    def index_handler(route: Route) -> None:
        resp = route.fetch()
        data = json.loads(resp.body())
        data.get("meta", {}).pop("inherited_links", None)
        for ent in data["entities"].values():
            ent.pop("cwe_inherited", None)
            _strip_inherited_rel_bodies(ent)
        route.fulfill(response=resp, body=json.dumps(data))

    def shard_handler(route: Route) -> None:
        resp = route.fetch()
        out = []
        for line in gzip.decompress(resp.body()).decode("utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                for payload in rec.values():
                    for key in [k for k in payload if k.endswith("_INHERITED")]:
                        del payload[key]
                    for d in payload.get("DEFEND") or []:
                        if isinstance(d, dict):
                            d.pop("inherited", None)
                line = json.dumps(rec)
            out.append(line)
        route.fulfill(response=resp, body=gzip.compress("\n".join(out).encode("utf-8")))

    page.route("**/data/entity_index.json", index_handler)
    page.route("**/database/CVE-*.jsonl.gz", shard_handler)


def test_isc17_legacy_data_renders_without_markers(page: Page) -> None:
    _serve_legacy(page)
    for target in (CVE, SHARD_ONLY_CVE):
        page.goto(f"{BASE_URL}#/cve/{target}")
        expect(page.locator("#result-main .detail-tabs")).to_be_visible(timeout=TIMEOUT_MS)
        page.wait_for_timeout(300)
        assert page.locator(".inherited-badge").count() == 0
        assert page.locator("[data-cwe-section]").count() == 0
        assert page.locator(".entity-card-inherited, .inherited-chip").count() == 0
        assert page.locator(".graph-node-inherited, .summary-card-inherited").count() == 0
        assert page.locator("#result-main .badge", has_text="inherited").count() == 0
