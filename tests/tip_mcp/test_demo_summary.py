"""T10.8 F6: the demo's get_defenses summary states why CVE-side defenses are
derived without misdescribing the CVE to technique links."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "mcp_demo", Path(__file__).resolve().parents[2] / "scripts" / "mcp_demo.py")
assert SPEC is not None and SPEC.loader is not None
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


def _result(link_tier: str) -> dict:
    link = {"id": "T1190", "source": "src", "tier": link_tier}
    return {"ok": True, "data": [
        {"id": "D3-A", "tier": "derived", "relationship": "monitors", "technique_links": [link]},
        {"id": "D3-B", "tier": "derived", "technique_links": [link]},
    ], "meta": {"count": 2, "techniques": ["T1190"], "query": {"cve_id": "CVE-2023-44487"}}}


def test_f6_official_links_are_not_called_derived_links():
    text = demo.summarize("get_defenses", _result("official"))
    assert "CAPEC to technique chain" not in text
    assert "TIP derives the CVE to technique links" not in text
    assert "1 official" in text
    assert "not a defense the source states for the CVE" in text


def test_f6_wording_follows_the_actual_link_tiers():
    text = demo.summarize("get_defenses", _result("derived"))
    assert "1 derived" in text and "1 official" not in text
