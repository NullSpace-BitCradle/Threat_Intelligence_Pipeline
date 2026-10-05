"""T10.8 cross-vendor audit regressions (F1, F2, F3, F5, F7).

Each test fails on the pre-audit code and passes with the fix.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from tip.core.cve_processor import CVEProcessor
from tip_mcp.tools import (
    build_attack_chain_impl,
    get_defenses_impl,
    kev_status_impl,
    lookup_entity_impl,
    pivot_from_entity_impl,
)

from .sweeps import chain_uncredited_capec_violations
from .test_phase_b import _chain_graph, _graph, _rel

CTID = "MITRE CTID"
LONG_CVE = "CVE-2024-" + "1" * 5000


# ---------------------------------------------------------------- F1


def _no_capec_graph() -> dict:
    """T9001 <- CAPEC-900 <- CWE-900. CVE-2021-0001 is assigned CWE-900 but
    credits no CAPEC at all (like CVE-2021-40449); its technique link is a
    per-link CTID mapping."""
    g = _chain_graph()
    for k in ("CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004"):
        del g[k]
    g["T9001"]["rels"]["cve"] = _rel(["CVE-2021-0001"], "Pipeline (CAPEC→Technique chain)", "derived")
    g["T9001"]["rels"]["cve"]["link_prov"] = {"CVE-2021-0001": {"source": CTID, "tier": "official"}}
    g["CWE-900"]["rels"]["cve"] = _rel(["CVE-2021-0001"], "NVD", "authoritative")
    g["CVE-2021-0001"] = {
        "type": "cve",
        "kev": False,
        "rels": {"cwe": _rel(["CWE-900"], "NVD", "authoritative")},
    }
    return g


def test_f1_cve_without_credited_capecs_gets_no_cwe_path(tmp_path):
    ld = _graph(tmp_path, _no_capec_graph())
    data = build_attack_chain_impl(ld, "T9001")["data"]
    (cve,) = data["cves"]
    assert cve["id"] == "CVE-2021-0001"
    assert cve["via_cwes"] == []
    assert cve["via_capecs"] == []
    assert data["cwes"] == []
    assert chain_uncredited_capec_violations(ld) == []


# ---------------------------------------------------------------- F2


def test_f2_kev_unknown_when_no_source_available(tmp_path):
    # No kev_db.json, no entity, no shard: unknown, never a confident negative.
    ld = _graph(tmp_path, {"T9001": {"type": "technique", "rels": {}}})
    resp = kev_status_impl(ld, "CVE-2021-9999")
    assert resp["ok"] is True
    assert resp["data"]["in_kev"] is None
    assert "kev_db.json unavailable" in resp["meta"]["note"]


def test_f2_kev_known_negative_still_false_from_graph(tmp_path):
    g = {"CVE-2021-0001": {"type": "cve", "kev": False}}
    ld = _graph(tmp_path, g)
    assert kev_status_impl(ld, "CVE-2021-0001")["data"]["in_kev"] is False


def test_f2_non_object_catalog_entry_is_not_dropped(tmp_path):
    ld = _graph(tmp_path, {"T9001": {"type": "technique", "rels": {}}},
                kev_db={"CVE-2021-0001": "garbage", "CVE-2021-0002": {"inKEV": True}})
    resp = kev_status_impl(ld, "CVE-2021-0001")
    assert resp["data"]["in_kev"] is True
    assert resp["data"]["date_added"] is None
    assert "CVE-2021-0001" in json.dumps(resp["meta"]["warnings"])
    # A well-formed entry raises no warning.
    assert "warnings" not in kev_status_impl(ld, "CVE-2021-0002")["meta"]


# ---------------------------------------------------------------- F3


def _nvd(weaknesses: list, description: str) -> dict:
    return {"cve": {
        "id": "CVE-2021-1111",
        "weaknesses": weaknesses,
        "descriptions": [{"lang": "en", "value": description}],
    }}


def test_f3_description_text_never_feeds_cwe_list():
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.logger = logging.getLogger("t")
    out = proc.process_nvd_cves([_nvd([], "This is not CWE-79 but looks like CWE-89.")])
    assert out["CVE-2021-1111"]["CWE"] == []
    weak = [{"description": [{"lang": "en", "value": "CWE-20"}]}]
    out = proc.process_nvd_cves([_nvd(weak, "mentions CWE-79")])
    assert out["CVE-2021-1111"]["CWE"] == ["CWE-20"]


# ---------------------------------------------------------------- F5


def test_f5_capped_chain_cwes_come_from_returned_cves(tmp_path):
    g = _chain_graph()
    # limit=1 returns CVE-2020-0003 (KEV, highest CVSS among KEV). CWE-900
    # sorts first but is used only by CVE-2020-0001, which is not returned.
    g["CWE-900"]["rels"]["cve"] = _rel(["CVE-2020-0001"], "NVD", "authoritative")
    g["CWE-901"] = {"type": "cwe", "rels": {
        "capec": _rel(["CAPEC-900"], "CWE", "official"),
        "cve": _rel(["CVE-2020-0003"], "NVD", "authoritative"),
    }}
    for cid in CHAIN_IDS:
        g[cid]["rels"] = {"capec": _rel(["CAPEC-900"], "Pipeline (CWE→CAPEC chain)")}
    ld = _graph(tmp_path, g)
    resp = build_attack_chain_impl(ld, "T9001", limit=1)
    data = resp["data"]
    assert [c["id"] for c in data["cves"]] == ["CVE-2020-0003"]
    assert [c["id"] for c in data["cwes"]] == ["CWE-901"]
    assert resp["meta"]["totals"]["cwes"] == 2


CHAIN_IDS = ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004"]


# ---------------------------------------------------------------- F7


@pytest.fixture
def long_id_loader(tmp_path):
    g = {"CVE-2024-0001": {"type": "cve", "kev": False}}
    ld = _graph(tmp_path, g, kev_db={})
    ld._cve_ids = {"2024": [1]}  # as cve_ids_index.json would load
    return ld


def test_f7_overlong_cve_suffix_is_bad_param_everywhere(long_id_loader):
    ld = long_id_loader
    for resp in (
        kev_status_impl(ld, LONG_CVE),
        lookup_entity_impl(ld, LONG_CVE),
        pivot_from_entity_impl(ld, LONG_CVE, "cwe"),
        get_defenses_impl(ld, cve_id=LONG_CVE),
    ):
        assert resp["ok"] is False
        assert resp["error"]["code"] == "bad_param"


def test_f7_nineteen_digit_suffix_is_still_valid(long_id_loader):
    resp = kev_status_impl(long_id_loader, "CVE-2024-" + "1" * 19)
    assert resp["ok"] is True
