"""I1: the epss block on the shared CVE intel contract (ISC-6, ISC-7).

EPSS reaches curated CVE entities through tip_intel.cve_blocks, the same
contract the MCP layer reads. Layer 2 (which CVEs are curated) ignores EPSS.
"""
import json

import pytest

from tip.core.entity_index_generator import build_cve_entity_record, generate_entity_index
from tip_intel import cve_blocks

from tests.test_correlation_correctness import KEV_ENTRY, _write_fixture

EPSS = {"score": 0.97, "percentile": 0.999, "date": "2026-09-26"}


def test_epss_block_from_payload():
    assert cve_blocks.epss_block({"EPSS": EPSS}) == EPSS
    assert cve_blocks.epss_block({}) is None


@pytest.mark.parametrize("bad", [
    None, "0.5", {}, {"score": "high", "percentile": 0.5, "date": "2026-09-26"},
    {"score": 0.5, "percentile": 0.5},            # no date: a score without a date misleads
    {"score": 1.5, "percentile": 0.5, "date": "2026-09-26"},
    {"score": True, "percentile": 0.5, "date": "2026-09-26"},
])
def test_epss_block_rejects_malformed(bad):
    assert cve_blocks.epss_block({"EPSS": bad}) is None


def test_generator_record_carries_additive_epss():
    rec = build_cve_entity_record("CVE-2024-0001", {"DESCRIPTION": "x", "EPSS": EPSS})
    assert rec["epss"] == EPSS
    legacy = build_cve_entity_record("CVE-2024-0001", {"DESCRIPTION": "x"})
    assert "epss" not in legacy


SHARD = {
    "CVE-2024-0001": {"CWE": ["CWE-79"], "TECHNIQUES": ["1059"],                  # APT-linked
                      "APT_GROUPS": [{"id": "G0007", "via": "G0007", "via_type": "intrusion-set"}]},
    "CVE-2024-0002": {"CWE": ["CWE-79"]},                                         # KEV
    "CVE-2024-0003": {"CWE": ["CWE-79"]},                                         # not curated
}


def _with_epss(records: dict) -> dict:
    out = json.loads(json.dumps(records))
    for cid in out:
        # Every CVE, curated or not, gets a high score; none may change tier.
        out[cid]["EPSS"] = {"score": 0.99, "percentile": 0.999, "date": "2026-09-26"}
    return out


def test_layer2_set_identical_with_and_without_epss(tmp_path):
    """ISC-7: the curated CVE set does not depend on EPSS."""
    kev = {"CVE-2024-0002": KEV_ENTRY}
    _write_fixture(tmp_path / "plain", SHARD, kev=kev)
    _write_fixture(tmp_path / "epss", _with_epss(SHARD), kev=kev)
    plain, _, _ = generate_entity_index(tmp_path / "plain")
    scored, _, _ = generate_entity_index(tmp_path / "epss")

    def cves(ei):
        return sorted(k for k, v in ei["entities"].items() if v["type"] == "cve")

    assert cves(plain) == cves(scored) == ["CVE-2024-0001", "CVE-2024-0002"]
    assert scored["entities"]["CVE-2024-0001"]["epss"]["score"] == 0.99
    assert "epss" not in plain["entities"]["CVE-2024-0001"]
