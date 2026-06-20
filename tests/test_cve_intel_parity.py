"""I24 cross-seam parity: the shared CVE intelligence contract reaches BOTH
surfaces.

The historical bug was a hand-maintained field allowlist mirrored in three
places (the generator emission and two spots in the MCP layer); a field added
to one and forgotten in another vanished silently with no failing test. The
fix is a single contract in ``tip_intel.cve_blocks`` consumed by both the
generator (producer) and the MCP layer (consumer). This test fails the build
if any contract field stops reaching either surface.
"""

from __future__ import annotations

import json
from pathlib import Path

from tip_intel import cve_blocks
from tip_intel.cve_blocks import INTEL_FIELDS
from tip_mcp.loader import IndexLoader
from tip_mcp.tools import lookup_entity_impl

# A shard payload populated so every contract field has data to surface.
RICH_PAYLOAD = {
    "DESCRIPTION": "HTTP/2 rapid reset denial of service.",
    "CVSS": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "severity": "HIGH",
        "version": "3.1",
        "source": "cisa_vulnrichment",
    },
    "CWE": ["CWE-400"],
    "CAPEC": [],
    "TECHNIQUES": ["T1499"],
    "OWASP": [],
    "DEFEND": [
        {"id": "D3-ABPI", "name": "Application-based Process Isolation", "relationship": "isolates"}
    ],
    "APT_GROUPS": ["G0007"],
    "KEV": {
        "inKEV": True,
        "dateAdded": "2023-10-10",
        "dueDate": "2023-10-31",
        "knownRansomwareCampaignUse": "Known",
        "requiredAction": "Apply mitigations.",
        "vendorProject": "IETF",
        "product": "HTTP/2",
    },
    "VULNRICHMENT": {
        "ssvcExploitStatus": "active",
        "ssvcAutomatable": "no",
        "ssvcTechnicalImpact": "total",
        "cisaCVSS": {"baseScore": 8.7, "vector": "CVSS:4.0/AV:N/AC:L/..."},
    },
}


def _producer_record(payload: dict) -> dict:
    """Mirror the generator's CVE emission: a base entity record, then the
    shared enrich() — exactly the call entity_index_generator.py makes."""
    record = {
        "id": "CVE-2023-44487",
        "type": "cve",
        "name": "HTTP/2 rapid reset denial of service",
        "phase": "vulnerability",
    }
    cve_blocks.enrich(record, payload)
    return record


def _consumer_record(tmp_path: Path, payload: dict) -> dict:
    """The MCP projection: a shard-only CVE flows through lookup_entity_impl's
    shard fallback, which applies the same enrich()."""
    (tmp_path / "entity_index.json").write_text(json.dumps({"entities": {}}))
    (tmp_path / "search_index.json").write_text("{}")
    shards = tmp_path / "database"
    shards.mkdir()
    (shards / "CVE-2023.jsonl").write_text(json.dumps({"CVE-2023-44487": payload}) + "\n")
    ld = IndexLoader(tmp_path, shards_dir=shards)
    ld.load()
    resp = lookup_entity_impl(ld, "CVE-2023-44487")
    assert resp["ok"] is True, resp
    return resp["data"]


def test_contract_is_non_empty():
    assert set(INTEL_FIELDS) >= {
        "kev_detail",
        "ssvc",
        "cisa_cvss",
        "cvss_version",
        "cvss_source",
    }


def test_every_contract_field_reaches_the_producer():
    record = _producer_record(RICH_PAYLOAD)
    missing = [f for f in INTEL_FIELDS if f not in record]
    assert not missing, f"producer (generator) dropped: {missing}"


def test_every_contract_field_reaches_the_consumer(tmp_path: Path):
    data = _consumer_record(tmp_path, RICH_PAYLOAD)
    missing = [f for f in INTEL_FIELDS if f not in data]
    assert not missing, f"consumer (MCP) dropped: {missing}"


def test_producer_consumer_parity(tmp_path: Path):
    prod = _producer_record(RICH_PAYLOAD)
    cons = _consumer_record(tmp_path, RICH_PAYLOAD)
    prod_present = {f for f in INTEL_FIELDS if f in prod}
    cons_present = {f for f in INTEL_FIELDS if f in cons}
    assert prod_present == cons_present == set(INTEL_FIELDS), (
        f"cross-seam drift: producer={prod_present} consumer={cons_present}"
    )


def test_values_match_across_seam(tmp_path: Path):
    prod = _producer_record(RICH_PAYLOAD)
    cons = _consumer_record(tmp_path, RICH_PAYLOAD)
    for field in INTEL_FIELDS:
        assert prod[field] == cons[field], f"{field} differs across seam"
