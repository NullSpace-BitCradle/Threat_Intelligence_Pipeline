"""I24 cross-seam parity: the shared CVE intelligence contract reaches BOTH
surfaces.

The historical bug was a hand-maintained field allowlist mirrored in three
places (the generator emission and two spots in the MCP layer); a field added
to one and forgotten in another vanished silently with no failing test. The
fix is a single contract in ``tip_intel.cve_blocks`` consumed by both the
generator (producer) and the MCP layer (consumer).

The producer side calls the generator's real CVE record builder
(``build_cve_entity_record``), not a mirror of it, so removing the
generator's ``cve_blocks.enrich`` call fails this test. The consumer side
covers both MCP paths: the shard fallback, and the entity-index path serving
a generated record with no shards on disk.
"""

from __future__ import annotations

import json
from pathlib import Path

from tip.core.entity_index_generator import build_cve_entity_record
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
    "CWE": ["400", "CWE-770"],
    "CAPEC": [],
    "TECHNIQUES": ["1499"],
    "OWASP": [],
    "DEFEND": [
        {"id": "D3-ABPI", "name": "Application-based Process Isolation", "relationship": "isolates"}
    ],
    "KEV": {
        "inKEV": True,
        "dateAdded": "2023-10-10",
        "dueDate": "2023-10-31",
        "knownRansomwareCampaignUse": "Known",
        "requiredAction": "Apply mitigations.",
        "vendorProject": "IETF",
        "product": "HTTP/2",
    },
    "EPSS": {"score": 0.99999, "percentile": 0.99998, "date": "2026-09-26"},
    "VULNRICHMENT": {
        "ssvcExploitStatus": "active",
        "ssvcAutomatable": "no",
        "ssvcTechnicalImpact": "total",
        "cisaCVSS": {"baseScore": 8.7, "vector": "CVSS:4.0/AV:N/AC:L/..."},
    },
}


def _producer_record(payload: dict) -> dict:
    """The generator's own CVE record, built by the function
    generate_entity_index calls for every curated CVE."""
    return build_cve_entity_record("CVE-2023-44487", payload)


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
    assert resp["meta"]["source"] == "shard"
    return resp["data"]


def _consumer_entity_path_record(tmp_path: Path, payload: dict) -> dict:
    """The MCP entity-index path serving the generator's record with no
    shards on disk: every intel field must come from entity_index.json."""
    record = dict(_producer_record(payload), rels={})
    (tmp_path / "entity_index.json").write_text(
        json.dumps({"entities": {"CVE-2023-44487": record}})
    )
    (tmp_path / "search_index.json").write_text("{}")
    ld = IndexLoader(tmp_path, shards_dir=tmp_path / "no-shards")
    ld.load()
    resp = lookup_entity_impl(ld, "CVE-2023-44487")
    assert resp["ok"] is True, resp
    assert resp["meta"]["source"] == "entity_index.json"
    assert "enriched_from_shard" not in resp["meta"]
    return resp["data"]


def test_contract_is_non_empty():
    assert set(INTEL_FIELDS) >= {
        "kev_detail",
        "ssvc",
        "cisa_cvss",
        "cvss_version",
        "cvss_source",
        "epss",
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


def test_entity_path_serves_every_contract_field_without_shards(tmp_path: Path):
    prod = _producer_record(RICH_PAYLOAD)
    cons = _consumer_entity_path_record(tmp_path, RICH_PAYLOAD)
    for field in INTEL_FIELDS:
        assert field in cons, f"entity path dropped {field} with shards absent"
        assert cons[field] == prod[field], f"{field} differs across seam"
