"""MCP server entry point for TIP.

Registers lookup_entity, pivot_from_entity, search_threat_intel,
build_attack_chain, get_defenses, kev_status, and recent_changes with the mcp SDK's MCPServer (mcp 2.x; FastMCP in 1.x) over stdio. Requires the `mcp`
package pinned in requirements-mcp.txt.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from mcp.server.mcpserver import MCPServer

from .loader import IndexLoader, IndexNotLoadedError
from .tools import (
    DEFAULT_CHAIN_LIMIT,
    DEFAULT_CHANGES_LIMIT,
    build_attack_chain_impl,
    get_defenses_impl,
    kev_status_impl,
    lookup_entity_impl,
    pivot_from_entity_impl,
    recent_changes_impl,
    search_threat_intel_impl,
)


def _resolve_data_dir() -> Path:
    """Resolve the TIP data directory.

    Priority: TIP_DATA_DIR env var, then repo-relative default.
    """
    env = os.environ.get("TIP_DATA_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    return here.parent.parent.parent / "docs" / "data"


def _resolve_shards_dir() -> Optional[Path]:
    """TIP_SHARDS_DIR env var, else None (the loader uses <data_dir>/../database)."""
    env = os.environ.get("TIP_SHARDS_DIR")
    return Path(env) if env else None


mcp = MCPServer("tip-mcp")
_loader = IndexLoader(_resolve_data_dir(), shards_dir=_resolve_shards_dir())


# structured_output=True: clients get the envelope both as JSON text content
# (the pre-2.x surface) and as structuredContent with an output schema.
@mcp.tool(structured_output=True)
def lookup_entity(entity_id: str) -> dict[str, Any]:
    """Look up a TIP threat intel entity by ID.

    Supports CVE, CWE, CAPEC, ATT&CK technique, D3FEND, APT group, OWASP, and
    campaign identifiers (case and surrounding whitespace are ignored). CVEs
    outside the curated entity graph are served from the per-year shards.
    Returns a success envelope with the entity record and its relationships,
    or a not_found error if the ID is unknown. CVE records carry epss
    {score, percentile, date} from FIRST when scored, else null.
    """
    return lookup_entity_impl(_loader, entity_id)


@mcp.tool(structured_output=True)
def pivot_from_entity(entity_id: str, target_type: Optional[str] = None) -> dict[str, Any]:
    """Return entities related to entity_id, optionally filtered by type.

    target_type is one of: cve, cwe, capec, technique, defend, apt_group,
    owasp, campaign, kev (legacy aliases d3fend and apt are accepted). Omit
    target_type to return all related entities.
    """
    return pivot_from_entity_impl(_loader, entity_id, target_type)


@mcp.tool(structured_output=True)
def search_threat_intel(
    query: str,
    limit: int = 20,
    types: Optional[list] = None,
) -> dict[str, Any]:
    """Search TIP entities by free-text query.

    Returns ranked hits by token match count. Optional `types` filters to a
    subset of entity types (same vocabulary as pivot_from_entity).
    """
    return search_threat_intel_impl(_loader, query, limit, types)


@mcp.tool(structured_output=True)
def build_attack_chain(technique_id: str, limit: int = DEFAULT_CHAIN_LIMIT) -> dict[str, Any]:
    """Build the attack chain behind an ATT&CK technique.

    cves is exactly the set of CVEs the TIP graph links to the technique.
    capecs are the CAPEC patterns that map to the technique. Each CVE
    carries via_cwes and via_capecs: its CWE weaknesses that reach one of
    those CAPECs, and the CAPECs reached (empty when no CWE path exists).
    cwes lists only the CWEs some returned CVE goes through, each with
    via_capecs and an inherited flag: true when a CWE to CAPEC link is not in
    the CWE's own MITRE RelatedAttackPatterns (the generator inherited it
    from a parent CWE), null when cwe_db.json is unavailable to check.
    defenses are the technique's D3FEND mappings.

    Every element carries source and tier (authoritative > official >
    derived) of the weakest hop on its path, so an inherited or pipeline
    derived link is never labeled official. CVEs are ordered KEV first, then
    CVSS descending, and carry kev, cvss_score, and severity. Each list is
    capped at `limit` (default 50); meta.totals has the full counts and
    meta.note explains an empty or partly explained chain. Errors:
    not_found for an unknown id, invalid_type for a non-technique id.
    """
    return build_attack_chain_impl(_loader, technique_id, limit)


@mcp.tool(structured_output=True)
def get_defenses(
    technique_id: Optional[str] = None, cve_id: Optional[str] = None
) -> dict[str, Any]:
    """List D3FEND countermeasures for an ATT&CK technique or a CVE.

    Pass exactly one of technique_id or cve_id (both, neither, or a
    non-string is bad_param). Each defense has id, name, mapping_source,
    tier, and via_techniques. For a technique, mapping_source and tier are
    the technique to D3FEND mapping's own (MITRE D3FEND, official). For a
    CVE, defenses are reached through the ATT&CK techniques the CVE maps to
    (named in via_techniques; empty for a defense only on the CVE's own
    D3FEND rels); tier is the weakest of the CVE to technique and technique
    to D3FEND hops, which is derived because TIP derives CVE to technique
    links, and mapping_source names both hops. The D3FEND relationship verb
    (isolates, monitors, hardens, ...) is included when the CVE's data
    records it.
    """
    return get_defenses_impl(_loader, technique_id, cve_id)


@mcp.tool(structured_output=True)
def kev_status(cve_id: str) -> dict[str, Any]:
    """Report CISA KEV status for a CVE, for patch prioritization.

    Returns in_kev plus date_added, due_date, known_ransomware_campaign_use,
    required_action, vendor_project, and product from the CISA KEV catalog,
    and the CISA SSVC decision when TIP has one, plus epss {score,
    percentile, date} from FIRST when scored (else null). A CVE not in KEV returns ok
    with in_kev false and null KEV fields. in_kev is null (unknown) when the
    catalog, entity graph and shard are all unavailable. A malformed CVE id is bad_param.
    """
    return kev_status_impl(_loader, cve_id)


@mcp.tool(structured_output=True)
def recent_changes(
    entity_id: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = DEFAULT_CHANGES_LIMIT,
) -> dict[str, Any]:
    """Report what changed in TIP's data over the last 30 days.

    Events are observed by the pipeline run to run, newest first, each with
    date, type, cve, before, after, and related ids (cwe, technique,
    apt_group, and KEV vendor and product). type is one of kev_added,
    kev_removed, ssvc_exploitation_changed, epss_jump (a move of 0.1 or a
    crossing of 0.5 in EPSS, curated CVEs only), cvss_changed (curated CVEs),
    curated_added, curated_removed. entity_id keeps only events whose CVE or
    related ids, vendor, or product match it (case-insensitive), so a CWE,
    technique, APT group id, or vendor name works as a watch. Capped at limit
    (default 50); meta.total has the full count. When the log hit its event
    cap, meta.truncated counts the dropped older events and meta.note says
    so. No change log yet returns ok with no events and meta.note.
    """
    return recent_changes_impl(_loader, entity_id, type, limit)


def main() -> None:
    """Load indexes then run the MCP server over stdio."""
    try:
        _loader.load()
    except IndexNotLoadedError as exc:
        raise SystemExit(
            f"tip-mcp: {exc}. Run the TIP pipeline first to generate indexes."
        ) from exc
    mcp.run()


if __name__ == "__main__":
    main()
