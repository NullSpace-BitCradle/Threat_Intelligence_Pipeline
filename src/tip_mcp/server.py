"""MCP server entry point for TIP.

Registers lookup_entity, pivot_from_entity, search_threat_intel,
build_attack_chain, get_defenses, and kev_status with the mcp SDK's MCPServer (mcp 2.x; FastMCP in 1.x) over stdio. Requires the `mcp`
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
    build_attack_chain_impl,
    get_defenses_impl,
    kev_status_impl,
    lookup_entity_impl,
    pivot_from_entity_impl,
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
    or a not_found error if the ID is unknown.
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

    Walks technique <- CAPEC attack patterns <- CWE weaknesses -> CVEs, and
    lists the technique's D3FEND defenses. CVEs are ordered KEV first, then
    CVSS descending, and each carries kev, cvss_score, and severity. Every
    element carries its provenance (source, tier) so derived links are not
    mistaken for authoritative ones. Each list is capped at `limit` (default
    50); meta.totals has the full counts. A technique with no CAPEC mapping
    returns empty chain lists and a meta.note explaining why, still with its
    defenses. Errors: not_found for an unknown id, invalid_type for a
    non-technique id.
    """
    return build_attack_chain_impl(_loader, technique_id, limit)


@mcp.tool(structured_output=True)
def get_defenses(
    technique_id: Optional[str] = None, cve_id: Optional[str] = None
) -> dict[str, Any]:
    """List D3FEND countermeasures for an ATT&CK technique or a CVE.

    Pass exactly one of technique_id or cve_id (both or neither is
    bad_param). Each defense has id, name, mapping_source, tier, and
    via_techniques. For a CVE, defenses are reached through the ATT&CK
    techniques the CVE maps to (named in via_techniques), plus the CVE's own
    D3FEND links (direct: true), and include the D3FEND relationship verb
    (isolates, monitors, hardens, ...) when the CVE's data records it.
    """
    return get_defenses_impl(_loader, technique_id, cve_id)


@mcp.tool(structured_output=True)
def kev_status(cve_id: str) -> dict[str, Any]:
    """Report CISA KEV status for a CVE, for patch prioritization.

    Returns in_kev plus date_added, due_date, known_ransomware_campaign_use,
    required_action, vendor_project, and product from the CISA KEV catalog,
    and the CISA SSVC decision when TIP has one. A CVE not in KEV returns ok
    with in_kev false and null KEV fields. A malformed CVE id is bad_param.
    """
    return kev_status_impl(_loader, cve_id)


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
