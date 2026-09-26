"""MCP server entry point for TIP.

Registers lookup_entity, pivot_from_entity, and search_threat_intel with the
mcp SDK's MCPServer (mcp 2.x; FastMCP in 1.x) over stdio. Requires the `mcp`
package pinned in requirements-mcp.txt.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from mcp.server.mcpserver import MCPServer

from .loader import IndexLoader, IndexNotLoadedError
from .tools import (
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
