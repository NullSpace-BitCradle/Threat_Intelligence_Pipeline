"""MCP server entry point for TIP.

Registers lookup_entity, pivot_from_entity, and search_threat_intel with
FastMCP over stdio. Requires the `mcp` package (see requirements-mcp.txt).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]

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


mcp = FastMCP("tip-mcp")
_loader = IndexLoader(_resolve_data_dir())


@mcp.tool()
def lookup_entity(entity_id: str) -> dict:
    """Look up a TIP threat intel entity by ID.

    Supports CVE, CWE, CAPEC, ATT&CK technique, D3FEND, APT group, OWASP, KEV,
    and campaign identifiers. Returns a success envelope with the entity record
    and its relationships, or a not_found error if the ID is not in the graph.
    """
    return lookup_entity_impl(_loader, entity_id)


@mcp.tool()
def pivot_from_entity(entity_id: str, target_type: Optional[str] = None) -> dict:
    """Return entities related to entity_id, optionally filtered by type.

    target_type is one of: cve, cwe, capec, technique, d3fend, apt, owasp,
    campaign, kev. Omit target_type to return all related entities.
    """
    return pivot_from_entity_impl(_loader, entity_id, target_type)


@mcp.tool()
def search_threat_intel(
    query: str,
    limit: int = 20,
    types: Optional[list] = None,
) -> dict:
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
