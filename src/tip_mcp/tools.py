"""Tool implementations for TIP MCP.

Each *_impl function takes an IndexLoader as its first argument so tests can
inject a fixture loader without spinning up the MCP server. The server module
re-exports thin wrappers decorated with @mcp.tool().
"""

from __future__ import annotations

from typing import Optional

from .loader import IndexLoader
from .schema import ErrorCode, error_response, ok_response

VALID_TYPES = {
    "cve",
    "cwe",
    "capec",
    "technique",
    "d3fend",
    "apt",
    "owasp",
    "campaign",
    "kev",
}


def lookup_entity_impl(loader: IndexLoader, entity_id: str) -> dict:
    """Look up a single entity by ID."""
    if not entity_id or not isinstance(entity_id, str):
        return error_response(ErrorCode.BAD_PARAM, "entity_id must be a non-empty string")

    entity = loader.entities.get(entity_id)
    if entity is None:
        return error_response(
            ErrorCode.NOT_FOUND,
            f"entity {entity_id!r} not in entity graph",
            hint=(
                "CVE may exist in shard data but not in the enriched entity graph. "
                "TIP currently indexes only CVEs with CWE mappings."
            ),
        )

    rels_out = []
    for rel_type, rel_body in entity.get("rels", {}).items():
        for tid in rel_body.get("ids", []):
            rels_out.append(
                {
                    "target_id": tid,
                    "rel_type": rel_type,
                    "source": rel_body.get("source"),
                }
            )

    record = {
        "id": entity.get("id", entity_id),
        "type": entity.get("type"),
        "name": entity.get("name"),
        "phase": entity.get("phase"),
        "kev": bool(entity.get("kev", False)),
        "rels": rels_out,
    }
    meta = {"source": "entity_index.json", "rel_count": len(rels_out)}
    return ok_response(record, meta=meta)


def pivot_from_entity_impl(
    loader: IndexLoader,
    entity_id: str,
    target_type: Optional[str] = None,
) -> dict:
    """Return entities related to entity_id, optionally filtered by target type."""
    if not entity_id:
        return error_response(ErrorCode.BAD_PARAM, "entity_id is required")

    if target_type is not None and target_type not in VALID_TYPES:
        return error_response(
            ErrorCode.INVALID_TYPE,
            f"target_type {target_type!r} not one of {sorted(VALID_TYPES)}",
        )

    entity = loader.entities.get(entity_id)
    if entity is None:
        return error_response(
            ErrorCode.NOT_FOUND,
            f"entity {entity_id!r} not in entity graph",
        )

    hits = []
    for rel_type, rel_body in entity.get("rels", {}).items():
        for tid in rel_body.get("ids", []):
            target = loader.entities.get(tid)
            if target is None:
                continue
            ttype = target.get("type")
            if target_type is not None and ttype != target_type and rel_type != target_type:
                continue
            hits.append(
                {
                    "id": target.get("id", tid),
                    "type": ttype,
                    "name": target.get("name"),
                    "rel_type": rel_type,
                }
            )

    return ok_response(hits, meta={"source": "entity_index.json", "count": len(hits)})


def search_threat_intel_impl(
    loader: IndexLoader,
    query: str,
    limit: int = 20,
    types: Optional[list] = None,
) -> dict:
    """Search the inverted index by query string, ranked by match count."""
    if not query or not isinstance(query, str):
        return error_response(ErrorCode.BAD_PARAM, "query must be a non-empty string")
    if not isinstance(limit, int) or limit < 1:
        return error_response(ErrorCode.BAD_PARAM, "limit must be a positive integer")

    tokens = [t for t in query.lower().split() if t]
    if not tokens:
        return ok_response([], meta={"source": "search_index.json", "count": 0})

    scores: dict = {}
    for tok in tokens:
        for eid in loader.search_index.get(tok, []):
            scores[eid] = scores.get(eid, 0) + 1

    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))

    hits = []
    for eid, score in ranked:
        ent = loader.entities.get(eid)
        if ent is None:
            continue
        ttype = ent.get("type")
        if types and ttype not in types:
            continue
        hits.append(
            {
                "id": ent.get("id", eid),
                "type": ttype,
                "name": ent.get("name"),
                "score": score,
            }
        )
        if len(hits) >= limit:
            break

    return ok_response(
        hits,
        meta={
            "source": "search_index.json",
            "count": len(hits),
            "query_tokens": tokens,
        },
    )
