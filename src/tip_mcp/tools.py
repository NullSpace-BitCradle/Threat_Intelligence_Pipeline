"""Tool implementations for TIP MCP.

Each *_impl function takes an IndexLoader as its first argument so tests can
inject a fixture loader without spinning up the MCP server. The server module
re-exports thin wrappers decorated with @mcp.tool().
"""

from __future__ import annotations

import re
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

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _shard_rels(payload: dict) -> list[dict]:
    """Project a shard CVE payload's enrichment lists into rel dicts.

    Returns a list of {target_id, rel_type, source} entries covering CWE,
    CAPEC, TECHNIQUES, and OWASP fields. Used by both lookup_entity (via
    _build_shard_record) and pivot_from_entity so the two tools project
    the same graph out of a shard.
    """
    rels: list[dict] = []
    for cwe in payload.get("CWE", []) or []:
        # Normalize CWE-123 vs 123 form.
        cwe_id = cwe if str(cwe).startswith("CWE-") else f"CWE-{cwe}"
        rels.append({"target_id": cwe_id, "rel_type": "cwe", "source": "shard"})
    for capec in payload.get("CAPEC", []) or []:
        capec_id = capec if str(capec).startswith("CAPEC-") else f"CAPEC-{capec}"
        rels.append({"target_id": capec_id, "rel_type": "capec", "source": "shard"})
    for tech in payload.get("TECHNIQUES", []) or []:
        tech_id = tech if str(tech).startswith("T") else f"T{tech}"
        rels.append({"target_id": tech_id, "rel_type": "technique", "source": "shard"})
    for owasp in payload.get("OWASP", []) or []:
        rels.append({"target_id": owasp, "rel_type": "owasp", "source": "shard"})
    return rels


def _build_shard_record(cve_id: str, payload: dict, shard_name: str) -> dict:
    """Project a shard CVE payload onto the same shape as an entity record.

    The shard has raw enrichment fields (DESCRIPTION, CWE, CVSS, ...). The
    entity_index format is snake_cased with a flat rels list, so we adapt.
    """
    description = payload.get("DESCRIPTION") or ""
    first_sentence = description.split(". ", 1)[0].strip() if description else ""
    name = first_sentence or cve_id.upper()

    record = {
        "id": cve_id.upper(),
        "type": "cve",
        "name": name,
        "phase": "vulnerability",
        "kev": bool(payload.get("KEV")),
        "description": description,
        "rels": _shard_rels(payload),
    }
    cvss = payload.get("CVSS")
    if isinstance(cvss, dict):
        if cvss.get("score") is not None:
            record["cvss_score"] = cvss.get("score")
        if cvss.get("severity"):
            record["severity"] = cvss.get("severity")
        if cvss.get("vector"):
            record["cvss_vector"] = cvss.get("vector")
    if payload.get("PUBLISHED"):
        record["published"] = payload["PUBLISHED"]
    if payload.get("LAST_MODIFIED"):
        record["last_modified"] = payload["LAST_MODIFIED"]
    refs = payload.get("REFERENCES")
    if isinstance(refs, list) and refs:
        record["references"] = refs
    return record


def lookup_entity_impl(loader: IndexLoader, entity_id: str) -> dict:
    """Look up a single entity by ID.

    Falls back to scanning the per-year CVE JSONL shard when the ID looks
    like a CVE but is not present in the enriched entity graph. This lets
    callers find any CVE that the pipeline has ingested, even those below
    the "interesting" threshold.
    """
    if not entity_id or not isinstance(entity_id, str):
        return error_response(ErrorCode.BAD_PARAM, "entity_id must be a non-empty string")

    entity = loader.entities.get(entity_id)
    if entity is not None:
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
        # Surface enriched CVE metadata if the entity carries it.
        for field in (
            "description",
            "cvss_score",
            "severity",
            "cvss_vector",
            "published",
            "last_modified",
            "references",
        ):
            if field in entity:
                record[field] = entity[field]
        meta = {"source": "entity_index.json", "rel_count": len(rels_out)}
        return ok_response(record, meta=meta)

    # Shard fallback: only for syntactically valid CVE IDs.
    if _CVE_ID_RE.match(entity_id.strip()):
        shard_hit = loader.find_cve_in_shards(entity_id)
        if shard_hit is not None:
            payload, shard_name = shard_hit
            record = _build_shard_record(entity_id, payload, shard_name)
            meta = {
                "source": "shard",
                "shard": shard_name,
                "rel_count": len(record["rels"]),
            }
            return ok_response(record, meta=meta)

    return error_response(
        ErrorCode.NOT_FOUND,
        f"entity {entity_id!r} not in entity graph",
        hint=(
            "CVE may exist in shard data but not in the enriched entity graph. "
            "TIP currently indexes only CVEs with CWE mappings."
        ),
    )


def pivot_from_entity_impl(
    loader: IndexLoader,
    entity_id: str,
    target_type: Optional[str] = None,
) -> dict:
    """Return entities related to entity_id, optionally filtered by target type.

    Falls back to the per-year CVE JSONL shard when the ID looks like a CVE
    but is not present in the enriched entity graph, so any CVE the pipeline
    has ingested can be pivoted from, not just the "interesting" subset.
    """
    if not entity_id:
        return error_response(ErrorCode.BAD_PARAM, "entity_id is required")

    if target_type is not None and target_type not in VALID_TYPES:
        return error_response(
            ErrorCode.INVALID_TYPE,
            f"target_type {target_type!r} not one of {sorted(VALID_TYPES)}",
        )

    entity = loader.entities.get(entity_id)
    if entity is not None:
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

    # Shard fallback: only for syntactically valid CVE IDs.
    if _CVE_ID_RE.match(entity_id.strip()):
        shard_hit = loader.find_cve_in_shards(entity_id)
        if shard_hit is not None:
            payload, shard_name = shard_hit
            hits = []
            for rel in _shard_rels(payload):
                tid = rel["target_id"]
                rtype = rel["rel_type"]
                target = loader.entities.get(tid)
                if target is not None:
                    ttype = target.get("type")
                    name = target.get("name")
                else:
                    # Target not in the entity graph (unusual: all reference
                    # DB entities should be indexed). Fall back to the bare
                    # ID and infer the type from the rel label.
                    ttype = rtype
                    name = tid
                if target_type is not None and ttype != target_type and rtype != target_type:
                    continue
                hits.append(
                    {
                        "id": tid,
                        "type": ttype,
                        "name": name,
                        "rel_type": rtype,
                    }
                )
            return ok_response(
                hits,
                meta={
                    "source": "shard",
                    "shard": shard_name,
                    "count": len(hits),
                },
            )

    return error_response(
        ErrorCode.NOT_FOUND,
        f"entity {entity_id!r} not in entity graph",
    )


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
