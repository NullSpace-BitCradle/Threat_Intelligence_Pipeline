"""Tool implementations for TIP MCP.

Each *_impl function takes an IndexLoader as its first argument so tests can
inject a fixture loader without spinning up the MCP server. The server module
re-exports thin wrappers decorated with @mcp.tool().

Type vocabulary: the entity graph (entity_index.json) names its types
``cve, cwe, capec, technique, defend, apt_group, owasp, campaign``. Tools
accept those names plus the legacy aliases ``d3fend`` (for ``defend``) and
``apt`` (for ``apt_group``), and ``kev`` (CVE targets flagged KEV). Every rel
and hit the tools emit uses the graph names, on both the entity path and the
shard path.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from tip_intel import cve_blocks

from .loader import IndexLoader, IndexNotLoadedError, ShardReadError
from .schema import ErrorCode, error_response, ok_response

# Types as the entity graph names them.
GRAPH_TYPES = (
    "cve",
    "cwe",
    "capec",
    "technique",
    "defend",
    "apt_group",
    "owasp",
    "campaign",
)
# Legacy names accepted on input and mapped to the graph name.
TYPE_ALIASES = {"d3fend": "defend", "apt": "apt_group"}
# Pseudo-type: CVE targets whose entity carries kev=true.
KEV_TYPE = "kev"

# Every type name a caller may pass (graph names, aliases, kev).
VALID_TYPES = set(GRAPH_TYPES) | set(TYPE_ALIASES) | {KEV_TYPE}

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# IDs whose canonical form is upper case.
_UPPER_ID_RE = re.compile(
    r"^(?:(?:CVE|CWE|CAPEC)-.+|T\d{4}(?:\.\d{3})?|[GCS]\d{4}|D3-.+|A\d{2}:\d{4})$",
    re.IGNORECASE,
)
_TECH_NUM_RE = re.compile(r"^\d{4}(?:\.\d{3})?$")


def normalize_type(value: Any) -> Optional[str]:
    """Map a caller-supplied type name to its graph name, or None if unknown."""
    if not isinstance(value, str):
        return None
    t = value.strip().lower()
    t = TYPE_ALIASES.get(t, t)
    return t if t in GRAPH_TYPES or t == KEV_TYPE else None


def normalize_entity_id(value: str) -> str:
    """Strip whitespace and upper-case IDs whose canonical form is upper case
    (CVE-, CWE-, CAPEC-, T-ids, G/C/S ids, D3- ids, OWASP Axx:yyyy). Other
    IDs (D3FEND names like 'AccessModeling') keep their case; lookups fall
    back to a case-insensitive match for those."""
    s = value.strip()
    return s.upper() if _UPPER_ID_RE.match(s) else s


def _ensure_loaded(loader: IndexLoader) -> Optional[dict]:
    """Load indexes on first use. Returns an index_not_loaded envelope when
    they are missing or corrupt, None when the loader is ready."""
    if loader.loaded:
        return None
    try:
        loader.load()
    except IndexNotLoadedError as exc:
        return error_response(
            ErrorCode.INDEX_NOT_LOADED,
            str(exc),
            hint="Run the TIP pipeline to regenerate docs/data, or set TIP_DATA_DIR.",
        )
    return None


def _type_matches(want: str, ttype: Optional[str], rel_type: str, target: Optional[dict]) -> bool:
    if want == KEV_TYPE:
        return ttype == "cve" and bool(target and target.get("kev"))
    return ttype == want or rel_type == want


def _norm_ref(value: Any, prefix: str) -> str:
    """Prefix a bare numeric reference (shards mix '664' and 'CWE-400')."""
    s = str(value).strip()
    if s.isdigit():
        return f"{prefix}{s}"
    return s.upper() if s.upper().startswith(prefix) else s


def _norm_technique(value: Any) -> str:
    s = str(value).strip()
    if _TECH_NUM_RE.match(s):
        return f"T{s}"
    return s.upper() if s[:1] in ("t", "T") and _TECH_NUM_RE.match(s[1:]) else s


def _shard_rels(payload: dict, loader: Optional[IndexLoader] = None) -> list[dict]:
    """Project a shard CVE payload's enrichment lists into rel dicts.

    Returns {target_id, rel_type, source} entries in the graph vocabulary
    (cwe, capec, technique, owasp, defend, apt_group), with IDs normalized to
    the graph's form. When a loader is given, ATT&CK groups known to use a
    linked technique are added as apt_group rels, the same technique overlap
    the entity-index generator uses (shards carry no APT_GROUPS today).
    Used by both lookup_entity and pivot_from_entity so the two tools project
    the same graph out of a shard.
    """
    rels: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(target_id: str, rel_type: str, source: str = "shard") -> Optional[dict]:
        if not target_id or (target_id, rel_type) in seen:
            return None
        seen.add((target_id, rel_type))
        rel = {"target_id": target_id, "rel_type": rel_type, "source": source}
        rels.append(rel)
        return rel

    for cwe in payload.get("CWE", []) or []:
        add(_norm_ref(cwe, "CWE-"), "cwe")
    for capec in payload.get("CAPEC", []) or []:
        add(_norm_ref(capec, "CAPEC-"), "capec")
    techniques: list[str] = []
    for tech in payload.get("TECHNIQUES", []) or []:
        tech_id = _norm_technique(tech)
        techniques.append(tech_id)
        add(tech_id, "technique")
    for owasp in payload.get("OWASP", []) or []:
        add(str(owasp).strip(), "owasp")
    for defend in payload.get("DEFEND", []) or []:
        if not isinstance(defend, dict) or not defend.get("id"):
            continue
        rel = add(str(defend["id"]), "defend")
        if rel is None:
            continue
        if defend.get("relationship") is not None:
            rel["relationship"] = defend["relationship"]
        if defend.get("name") is not None:
            rel["name"] = defend["name"]
    for gid in payload.get("APT_GROUPS", []) or []:
        if gid:
            add(str(gid).strip().upper(), "apt_group")
    if loader is not None:
        for tech_id in techniques:
            tech = loader.entities.get(tech_id)
            if not tech:
                continue
            groups = (tech.get("rels") or {}).get("apt_group") or {}
            for gid in groups.get("ids", []) or []:
                add(str(gid), "apt_group", "graph (technique overlap)")
    return rels


# The CVE intelligence blocks (kev_detail, ssvc, cisa_cvss, cvss version/source,
# D3FEND semantics) are defined once in tip_intel.cve_blocks and shared with the
# entity-index generator. cve_blocks.enrich(record, payload) is the single
# projection used by both surfaces; see that module for the field contract.


def _build_shard_record(
    cve_id: str, payload: dict, shard_name: str, loader: Optional[IndexLoader] = None
) -> dict:
    """Project a shard CVE payload onto the same shape as an entity record.

    The shard has raw enrichment fields (DESCRIPTION, CWE, CVSS, ...). The
    entity_index format is snake_cased with a flat rels list, so we adapt.
    """
    description = payload.get("DESCRIPTION") or ""
    first_sentence = description.split(". ", 1)[0].strip() if description else ""
    name = first_sentence or cve_id.upper()

    kev = payload.get("KEV")
    record: dict = {
        "id": cve_id.upper(),
        "type": "cve",
        "name": name,
        "phase": "vulnerability",
        "kev": bool(kev.get("inKEV")) if isinstance(kev, dict) else bool(kev),
        "description": description,
        "rels": _shard_rels(payload, loader),
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
    cve_blocks.enrich(record, payload)
    return record


def _not_found(loader: IndexLoader, entity_id: str) -> dict:
    hint = (
        "Only curated CVEs (KEV, CISA vulnrichment, APT-linked) are in the entity "
        "graph; other ingested CVEs are served from the per-year shards."
    )
    if _CVE_ID_RE.match(entity_id) and loader.cve_known(entity_id) is False:
        hint = "cve_ids_index.json does not list this CVE, so the pipeline has not ingested it."
    return error_response(
        ErrorCode.NOT_FOUND,
        f"entity {entity_id!r} not in entity graph",
        hint=hint,
    )


def _shard_error(exc: ShardReadError) -> dict:
    return error_response(
        ErrorCode.DATA_CORRUPT,
        str(exc),
        hint="The CVE year shard is corrupt; rerun the pipeline to rewrite it.",
    )


def lookup_entity_impl(loader: IndexLoader, entity_id: str) -> dict:
    """Look up a single entity by ID.

    Falls back to the per-year CVE JSONL shard when the ID looks like a CVE
    but is not present in the enriched entity graph. This lets callers find
    any CVE that the pipeline has ingested, even those below the curated
    threshold.
    """
    if not entity_id or not isinstance(entity_id, str) or not entity_id.strip():
        return error_response(ErrorCode.BAD_PARAM, "entity_id must be a non-empty string")
    not_loaded = _ensure_loaded(loader)
    if not_loaded is not None:
        return not_loaded
    entity_id = normalize_entity_id(entity_id)

    key = loader.resolve_entity_key(entity_id)
    if key is not None:
        entity = loader.entities[key]
        rels_out = []
        for rel_type, rel_body in (entity.get("rels") or {}).items():
            for tid in rel_body.get("ids", []):
                rel = {
                    "target_id": tid,
                    "rel_type": rel_type,
                    "source": rel_body.get("source"),
                }
                if rel_body.get("tier") is not None:
                    rel["tier"] = rel_body["tier"]
                rels_out.append(rel)

        # Every field the entity carries (description, CVSS, dates,
        # references, the tip_intel blocks kev_detail/ssvc/cisa_cvss/
        # cvss_version/cvss_source, prov, campaign dates, ...) is served
        # straight from entity_index.json, so it survives absent shards.
        record = {k: v for k, v in entity.items() if k != "rels"}
        record["id"] = entity.get("id", key)
        record["type"] = entity.get("type")
        record["name"] = entity.get("name")
        record["phase"] = entity.get("phase")
        record["kev"] = bool(entity.get("kev", False))
        record["rels"] = rels_out

        meta: dict = {"source": "entity_index.json", "rel_count": len(rels_out)}
        # The shard adds what the index does not carry: D3FEND relationship
        # semantics on defend rels, and intel blocks for indexes generated
        # before the generator emitted them. enrich() never overwrites.
        if record.get("type") == "cve":
            try:
                shard_hit = loader.find_cve_in_shards(record["id"])
            except ShardReadError as exc:
                shard_hit = None
                meta["shard_error"] = str(exc)
            if shard_hit is not None:
                cve_blocks.enrich(record, shard_hit[0])
                meta["enriched_from_shard"] = True
        return ok_response(record, meta=meta)

    # Shard fallback: only for syntactically valid CVE IDs.
    if _CVE_ID_RE.match(entity_id):
        try:
            shard_hit = loader.find_cve_in_shards(entity_id)
        except ShardReadError as exc:
            return _shard_error(exc)
        if shard_hit is not None:
            payload, shard_name = shard_hit
            record = _build_shard_record(entity_id, payload, shard_name, loader)
            return ok_response(
                record,
                meta={"source": "shard", "shard": shard_name, "rel_count": len(record["rels"])},
            )

    return _not_found(loader, entity_id)


def pivot_from_entity_impl(
    loader: IndexLoader,
    entity_id: str,
    target_type: Optional[str] = None,
) -> dict:
    """Return entities related to entity_id, optionally filtered by target type.

    Falls back to the per-year CVE JSONL shard when the ID looks like a CVE
    but is not present in the enriched entity graph, so any CVE the pipeline
    has ingested can be pivoted from, not just the curated subset.
    """
    if not entity_id or not isinstance(entity_id, str) or not entity_id.strip():
        return error_response(ErrorCode.BAD_PARAM, "entity_id is required")

    want: Optional[str] = None
    if target_type is not None:
        want = normalize_type(target_type)
        if want is None:
            return error_response(
                ErrorCode.INVALID_TYPE,
                f"target_type {target_type!r} not one of {sorted(VALID_TYPES)}",
                hint="Graph names: " + ", ".join(GRAPH_TYPES) + "; aliases d3fend=defend, apt=apt_group.",
            )

    not_loaded = _ensure_loaded(loader)
    if not_loaded is not None:
        return not_loaded
    entity_id = normalize_entity_id(entity_id)

    key = loader.resolve_entity_key(entity_id)
    if key is not None:
        entity = loader.entities[key]
        hits = []
        for rel_type, rel_body in (entity.get("rels") or {}).items():
            for tid in rel_body.get("ids", []):
                target = loader.entities.get(tid)
                if target is None:
                    continue
                ttype = target.get("type")
                if want is not None and not _type_matches(want, ttype, rel_type, target):
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
    if _CVE_ID_RE.match(entity_id):
        try:
            shard_hit = loader.find_cve_in_shards(entity_id)
        except ShardReadError as exc:
            return _shard_error(exc)
        if shard_hit is not None:
            payload, shard_name = shard_hit
            hits = []
            for rel in _shard_rels(payload, loader):
                tid = rel["target_id"]
                rtype = rel["rel_type"]
                target = loader.entities.get(tid)
                if target is not None:
                    ttype = target.get("type")
                    name = target.get("name")
                else:
                    # Target not in the entity graph. Fall back to the bare ID;
                    # the rel label is already a graph type name.
                    ttype = rtype
                    name = rel.get("name") or tid
                if want is not None and not _type_matches(want, ttype, rtype, target):
                    continue
                hits.append({"id": tid, "type": ttype, "name": name, "rel_type": rtype})
            return ok_response(
                hits,
                meta={"source": "shard", "shard": shard_name, "count": len(hits)},
            )

    return _not_found(loader, entity_id)


def search_threat_intel_impl(
    loader: IndexLoader,
    query: str,
    limit: int = 20,
    types: Optional[list] = None,
) -> dict:
    """Search the inverted index by query string, ranked by match count."""
    if not query or not isinstance(query, str):
        return error_response(ErrorCode.BAD_PARAM, "query must be a non-empty string")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return error_response(ErrorCode.BAD_PARAM, "limit must be a positive integer")

    wanted: Optional[set[str]] = None
    if types:
        wanted = set()
        for t in types:
            nt = normalize_type(t)
            if nt is None:
                return error_response(
                    ErrorCode.INVALID_TYPE,
                    f"type {t!r} not one of {sorted(VALID_TYPES)}",
                )
            wanted.add(nt)

    not_loaded = _ensure_loaded(loader)
    if not_loaded is not None:
        return not_loaded

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
        if wanted is not None and not any(_type_matches(w, ttype, "", ent) for w in wanted):
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
