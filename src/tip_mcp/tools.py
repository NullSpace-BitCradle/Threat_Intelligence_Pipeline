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
    types: Any = None,
) -> dict:
    """Search the inverted index by query string, ranked by match count.

    ``types`` arrives from MCP clients unvalidated, so it is typed Any and
    checked here: None or a list of type names.
    """
    if not query or not isinstance(query, str):
        return error_response(ErrorCode.BAD_PARAM, "query must be a non-empty string")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return error_response(ErrorCode.BAD_PARAM, "limit must be a positive integer")

    if types is not None and not isinstance(types, list):
        return error_response(
            ErrorCode.BAD_PARAM,
            f"types must be a list of type names, got {type(types).__name__}",
        )

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


# Phase B tools: build_attack_chain, get_defenses, kev_status. Each is a thin
# projection of the entity graph (plus kev_db.json and the shards); none
# carries a mapping of its own.

DEFAULT_CHAIN_LIMIT = 50
_NUM_SPLIT_RE = re.compile(r"(\d+)")


def _id_key(value: str) -> list:
    """Natural sort key so numbered ids order numerically, not lexically."""
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in _NUM_SPLIT_RE.split(value)]


def _bad_limit(limit: Any) -> Optional[dict]:
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return error_response(ErrorCode.BAD_PARAM, "limit must be a positive integer")
    return None


def _resolve_typed(loader: IndexLoader, raw_id: Any, want_type: str, arg: str) -> "tuple[Optional[str], Optional[dict]]":
    """Resolve raw_id to a graph key of want_type. Returns (key, None) or
    (None, error envelope) for a bad, unknown, or wrongly typed id."""
    if not isinstance(raw_id, str) or not raw_id.strip():
        return None, error_response(ErrorCode.BAD_PARAM, f"{arg} must be a non-empty string")
    entity_id = normalize_entity_id(raw_id)
    key = loader.resolve_entity_key(entity_id)
    if key is None:
        return None, error_response(
            ErrorCode.NOT_FOUND,
            f"{want_type} {entity_id!r} not in entity graph",
            hint="Use search_threat_intel to find the id first.",
        )
    ttype = loader.entities[key].get("type")
    if ttype != want_type:
        return None, error_response(
            ErrorCode.INVALID_TYPE,
            f"{entity_id!r} is a {ttype}, not a {want_type}",
            hint=f"{arg} takes an ATT&CK technique id." if want_type == "technique" else None,
        )
    return key, None


def _name(loader: IndexLoader, eid: str) -> Any:
    ent = loader.entities.get(eid)
    return ent.get("name") if ent else None


def _capped(items: list, limit: int) -> list:
    return items[:limit]


def build_attack_chain_impl(
    loader: IndexLoader, technique_id: str, limit: int = DEFAULT_CHAIN_LIMIT
) -> dict:
    """Walk technique <- CAPEC <- CWE -> CVE, plus the technique's D3FEND
    defenses, and return each list ordered with the edge provenance it was
    reached by.

    The graph stores capec -> technique and cwe -> capec only, so the walk
    uses the loader's reverse adjacency for those two hops and the forward
    cwe -> cve (and reverse cve -> cwe) edges for the last one. CVEs are
    ordered KEV first, then CVSS descending, then id. Each list is capped at
    `limit`; meta.totals carries the uncapped counts.
    """
    bad = _bad_limit(limit)
    if bad is not None:
        return bad
    if not isinstance(technique_id, str) or not technique_id.strip():
        return error_response(ErrorCode.BAD_PARAM, "technique_id must be a non-empty string")
    not_loaded = _ensure_loaded(loader)
    if not_loaded is not None:
        return not_loaded
    key, err = _resolve_typed(loader, technique_id, "technique", "technique_id")
    if err is not None or key is None:
        return err or error_response(ErrorCode.NOT_FOUND, "technique not found")
    rev = loader.reverse_adjacency
    tech = loader.entities[key]

    # technique <- capec: CAPEC entities whose technique rels name this technique.
    capecs: dict[str, dict] = {}
    for src_id, rel_type, source, tier in rev.get(key, {}).get("capec", []):
        if rel_type == "technique" and src_id not in capecs:
            capecs[src_id] = {
                "id": src_id,
                "name": _name(loader, src_id),
                "source": source,
                "tier": tier,
            }

    # capec <- cwe: CWE entities whose capec rels name one of those CAPECs.
    cwes: dict[str, dict] = {}
    for capec_id in sorted(capecs, key=_id_key):
        for src_id, rel_type, source, tier in rev.get(capec_id, {}).get("cwe", []):
            if rel_type != "capec":
                continue
            if src_id not in cwes:
                cwes[src_id] = {
                    "id": src_id,
                    "name": _name(loader, src_id),
                    "via_capecs": [],
                    "source": source,
                    "tier": tier,
                }
            if capec_id not in cwes[src_id]["via_capecs"]:
                cwes[src_id]["via_capecs"].append(capec_id)

    # cwe -> cve: forward edges on the CWE, plus CVEs whose cwe rels name it.
    cves: dict[str, dict] = {}
    kev_db = loader.kev_db or {}

    def add_cve(cve_id: str, cwe_id: str, source: Any, tier: Any) -> None:
        if cve_id not in cves:
            ent = loader.entities.get(cve_id) or {}
            kev = bool(ent.get("kev")) or bool((kev_db.get(cve_id.upper()) or {}).get("inKEV"))
            cves[cve_id] = {
                "id": cve_id,
                "name": ent.get("name"),
                "kev": kev,
                "cvss_score": ent.get("cvss_score"),
                "severity": ent.get("severity"),
                "via_cwes": [],
                "source": source,
                "tier": tier,
            }
        if cwe_id not in cves[cve_id]["via_cwes"]:
            cves[cve_id]["via_cwes"].append(cwe_id)

    for cwe_id in sorted(cwes, key=_id_key):
        body = (loader.entities.get(cwe_id, {}).get("rels") or {}).get("cve") or {}
        for cve_id in body.get("ids", []) or []:
            add_cve(str(cve_id), cwe_id, body.get("source"), body.get("tier"))
        for src_id, rel_type, source, tier in rev.get(cwe_id, {}).get("cve", []):
            if rel_type == "cwe":
                add_cve(src_id, cwe_id, source, tier)

    # technique -> defend, plus D3FEND entities whose technique rels name it.
    defenses: dict[str, dict] = {}
    dbody = (tech.get("rels") or {}).get("defend") or {}
    for did in dbody.get("ids", []) or []:
        defenses.setdefault(
            str(did),
            {"id": str(did), "name": _name(loader, str(did)), "source": dbody.get("source"), "tier": dbody.get("tier")},
        )
    for src_id, rel_type, source, tier in rev.get(key, {}).get("defend", []):
        if rel_type == "technique":
            defenses.setdefault(
                src_id, {"id": src_id, "name": _name(loader, src_id), "source": source, "tier": tier}
            )

    capec_list = sorted(capecs.values(), key=lambda c: _id_key(c["id"]))
    cwe_list = sorted(cwes.values(), key=lambda c: _id_key(c["id"]))
    cve_list = sorted(
        cves.values(),
        key=lambda c: (
            not c["kev"],
            c["cvss_score"] is None,
            -(c["cvss_score"] or 0),
            _id_key(c["id"]),
        ),
    )
    defense_list = sorted(defenses.values(), key=lambda d: _id_key(d["id"]))
    totals = {
        "capecs": len(capec_list),
        "cwes": len(cwe_list),
        "cves": len(cve_list),
        "defenses": len(defense_list),
    }
    meta: dict = {
        "source": "entity_index.json",
        "walk": "technique <- capec <- cwe -> cve; technique -> defend",
        "totals": totals,
        "limit": limit,
        "truncated": any(n > limit for n in totals.values()),
    }
    if not capec_list:
        meta["note"] = (
            f"No CAPEC pattern maps to {key} in the TIP graph, so no weakness or CVE "
            "chain can be derived from it. Defenses come from the technique's own "
            "D3FEND mappings."
        )
    elif not cwe_list:
        meta["note"] = (
            f"CAPEC patterns map to {key}, but no CWE in the TIP graph links to "
            "those patterns, so no CVE chain can be derived."
        )
    elif not cve_list:
        meta["note"] = f"No CVE in the TIP graph links to the weaknesses behind {key}."
    data = {
        "technique": {"id": key, "name": tech.get("name")},
        "capecs": _capped(capec_list, limit),
        "cwes": _capped(cwe_list, limit),
        "cves": _capped(cve_list, limit),
        "defenses": _capped(defense_list, limit),
    }
    return ok_response(data, meta=meta)


def _defend_verbs(payload: dict) -> dict:
    """D3FEND relationship verbs from a shard payload, keyed by D3FEND id and
    by fragment name (graphs have used both as the entity id)."""
    out = dict(cve_blocks.defend_semantics(payload))
    for defend in payload.get("DEFEND", []) or []:
        if isinstance(defend, dict) and defend.get("d3fend_fragment") and defend.get("id"):
            sem = out.get(str(defend["id"]))
            if sem:
                out.setdefault(str(defend["d3fend_fragment"]), sem)
    return out


def _technique_defenses(loader: IndexLoader, tech_id: str) -> list[tuple[str, Any, Any]]:
    """(defend id, source, tier) for a technique, forward and reverse edges."""
    out: dict[str, tuple[str, Any, Any]] = {}
    tech = loader.entities.get(tech_id)
    if tech is not None:
        body = (tech.get("rels") or {}).get("defend") or {}
        for did in body.get("ids", []) or []:
            out.setdefault(str(did), (str(did), body.get("source"), body.get("tier")))
    for src_id, rel_type, source, tier in loader.reverse_adjacency.get(tech_id, {}).get("defend", []):
        if rel_type == "technique":
            out.setdefault(src_id, (src_id, source, tier))
    return list(out.values())


def get_defenses_impl(
    loader: IndexLoader,
    technique_id: Optional[str] = None,
    cve_id: Optional[str] = None,
) -> dict:
    """D3FEND defenses for exactly one of technique_id or cve_id.

    For a technique: its D3FEND mappings. For a CVE: the defenses of each
    ATT&CK technique the CVE maps to (each defense names the techniques it
    was reached through) plus the CVE's own defend rels, decorated with the
    D3FEND relationship verb when the CVE's shard carries one.
    """
    given = [a for a in (technique_id, cve_id) if a is not None and not (isinstance(a, str) and not a.strip())]
    if len(given) != 1:
        return error_response(
            ErrorCode.BAD_PARAM,
            "pass exactly one of technique_id or cve_id",
        )
    not_loaded = _ensure_loaded(loader)
    if not_loaded is not None:
        return not_loaded

    if technique_id is not None and technique_id.strip():
        key, err = _resolve_typed(loader, technique_id, "technique", "technique_id")
        if err is not None or key is None:
            return err or error_response(ErrorCode.NOT_FOUND, "technique not found")
        defs = [
            {
                "id": did,
                "name": _name(loader, did),
                "mapping_source": source,
                "tier": tier,
                "via_techniques": [key],
            }
            for did, source, tier in _technique_defenses(loader, key)
        ]
        defs.sort(key=lambda d: _id_key(d["id"]))
        return ok_response(
            defs,
            meta={"source": "entity_index.json", "query": {"technique_id": key}, "count": len(defs)},
        )

    if not isinstance(cve_id, str) or not _CVE_ID_RE.match(cve_id.strip()):
        return error_response(
            ErrorCode.BAD_PARAM,
            f"cve_id {cve_id!r} is not a valid CVE id",
            hint="Expected CVE-YYYY-NNNN.",
        )
    cid = normalize_entity_id(cve_id)
    meta: dict = {"query": {"cve_id": cid}}

    techniques: list[str] = []
    direct: list[tuple[str, Any, Any]] = []
    payload: Optional[dict] = None
    key = loader.resolve_entity_key(cid)
    if key is not None:
        cid = key
        rels = loader.entities[key].get("rels") or {}
        techniques = [str(t) for t in (rels.get("technique") or {}).get("ids", []) or []]
        dbody = rels.get("defend") or {}
        direct = [(str(d), dbody.get("source"), dbody.get("tier")) for d in dbody.get("ids", []) or []]
        meta["source"] = "entity_index.json"
    try:
        shard_hit = loader.find_cve_in_shards(cid)
    except ShardReadError as exc:
        if key is None:
            return _shard_error(exc)
        shard_hit = None
        meta["shard_error"] = str(exc)
    if shard_hit is not None:
        payload = shard_hit[0]
        if key is None:
            meta["source"] = "shard"
            meta["shard"] = shard_hit[1]
            for rel in _shard_rels(payload):
                if rel["rel_type"] == "technique":
                    techniques.append(rel["target_id"])
                elif rel["rel_type"] == "defend":
                    direct.append((rel["target_id"], "shard", None))
    if key is None and shard_hit is None:
        return _not_found(loader, cid)

    verbs = _defend_verbs(payload) if payload else {}
    out: dict[str, dict] = {}

    def entry(did: str, source: Any, tier: Any) -> dict:
        if did not in out:
            out[did] = {
                "id": did,
                "name": _name(loader, did) or (verbs.get(did) or {}).get("name"),
                "mapping_source": source,
                "tier": tier,
                "via_techniques": [],
                "direct": False,
            }
            if (verbs.get(did) or {}).get("relationship") is not None:
                out[did]["relationship"] = verbs[did]["relationship"]
        return out[did]

    for tech_id in techniques:
        for did, source, tier in _technique_defenses(loader, tech_id):
            e = entry(did, source, tier)
            if tech_id not in e["via_techniques"]:
                e["via_techniques"].append(tech_id)
    for did, source, tier in direct:
        entry(did, source, tier)["direct"] = True

    defs = sorted(out.values(), key=lambda d: _id_key(d["id"]))
    meta["count"] = len(defs)
    meta["techniques"] = techniques
    if not techniques:
        meta["note"] = f"{cid} maps to no ATT&CK technique, so only its direct D3FEND rels are listed."
    return ok_response(defs, meta=meta)


_KEV_FIELDS = (
    ("date_added", "dateAdded"),
    ("due_date", "dueDate"),
    ("known_ransomware_campaign_use", "knownRansomwareCampaignUse"),
    ("required_action", "requiredAction"),
    ("vendor_project", "vendorProject"),
    ("product", "product"),
)


def kev_status_impl(loader: IndexLoader, cve_id: str) -> dict:
    """CISA KEV status for a CVE, plus its SSVC decision when known.

    KEV membership and detail come from kev_db.json (the CISA catalog), so a
    KEV CVE outside the curated graph still reports in_kev true. When
    kev_db.json is unavailable the entity graph's kev flag is used and meta
    says so. SSVC comes from the entity record, else the CVE's shard.
    """
    if not isinstance(cve_id, str) or not _CVE_ID_RE.match(cve_id.strip()):
        return error_response(
            ErrorCode.BAD_PARAM,
            f"cve_id {cve_id!r} is not a valid CVE id",
            hint="Expected CVE-YYYY-NNNN.",
        )
    not_loaded = _ensure_loaded(loader)
    if not_loaded is not None:
        return not_loaded
    cid = normalize_entity_id(cve_id)
    meta: dict = {}

    key = loader.resolve_entity_key(cid)
    ent = loader.entities[key] if key is not None else None
    payload: Optional[dict] = None
    try:
        hit = loader.find_cve_in_shards(cid)
    except ShardReadError as exc:
        hit = None
        meta["shard_error"] = str(exc)
    if hit is not None:
        payload = hit[0]

    kev_db = loader.kev_db
    detail: Optional[dict]
    if kev_db is not None:
        entry = kev_db.get(cid)
        detail = entry if entry is not None and entry.get("inKEV", True) else None
        meta["kev_source"] = "kev_db.json"
    else:
        detail = (ent or {}).get("kev_detail") or (cve_blocks.kev_detail(payload) if payload else None)
        in_graph_kev = bool((ent or {}).get("kev")) or detail is not None
        if in_graph_kev and detail is None:
            detail = {}
        meta["kev_source"] = "entity_index.json" if ent is not None else ("shard" if payload else None)
        meta["note"] = "kev_db.json unavailable; KEV status taken from the entity graph or shard."

    data: dict = {"cve_id": cid, "in_kev": detail is not None}
    for out_key, src_key in _KEV_FIELDS:
        data[out_key] = (detail or {}).get(src_key)

    ssvc = (ent or {}).get("ssvc")
    ssvc_source: Optional[str] = "entity_index.json" if ssvc else None
    if not ssvc and payload is not None:
        ssvc = cve_blocks.ssvc_block(payload)
        ssvc_source = "shard" if ssvc else None
    data["ssvc"] = ssvc or None
    meta["ssvc_source"] = ssvc_source
    meta["in_entity_graph"] = ent is not None
    if ent is None and payload is None:
        meta.setdefault(
            "note",
            f"{cid} is not in the entity graph or the shards; KEV status is from the catalog only.",
        )
    return ok_response(data, meta=meta)
