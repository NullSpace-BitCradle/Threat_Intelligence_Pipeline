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

    I29 shards list ids reached only through an inherited parent CWE in
    CAPEC_INHERITED, TECHNIQUES_INHERITED and OWASP_INHERITED, and flag such
    DEFEND entries; those rels carry inherited: true. CWE rels are the
    NVD-assigned CWEs only (the parents are the record's cwe_inherited), as
    in the entity index. Legacy shards produce no inherited flag.
    """
    rels: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(target_id: str, rel_type: str, source: str = "shard", inherited: bool = False) -> Optional[dict]:
        if not target_id or (target_id, rel_type) in seen:
            return None
        seen.add((target_id, rel_type))
        rel: dict = {"target_id": target_id, "rel_type": rel_type, "source": source}
        if inherited:
            rel["inherited"] = True
        rels.append(rel)
        return rel

    # Direct lists first, so an id in both is never flagged inherited.
    both = ((False, ""), (True, "_INHERITED"))
    for cwe in payload.get("CWE", []) or []:
        add(_norm_ref(cwe, "CWE-"), "cwe")
    for inh, suffix in both:
        for capec in payload.get("CAPEC" + suffix, []) or []:
            add(_norm_ref(capec, "CAPEC-"), "capec", inherited=inh)
    techniques: list[tuple[str, bool]] = []
    for inh, suffix in both:
        for tech in payload.get("TECHNIQUES" + suffix, []) or []:
            tech_id = _norm_technique(tech)
            techniques.append((tech_id, inh))
            add(tech_id, "technique", inherited=inh)
    for inh, suffix in both:
        for owasp in payload.get("OWASP" + suffix, []) or []:
            add(str(owasp).strip(), "owasp", inherited=inh)
    defends = [d for d in payload.get("DEFEND", []) or [] if isinstance(d, dict) and d.get("id")]
    for defend in sorted(defends, key=lambda d: d.get("inherited") is True):
        rel = add(str(defend["id"]), "defend", inherited=defend.get("inherited") is True)
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
        for tech_id, inh in techniques:
            tech = loader.entities.get(tech_id)
            if not tech:
                continue
            groups = (tech.get("rels") or {}).get("apt_group") or {}
            for gid in groups.get("ids", []) or []:
                add(str(gid), "apt_group", "graph (technique overlap)", inherited=inh)
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
    if "CWE_INHERITED" in payload:
        record["cwe_inherited"] = [_norm_ref(c, "CWE-") for c in payload.get("CWE_INHERITED") or []]
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
            marked = set(rel_body.get("inherited") or [])
            for tid in rel_body.get("ids", []):
                rel = {
                    "target_id": tid,
                    "rel_type": rel_type,
                    "source": rel_body.get("source"),
                }
                if rel_body.get("tier") is not None:
                    rel["tier"] = rel_body["tier"]
                if tid in marked:
                    rel["inherited"] = True
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
            marked = set(rel_body.get("inherited") or [])
            for tid in rel_body.get("ids", []):
                target = loader.entities.get(tid)
                if target is None:
                    continue
                ttype = target.get("type")
                if want is not None and not _type_matches(want, ttype, rel_type, target):
                    continue
                hit = {
                    "id": target.get("id", tid),
                    "type": ttype,
                    "name": target.get("name"),
                    "rel_type": rel_type,
                    # Provenance of the link itself (additive), so a
                    # derived mapping never reads as a stated fact.
                    "source": rel_body.get("source"),
                    "tier": rel_body.get("tier"),
                }
                # Additive (I29): reached only through an inherited parent CWE.
                if tid in marked:
                    hit["inherited"] = True
                hits.append(hit)
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
                shard_hit_rel = {
                    "id": tid,
                    "type": ttype,
                    "name": name,
                    "rel_type": rtype,
                    # Shard enrichment lists are pipeline output, not a
                    # source's own statement, so they are derived.
                    "source": "Pipeline (shard enrichment)",
                    "tier": "derived",
                }
                if rel.get("inherited"):
                    shard_hit_rel["inherited"] = True
                hits.append(shard_hit_rel)
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


# Provenance tiers, strongest first. An element composed of several hops is
# only as strong as its weakest hop; an unknown tier ranks below derived.
TIER_RANK = {"authoritative": 3, "official": 2, "derived": 1}
INHERITED_SOURCE = "TIP generator (CAPEC inherited from a CWE ChildOf ancestor)"
INHERITED_CWE_SOURCE = "TIP processor (CWE inherited as a ChildOf parent of an NVD-assigned CWE)"
UNVERIFIED_SOURCE = "TIP graph (CWE to CAPEC hop unverified: cwe_db.json unavailable)"
SHARD_TECHNIQUE_SOURCE = "shard (pipeline CAPEC→Technique enrichment)"
SHARD_DEFEND_SOURCE = "shard (pipeline Technique→D3FEND enrichment)"

Hop = tuple[Any, Any]  # (source, tier)


def _weakest(hops: list[Hop]) -> Hop:
    """The (source, tier) of the weakest hop; the first one wins a tie."""
    return min(hops, key=lambda h: TIER_RANK.get(h[1], 0) if isinstance(h[1], str) else 0)


def _kev_listed(entry: Optional[dict]) -> bool:
    """Whether a kev_db.json entry means "in the catalog". The catalog is
    membership, so an entry without inKEV counts as listed."""
    return entry is not None and bool(entry.get("inKEV", True))


def _kev_flag(loader: IndexLoader, cve_id: str, ent: Optional[dict]) -> bool:
    """KEV membership from kev_db.json when it is available, else the graph."""
    kev_db = loader.kev_db
    if kev_db is not None:
        return _kev_listed(kev_db.get(cve_id.upper()))
    return bool((ent or {}).get("kev"))


def _rels_to(loader: IndexLoader, eid: str, rel_type: str, back_rel: str) -> dict[str, Hop]:
    """Targets of eid's rel_type rels plus rel_type entities whose back_rel
    rels name eid, as target id -> weakest (source, tier) over both
    directions."""
    out: dict[str, Hop] = {}
    body = ((loader.entities.get(eid) or {}).get("rels") or {}).get(rel_type) or {}
    for tid in body.get("ids", []) or []:
        out[str(tid)] = (body.get("source"), body.get("tier"))
    for src_id, rtype, source, tier in loader.reverse_adjacency.get(eid, {}).get(rel_type, []):
        if rtype == back_rel:
            out[src_id] = _weakest([out[src_id], (source, tier)]) if src_id in out else (source, tier)
    return out


def _bare(ref: str) -> str:
    """Strip the prefix from a CWE or CAPEC id; cwe_db.json uses bare numbers."""
    return ref.split("-", 1)[1] if "-" in ref else ref


def build_attack_chain_impl(
    loader: IndexLoader, technique_id: str, limit: int = DEFAULT_CHAIN_LIMIT
) -> dict:
    """The CVEs the graph links to a technique, each explained by the CWE and
    CAPEC path that connects it, plus the technique's D3FEND defenses.

    The CVE set is exactly the technique's own cve rels. The CAPECs are those
    whose capec -> technique rel names the technique (the graph stores that
    edge on the CAPEC, so the loader's reverse adjacency finds it). For each
    CVE, via_cwes are its CWEs that link to one of those CAPECs and
    via_capecs the CAPECs reached; a CVE with no such CWE still appears, with
    empty via lists. cwes lists only the CWEs some returned CVE goes through.

    Every element carries the source and tier of its weakest hop. A CWE to
    CAPEC hop not in the CWE's own RelatedAttackPatterns (cwe_db.json) was
    inherited from a ChildOf ancestor by the generator: the CWE is flagged
    inherited and its tier is derived. CVEs are ordered KEV first, then CVSS
    descending, then id. Each list is capped at `limit`; meta.totals carries
    the uncapped counts.
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
    tech = loader.entities[key]
    related = loader.cwe_related_capecs

    # CAPECs whose capec -> technique rel names this technique.
    capecs: dict[str, dict] = {}
    for src_id, rel_type, source, tier in loader.reverse_adjacency.get(key, {}).get("capec", []):
        if rel_type == "technique" and src_id not in capecs:
            capecs[src_id] = {"id": src_id, "name": _name(loader, src_id), "source": source, "tier": tier}

    cwe_cache: dict[str, Optional[dict]] = {}

    def cwe_entry(cwe_id: str) -> Optional[dict]:
        """The chain element for a CWE, or None when it reaches no chain CAPEC."""
        if cwe_id in cwe_cache:
            return cwe_cache[cwe_id]
        links = _rels_to(loader, cwe_id, "capec", "cwe")
        hits = sorted((c for c in links if c in capecs), key=_id_key)
        entry: Optional[dict] = None
        if hits:
            inherited: Optional[bool]
            hops: list[Hop]
            if loader.inherited_links:
                # The index names the ancestor-inherited CAPECs itself (I29).
                cbody = ((loader.entities.get(cwe_id) or {}).get("rels") or {}).get("capec") or {}
                marked = {str(c) for c in cbody.get("inherited") or []}
                inherited_capecs = [c for c in hits if c in marked]
                inherited = bool(inherited_capecs)
                hops = [(INHERITED_SOURCE, "derived")] if inherited else []
            elif related is None:
                inherited, inherited_capecs = None, []
                hops = [(UNVERIFIED_SOURCE, "derived")]
            else:
                own = related.get(_bare(cwe_id), frozenset())
                inherited_capecs = [c for c in hits if _bare(c) not in own]
                inherited = bool(inherited_capecs)
                hops = [(INHERITED_SOURCE, "derived")] if inherited else []
            hops += [links[c] for c in hits]
            hops += [(capecs[c]["source"], capecs[c]["tier"]) for c in hits]
            source, tier = _weakest(hops)
            entry = {
                "id": cwe_id,
                "name": _name(loader, cwe_id),
                "via_capecs": hits,
                "inherited": inherited,
                "inherited_capecs": inherited_capecs,
                "source": source,
                "tier": tier,
            }
        cwe_cache[cwe_id] = entry
        return entry

    tbody = (tech.get("rels") or {}).get("cve") or {}
    tech_cve_hop: Hop = (tbody.get("source"), tbody.get("tier"))
    own_cves = list(dict.fromkeys(str(c) for c in tbody.get("ids", []) or []))
    tech_inherited = {str(c) for c in tbody.get("inherited") or []}

    cves: list[dict] = []
    cwes: dict[str, dict] = {}
    parent_cwes: set[str] = set()
    for cve_id in own_cves:
        ent = loader.entities.get(cve_id) or {}
        via_cwes: list[str] = []
        via_capecs: set[str] = set()
        inherited_cwes: list[str] = []
        hops = [tech_cve_hop]
        cve_cwes = _rels_to(loader, cve_id, "cwe", "cve")
        for cwe_id in sorted(cve_cwes, key=_id_key):
            ce = cwe_entry(cwe_id)
            if ce is None:
                continue
            via_cwes.append(cwe_id)
            via_capecs.update(ce["via_capecs"])
            cwes[cwe_id] = ce
            hops += [cve_cwes[cwe_id], (ce["source"], ce["tier"])]
        if not via_cwes:
            # No NVD-assigned CWE explains the CVE: fall back to its
            # inherited parent CWEs (I29), flagged and derived.
            for cwe_id in sorted((str(c) for c in ent.get("cwe_inherited") or []), key=_id_key):
                ce = cwe_entry(cwe_id)
                if ce is None:
                    continue
                via_cwes.append(cwe_id)
                inherited_cwes.append(cwe_id)
                via_capecs.update(ce["via_capecs"])
                cwes[cwe_id] = ce
                parent_cwes.add(cwe_id)
                hops += [(INHERITED_CWE_SOURCE, "derived"), (ce["source"], ce["tier"])]
        source, tier = _weakest(hops)
        element = {
            "id": cve_id,
            "name": ent.get("name"),
            "kev": _kev_flag(loader, cve_id, ent),
            "cvss_score": ent.get("cvss_score"),
            "severity": ent.get("severity"),
            "via_cwes": via_cwes,
            "via_capecs": sorted(via_capecs, key=_id_key),
            "source": source,
            "tier": tier,
        }
        # Additive (I29), present only when true.
        if inherited_cwes:
            element["inherited_cwes"] = inherited_cwes
        if cve_id in tech_inherited:
            element["inherited"] = True
        cves.append(element)
    for cwe_id in parent_cwes:
        # Some returned CVE is explained through this CWE as an inherited
        # parent; each such CVE names it in inherited_cwes.
        cwes[cwe_id]["inherited_parent"] = True

    defenses = [
        {"id": did, "name": _name(loader, did), "source": source, "tier": tier}
        for did, source, tier in _technique_defenses(loader, key)
    ]

    capec_list = sorted(capecs.values(), key=lambda c: _id_key(c["id"]))
    cwe_list = sorted(cwes.values(), key=lambda c: _id_key(c["id"]))
    cve_list = sorted(
        cves,
        key=lambda c: (
            not c["kev"],
            c["cvss_score"] is None,
            -(c["cvss_score"] or 0),
            _id_key(c["id"]),
        ),
    )
    defense_list = sorted(defenses, key=lambda d: _id_key(d["id"]))
    unexplained = sum(1 for c in cve_list if not c["via_cwes"])
    totals = {
        "capecs": len(capec_list),
        "cwes": len(cwe_list),
        "cves": len(cve_list),
        "defenses": len(defense_list),
    }
    meta: dict = {
        "source": "entity_index.json",
        "walk": (
            "cves: the technique's own cve rels; each explained by cve -> cwe -> "
            "capec -> technique; defenses: technique -> defend"
        ),
        "totals": totals,
        "cves_without_path": unexplained,
        "limit": limit,
        "truncated": any(n > limit for n in totals.values()),
    }
    if related is None and not loader.inherited_links:
        meta["cwe_db_note"] = (
            "cwe_db.json unavailable, so CWE to CAPEC hops cannot be checked against "
            "each CWE's own RelatedAttackPatterns; they are marked unverified and derived."
        )
    if not capec_list:
        note = (
            f"No CAPEC pattern maps to {key} in the TIP graph, so no weakness path can "
            "be derived from it."
        )
        if cve_list:
            note += f" Its {len(cve_list)} linked CVEs are listed without a CAPEC or CWE path."
        meta["note"] = note + " Defenses come from the technique's own D3FEND mappings."
    elif not cve_list:
        meta["note"] = f"No CVE in the TIP graph is linked to {key}."
    elif not cwe_list:
        meta["note"] = (
            f"CAPEC patterns map to {key}, but no CWE on its linked CVEs reaches those "
            "patterns, so its CVEs are listed with no CWE path."
        )
    elif unexplained:
        meta["note"] = (
            f"{unexplained} of the {len(cve_list)} CVEs linked to {key} have no CWE path "
            "to its CAPEC patterns; their via lists are empty."
        )
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
    """(defend id, source, tier) for a technique over forward and reverse
    edges, keeping the weaker provenance when both directions exist."""
    links = _rels_to(loader, tech_id, "defend", "technique")
    return [(did, hop[0], hop[1]) for did, hop in links.items()]


def get_defenses_impl(
    loader: IndexLoader,
    technique_id: Any = None,
    cve_id: Any = None,
) -> dict:
    """D3FEND defenses for exactly one of technique_id or cve_id.

    For a technique: its D3FEND mappings with their own provenance. For a
    CVE: the defenses of each ATT&CK technique the CVE maps to, each naming
    the techniques it was reached through (via_techniques), plus any defense
    only on the CVE's own defend rels (via_techniques empty). A CVE-side
    defense carries the weakest tier of CVE -> technique and technique ->
    D3FEND (and of the CVE's own rel to it), and mapping_source names that
    composed path. The D3FEND relationship verb is added when the CVE's
    shard carries one.
        Arguments arrive from MCP clients unvalidated, hence Any: a non-string is
    bad_param.
    """
    for arg in (technique_id, cve_id):
        if arg is not None and not isinstance(arg, str):
            return error_response(ErrorCode.BAD_PARAM, "technique_id and cve_id must be strings")
    given = [a for a in (technique_id, cve_id) if a is not None and a.strip()]
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

    # (technique id, source, tier, inherited) of each CVE -> technique hop,
    # and (defend id, source, tier, inherited) of the CVE's own defend rels.
    techniques: list[tuple[str, Any, Any, bool]] = []
    own: list[tuple[str, Any, Any, bool]] = []
    payload: Optional[dict] = None
    key = loader.resolve_entity_key(cid)
    if key is not None:
        cid = key
        rels = loader.entities[key].get("rels") or {}
        tbody = rels.get("technique") or {}
        tinh = {str(t) for t in tbody.get("inherited") or []}
        techniques = [(str(t), tbody.get("source"), tbody.get("tier"), str(t) in tinh)
                      for t in tbody.get("ids", []) or []]
        dbody = rels.get("defend") or {}
        dinh = {str(d) for d in dbody.get("inherited") or []}
        own = [(str(d), dbody.get("source"), dbody.get("tier"), str(d) in dinh)
               for d in dbody.get("ids", []) or []]
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
                inh = bool(rel.get("inherited"))
                if rel["rel_type"] == "technique":
                    techniques.append((rel["target_id"], SHARD_TECHNIQUE_SOURCE, "derived", inh))
                elif rel["rel_type"] == "defend":
                    own.append((rel["target_id"], SHARD_DEFEND_SOURCE, "derived", inh))
    if key is None and shard_hit is None:
        return _not_found(loader, cid)

    verbs = _defend_verbs(payload) if payload else {}
    out: dict[str, dict] = {}
    hops: dict[str, list[Hop]] = {}
    paths: dict[str, list[str]] = {}
    # Defenses reached by at least one direct link, and by an inherited one.
    reached_direct: set[str] = set()
    reached_inherited: set[str] = set()

    def entry(did: str) -> dict:
        if did not in out:
            out[did] = {
                "id": did,
                "name": _name(loader, did) or (verbs.get(did) or {}).get("name"),
                "via_techniques": [],
            }
            if (verbs.get(did) or {}).get("relationship") is not None:
                out[did]["relationship"] = verbs[did]["relationship"]
            hops[did], paths[did] = [], []
        return out[did]

    for tech_id, tsource, ttier, tinherited in techniques:
        for did, dsource, dtier in _technique_defenses(loader, tech_id):
            e = entry(did)
            (reached_inherited if tinherited else reached_direct).add(did)
            if tech_id not in e["via_techniques"]:
                e["via_techniques"].append(tech_id)
            hops[did] += [(tsource, ttier), (dsource, dtier)]
            path = f"CVE→technique: {tsource}; technique→D3FEND: {dsource}"
            if path not in paths[did]:
                paths[did].append(path)
    for did, source, tier, dinherited in own:
        entry(did)
        (reached_inherited if dinherited else reached_direct).add(did)
        hops[did].append((source, tier))
        if not paths[did]:
            paths[did].append(str(source))

    for did, e in out.items():
        e["mapping_source"] = " | ".join(paths[did])
        e["tier"] = _weakest(hops[did])[1]
        # Additive (I29): reached only through an inherited parent CWE.
        if did in reached_inherited and did not in reached_direct:
            e["inherited"] = True

    defs = sorted(out.values(), key=lambda d: _id_key(d["id"]))
    meta["count"] = len(defs)
    meta["techniques"] = list(dict.fromkeys(t[0] for t in techniques))
    meta["path"] = "cve -> technique -> defend; each defense carries the weakest tier on its path"
    if not techniques:
        meta["note"] = f"{cid} maps to no ATT&CK technique, so only its own D3FEND rels are listed."
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
        detail = entry if _kev_listed(entry) else None
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
