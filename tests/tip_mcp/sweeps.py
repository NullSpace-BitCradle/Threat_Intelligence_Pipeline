"""Graph-wide sweeps for the F5 review closures (ISC-25, ISC-26).

Shared by the fixture tests and the probe on a regenerated real index, so
the same check runs on both. Each sweep checks the tools against the graph
itself, not against the tools' own labels.
"""

from __future__ import annotations

from typing import Any

from tip_intel.link_tiers import CTID_SOURCE, TIER_RANK
from tip_mcp.loader import IndexLoader, link_provenance
from tip_mcp.tools import (
    build_attack_chain_impl,
    get_defenses_impl,
    lookup_entity_impl,
    pivot_from_entity_impl,
)

STRONG = ("authoritative", "official")
BIG = 10**9


def _rel(loader: IndexLoader, eid: str, rel_type: str) -> dict:
    return ((loader.entities.get(eid) or {}).get("rels") or {}).get(rel_type) or {}


def _per_link(loader: IndexLoader, eid: str, rel_type: str, tid: str) -> bool:
    """Whether the graph gives this link its own provenance (I21 link_prov)."""
    return tid in (_rel(loader, eid, rel_type).get("link_prov") or {})


def _link_tier(loader: IndexLoader, eid: str, rel_type: str, tid: str) -> object:
    return link_provenance(_rel(loader, eid, rel_type), tid)["tier"]


def chain_cve_mismatches(loader: IndexLoader) -> list[dict]:
    """Techniques whose chain CVE set differs from their own cve rels, or
    from pivot_from_entity(technique, "cve")."""
    bad = []
    for tid, ent in loader.entities.items():
        if ent.get("type") != "technique":
            continue
        own = {str(c) for c in _rel(loader, tid, "cve").get("ids", []) or []}
        resp = build_attack_chain_impl(loader, tid, limit=BIG)
        got = {c["id"] for c in resp["data"]["cves"]}
        pivot = {h["id"] for h in pivot_from_entity_impl(loader, tid, "cve")["data"]}
        # pivot drops rels whose target is not an entity; compare on those.
        known_own = {c for c in own if c in loader.entities}
        if got != own or pivot != known_own or resp["meta"]["totals"]["cves"] != len(own):
            bad.append({"technique": tid, "own": len(own), "chain": len(got), "extra": sorted(got - own)[:5]})
    return bad


def chain_tier_violations(loader: IndexLoader, tid: str, chain: dict) -> list[dict]:
    """Chain elements labeled authoritative/official although a hop on their
    path is derived, inherited, or unverified. Hop tiers are read from the
    graph, not from the element."""
    out: list[dict] = []
    cwes = {c["id"]: c for c in chain["cwes"]}
    related = loader.cwe_related_capecs
    for cwe in chain["cwes"]:
        # Recompute "inherited" from cwe_db.json rather than trust the flag.
        inherited = None
        if related is not None:
            own = related.get(cwe["id"].split("-", 1)[1], frozenset())
            inherited = any(c.split("-", 1)[1] not in own for c in cwe["via_capecs"])
        if cwe["inherited"] != inherited:
            out.append({"technique": tid, "kind": "cwe-inherited-flag", "id": cwe["id"], "flag": cwe["inherited"]})
        hops = [_rel(loader, cwe["id"], "capec").get("tier")]
        if inherited is not False:
            hops.append("derived")
        for capec_id in cwe["via_capecs"]:
            hops.append(_rel(loader, capec_id, "technique").get("tier"))
        if cwe["tier"] in STRONG and any(h not in STRONG for h in hops):
            out.append({"technique": tid, "kind": "cwe", "id": cwe["id"], "tier": cwe["tier"]})
    for cve in chain["cves"]:
        # I21: a CTID or inferred link is labeled by the link alone, and
        # must carry exactly the graph's provenance for it.
        link = link_provenance(_rel(loader, tid, "cve"), cve["id"])
        if _per_link(loader, tid, "cve", cve["id"]):
            if (cve["tier"], cve["source"]) != (link["tier"], link["source"]):
                out.append({"technique": tid, "kind": "cve-link", "id": cve["id"], "tier": cve["tier"]})
            continue
        hops = [link["tier"]]
        if cve.get("inherited_cwes"):
            hops.append("derived")
        for cwe_id in cve["via_cwes"]:
            hops.append(cwes[cwe_id]["tier"] if cwe_id in cwes else None)
        if cve["tier"] in STRONG and any(h not in STRONG for h in hops):
            out.append({"technique": tid, "kind": "cve", "id": cve["id"], "tier": cve["tier"]})
    for capec in chain["capecs"]:
        if capec["tier"] in STRONG and _rel(loader, capec["id"], "technique").get("tier") not in STRONG:
            out.append({"technique": tid, "kind": "capec", "id": capec["id"], "tier": capec["tier"]})
    return out


def chain_inherited_cwe_violations(loader: IndexLoader) -> list[dict]:
    """I29: a chain CVE is explained through inherited CWEs only when none
    of its NVD-assigned CWEs explains it; those CWEs are the CVE's own
    cwe_inherited, never assigned ones; and the CVE is then derived."""
    bad: list[dict] = []
    for tid, ent in loader.entities.items():
        if ent.get("type") != "technique":
            continue
        chain = build_attack_chain_impl(loader, tid, limit=BIG)["data"]
        for cve in chain["cves"]:
            inh = cve.get("inherited_cwes") or []
            if not inh:
                continue
            cve_ent = loader.entities.get(cve["id"]) or {}
            assigned = set(_rel(loader, cve["id"], "cwe").get("ids") or [])
            parents = set(cve_ent.get("cwe_inherited") or [])
            ctid_link = _per_link(loader, tid, "cve", cve["id"]) and cve.get("link_source") == CTID_SOURCE
            if not set(inh) <= parents or set(inh) & assigned or set(cve["via_cwes"]) != set(inh) \
                    or (cve["tier"] in STRONG and not ctid_link):
                bad.append({"technique": tid, "cve": cve["id"], "inherited_cwes": inh})
    return bad


def defense_tier_violations(loader: IndexLoader, cve_id: str, defenses: list[dict]) -> list[dict]:
    """CVE-side defenses labeled authoritative/official although the CVE to
    technique hop (or the CVE's own defend rel) is not."""
    out: list[dict] = []
    key = loader.resolve_entity_key(cve_id)
    for d in defenses:
        if "direct" in d:
            out.append({"cve": cve_id, "id": d["id"], "problem": "direct flag present"})
        if d["tier"] not in STRONG:
            continue
        own = _rel(loader, key, "defend") if key else {}
        # I21: the CVE -> technique hop is read per link from the graph.
        hops: list[Any] = [_link_tier(loader, key, "technique", t) for t in d["via_techniques"]] if key else []
        if not d["via_techniques"] or d["id"] in (own.get("ids") or []):
            hops.append(link_provenance(own, d["id"])["tier"] if own else None)
        if any(h not in STRONG for h in hops):
            out.append({"cve": cve_id, "id": d["id"], "tier": d["tier"]})
    return out


def link_label_violations(loader: IndexLoader) -> list[dict]:
    """I21 (ISC-9): every link the tools report carries the graph's own
    provenance for that link. A CTID or inferred link never reads as chain
    derived, and a chain link never reads as CTID or inferred. Checked on
    lookup_entity and pivot_from_entity for every CVE and technique, on
    every chain element, and on every CVE-side defense's technique links."""
    bad: list[dict] = []
    for eid, ent in loader.entities.items():
        etype = ent.get("type")
        if etype not in ("cve", "technique", "defend"):
            continue
        rels_out = lookup_entity_impl(loader, eid)["data"]["rels"]
        for rel in rels_out:
            want = link_provenance(_rel(loader, eid, rel["rel_type"]), rel["target_id"])
            if (rel.get("source"), rel.get("tier")) != (want["source"], want["tier"]):
                bad.append({"tool": "lookup", "id": eid, "target": rel["target_id"], "got": rel.get("tier")})
        for hit in pivot_from_entity_impl(loader, eid)["data"]:
            want = link_provenance(_rel(loader, eid, hit["rel_type"]), hit["id"])
            if (hit.get("source"), hit.get("tier")) != (want["source"], want["tier"]):
                bad.append({"tool": "pivot", "id": eid, "target": hit["id"], "got": hit.get("tier")})
        if etype == "technique":
            for cve in build_attack_chain_impl(loader, eid, limit=BIG)["data"]["cves"]:
                want = link_provenance(_rel(loader, eid, "cve"), cve["id"])
                if (cve.get("link_source"), cve.get("link_tier")) != (want["source"], want["tier"]):
                    bad.append({"tool": "chain", "id": eid, "target": cve["id"], "got": cve.get("link_tier")})
        if etype == "cve":
            resp = get_defenses_impl(loader, cve_id=eid)
            for d in resp.get("data") or []:
                for tl in d.get("technique_links", []):
                    want = link_provenance(_rel(loader, eid, "technique"), tl["id"])
                    if (tl.get("source"), tl.get("tier")) != (want["source"], want["tier"]):
                        bad.append({"tool": "defenses", "id": eid, "target": tl["id"], "got": tl.get("tier")})
    return bad


def all_tier_violations(loader: IndexLoader, cve_ids: "list[str] | None" = None) -> dict:
    """Sweep every technique's chain and get_defenses for each CVE given
    (default: every CVE in the graph). Returns counts and violations."""
    chain_bad: list[dict] = []
    techniques = [t for t, e in loader.entities.items() if e.get("type") == "technique"]
    for tid in techniques:
        chain = build_attack_chain_impl(loader, tid, limit=BIG)["data"]
        chain_bad += chain_tier_violations(loader, tid, chain)
    if cve_ids is None:
        cve_ids = [c for c, e in loader.entities.items() if e.get("type") == "cve"]
    def_bad: list[dict] = []
    errors: dict[str, int] = {}
    defenses_seen = 0
    for cid in cve_ids:
        resp = get_defenses_impl(loader, cve_id=cid)
        if not resp.get("ok"):
            code = resp["error"]["code"]
            errors[code] = errors.get(code, 0) + 1
            continue
        defenses_seen += len(resp["data"])
        def_bad += defense_tier_violations(loader, cid, resp["data"])
    return {
        "techniques": len(techniques),
        "cves": len(cve_ids),
        "defenses": defenses_seen,
        "errors": errors,
        "chain_violations": chain_bad,
        "defense_violations": def_bad,
    }


def body_label_violations(entities: dict) -> list[dict]:
    """I21 review: a rel body's own source and tier must describe its links,
    so a reader that ignores link_prov under-claims instead of mislabeling.
    Every part of the body source (parts joined by " and ") is some link's
    source, and the body tier is the weakest tier among its links."""
    bad: list[dict] = []
    for eid, ent in entities.items():
        for rel_type, body in (ent.get("rels") or {}).items():
            if not isinstance(body, dict) or "link_prov" not in body:
                continue
            links = [link_provenance(body, t) for t in body.get("ids", [])]
            sources = [str(p["source"]) for p in links]
            parts = str(body.get("source")).split(" and ")
            claims_ok = all(any(src == part or src.startswith(part) for src in sources) for part in parts)
            weakest = min((p["tier"] for p in links), key=lambda t: TIER_RANK.get(t, -1))
            if not claims_ok or body.get("tier") != weakest:
                bad.append({"id": eid, "rel": rel_type, "source": body.get("source"), "tier": body.get("tier")})
    return bad
