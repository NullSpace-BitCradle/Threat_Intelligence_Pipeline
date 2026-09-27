"""
Entity Index Generator for TIP v1.5

Reads all pipeline data files and produces:
  - docs/data/entity_index.json  — every entity with type, relationships, search terms
  - docs/data/search_index.json  — inverted index mapping terms to entity IDs
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from tip_intel import cve_blocks
from tip.utils.atomic_io import atomic_replace_many
from tip.database.database_optimizer import JSONLManager
from tip.core.id_normalize import (
    cwe_capecs_with_ancestors,
    normalize_capec_id,
    normalize_cwe_id,
    normalize_technique_id,
)
from tip.core.ctid_processor import SOURCE as CTID_SOURCE, TIER as CTID_TIER, load_ctid_db
from tip.core.technique_inference import INFERRED_TIER, ctid_links, extra_technique_links
from tip_intel.link_tiers import CTID_DEFEND_SOURCE, INFERRED_DEFEND_SOURCE, INFERRED_FAMILY, TIER_RANK

_jsonl = JSONLManager()


# Provenance metadata — entity-level derived from type
ENTITY_PROVENANCE = {
    'cve':       {'source': 'NVD', 'tier': 'authoritative'},
    'cwe':       {'source': 'MITRE CWE Database', 'tier': 'official'},
    'capec':     {'source': 'MITRE CAPEC Database', 'tier': 'official'},
    'technique': {'source': 'MITRE ATT&CK', 'tier': 'official'},
    'defend':    {'source': 'MITRE D3FEND', 'tier': 'official'},
    'apt_group': {'source': 'MITRE ATT&CK Groups', 'tier': 'official'},
    'campaign':  {'source': 'MITRE ATT&CK Campaigns', 'tier': 'official'},
    'owasp':     {'source': 'Pipeline (NVD/CWE mapping)', 'tier': 'derived'},
}

# Relationship-level provenance — source/tier per relationship direction
REL_PROVENANCE = {
    ('cve', 'cwe'):       {'source': 'NVD Enrichment', 'tier': 'authoritative'},
    ('cwe', 'cve'):       {'source': 'NVD Enrichment', 'tier': 'authoritative'},
    ('cve', 'capec'):     {'source': 'Pipeline (CWE→CAPEC chain)', 'tier': 'derived'},
    ('capec', 'cve'):     {'source': 'Pipeline (CWE→CAPEC chain)', 'tier': 'derived'},
    ('cve', 'technique'): {'source': 'Pipeline (CAPEC→Technique chain)', 'tier': 'derived'},
    ('technique', 'cve'): {'source': 'Pipeline (CAPEC→Technique chain)', 'tier': 'derived'},
    ('cve', 'defend'):    {'source': 'Pipeline (Technique→D3FEND chain)', 'tier': 'derived'},
    ('defend', 'cve'):    {'source': 'Pipeline (Technique→D3FEND chain)', 'tier': 'derived'},
    ('cve', 'owasp'):     {'source': 'Pipeline (CWE→OWASP mapping)', 'tier': 'derived'},
    ('owasp', 'cve'):     {'source': 'Pipeline (CWE→OWASP mapping)', 'tier': 'derived'},
    ('cve', 'apt_group'): {'source': 'Pipeline (technique overlap)', 'tier': 'derived'},
    ('apt_group', 'cve'): {'source': 'Pipeline (technique overlap)', 'tier': 'derived'},
    ('cwe', 'capec'):     {'source': 'MITRE CWE Database', 'tier': 'official'},
    ('capec', 'cwe'):     {'source': 'MITRE CWE Database', 'tier': 'official'},
    ('capec', 'technique'): {'source': 'MITRE CAPEC Database', 'tier': 'official'},
    ('technique', 'capec'): {'source': 'MITRE CAPEC Database', 'tier': 'official'},
    ('technique', 'defend'): {'source': 'MITRE D3FEND', 'tier': 'official'},
    ('defend', 'technique'): {'source': 'MITRE D3FEND', 'tier': 'official'},
    ('apt_group', 'technique'): {'source': 'MITRE ATT&CK', 'tier': 'official'},
    ('technique', 'apt_group'): {'source': 'MITRE ATT&CK', 'tier': 'official'},
    ('campaign', 'apt_group'): {'source': 'MITRE ATT&CK Campaigns', 'tier': 'official'},
    ('apt_group', 'campaign'): {'source': 'MITRE ATT&CK Campaigns', 'tier': 'official'},
    ('campaign', 'technique'): {'source': 'MITRE ATT&CK Campaigns', 'tier': 'official'},
    ('technique', 'campaign'): {'source': 'MITRE ATT&CK Campaigns', 'tier': 'official'},
}


_STOP_WORDS = frozenset({
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "were",
    "been", "being", "have", "has", "had", "does", "did", "but", "not", "you",
    "all", "can", "her", "his", "its", "may", "our", "out", "own", "than",
    "too", "very", "just", "into", "over", "such", "also", "some", "when",
    "which", "who", "whom", "how", "what", "where", "will", "each", "other",
    "them", "then", "there", "these", "they", "your", "more", "most", "could",
    "would", "should", "about", "after", "before", "between", "under", "again",
    "further", "once", "during", "while", "through", "above", "below",
    "used", "use", "using", "allows", "allow", "result", "results",
    "based", "specific", "within", "without", "another", "because",
})


def _load_json(path: Path) -> dict:
    """Load a JSON file, return empty dict if missing."""
    if not path.exists():
        print(f"  [SKIP] {path.name} not found")
        return {}
    with open(path, "r", encoding="utf-8") as f:
        loaded: dict = json.load(f)
        return loaded


def _parse_capec_technique_ids(techniques_str: str) -> list[str]:
    """Extract ATT&CK technique IDs from CAPEC techniques string."""
    if not techniques_str:
        return []
    return re.findall(r"TAXONOMY NAME:ATTACK:ENTRY ID:([^:]+)", techniques_str)


def _tokenize_name(name: str) -> list[str]:
    """Split a name into lowercase search tokens (words 3+ chars)."""
    if not name:
        return []
    words = re.split(r"[\s\-_/,.:;()\[\]]+", name.lower())
    return [w for w in words if len(w) >= 3]


def build_cve_entity_record(
    cve_id: str,
    cve_data: dict,
    cvss_fallback: Callable[[str], dict | None] | None = None,
) -> dict:
    """Build one CVE entity record (without rels) from its shard payload.

    Pure: the result depends only on the arguments. ``cvss_fallback(cve_id)``
    supplies {score, vector, severity} when the shard has no NVD CVSS (the
    generator passes its CISA vulnrichment lookup). The UI and MCP consumers
    render score, severity, dates, and description from these fields without
    loading the JSONL shards.
    """
    cve_desc = cve_data.get("DESCRIPTION", "")
    # Short display name: first sentence (trimmed) or the CVE ID as fallback.
    # The full description is carried on the entity record itself so we
    # do not silently truncate intelligence data anywhere.
    if cve_desc:
        first_sentence = cve_desc.split(". ", 1)[0].strip()
        cve_name = first_sentence if first_sentence else cve_id
    else:
        cve_name = cve_id
    record: dict = {"type": "cve", "id": cve_id, "name": cve_name, "phase": "vulnerability"}
    if cve_desc:
        record["description"] = cve_desc
    cvss = cve_data.get("CVSS")
    if (not isinstance(cvss, dict) or cvss.get("score") is None) and cvss_fallback is not None:
        # Fall back to the CISA vulnrichment CVSS when NVD CVSS was not
        # captured during ingest (legacy shards from before the
        # process_nvd_cves fix).
        cvss = cvss_fallback(cve_id)
    if isinstance(cvss, dict):
        if cvss.get("score") is not None:
            record["cvss_score"] = cvss.get("score")
        if cvss.get("severity"):
            record["severity"] = cvss.get("severity")
        if cvss.get("vector"):
            record["cvss_vector"] = cvss.get("vector")
    if cve_data.get("PUBLISHED"):
        record["published"] = cve_data["PUBLISHED"]
    if cve_data.get("LAST_MODIFIED"):
        record["last_modified"] = cve_data["LAST_MODIFIED"]
    refs = cve_data.get("REFERENCES")
    if isinstance(refs, list) and refs:
        record["references"] = refs

    # Attach the shared CVE intelligence blocks (full KEV detail, SSVC,
    # CISA CVSS override, CVSS version/source) from the same shard payload.
    # One contract, shared with the MCP layer (tip_intel.cve_blocks), so a
    # new field reaches both surfaces without editing three allowlists.
    # rels are finalized later, so D3FEND-semantics decoration is a no-op
    # here by design.
    cve_blocks.enrich(record, cve_data)
    return record


def technique_extras(cve_id: str, cve_data: dict, ctid_db: dict | None,
                     cvss_vector: str | None) -> tuple[list[dict], list[dict]]:
    """(TECHNIQUES_CTID, TECHNIQUES_INFERRED) for one CVE (I21).

    A shard the I21 processor wrote carries both lists and is used as is,
    except that CTID mappings in ctid_db.json always win: a CVE CTID maps
    gets those links and nothing inferred, even when its shard predates the
    mapping (shards are rewritten weekly, ctid_db.json daily). For an older
    shard both lists are derived the same way the processor would, from
    ctid_db.json and the CVSS vector; without ctid_db.json nothing is
    derived, since inference must not fill a slot CTID may hold.
    """
    current = ctid_links(ctid_db.get(cve_id)) if ctid_db is not None else []
    if "TECHNIQUES_CTID" in cve_data or "TECHNIQUES_INFERRED" in cve_data:
        if current:
            return current, []
        ctid = [t for t in cve_data.get("TECHNIQUES_CTID") or [] if isinstance(t, dict) and t.get("id")]
        inferred = [t for t in cve_data.get("TECHNIQUES_INFERRED") or [] if isinstance(t, dict) and t.get("id")]
        return ctid, inferred
    if ctid_db is None:
        return [], []
    extra = extra_technique_links(
        cve_data.get("TECHNIQUES") or [],
        cve_data.get("TECHNIQUES_INHERITED") or [],
        ctid_db.get(cve_id),
        cvss_vector,
    )
    return extra["TECHNIQUES_CTID"], extra["TECHNIQUES_INFERRED"]


def _relabel_body(body: dict, chain_prov: dict, per_link: dict) -> None:
    """Make a rel body's own source and tier describe its links (I21 review),
    so a reader that ignores link_prov under-claims rather than mislabels.

    With chain links present the body keeps the chain source and takes the
    weakest tier present; ``default_prov`` then carries the chain label for
    the ids link_prov does not name, when it differs from the body's. With
    no chain link, one source gives that source and tier, and several give a
    source naming each, joined by " + " (inferred rules as one family) at the weakest tier.
    """
    chain_ids = [t for t in body["ids"] if t not in per_link]
    provs = list(per_link.values()) + ([chain_prov] if chain_ids else [])
    weakest = min((p["tier"] for p in provs), key=lambda t: TIER_RANK.get(t, -1))
    if chain_ids:
        body["tier"] = weakest
        if weakest != chain_prov["tier"]:
            body["default_prov"] = {"source": chain_prov["source"], "tier": chain_prov["tier"]}
        return
    sources = list(dict.fromkeys(str(p["source"]) for p in provs))
    if len(sources) > 1:
        ranked = sorted(provs, key=lambda p: -TIER_RANK.get(p["tier"], -1))
        families = [INFERRED_FAMILY if str(p["source"]).startswith(INFERRED_FAMILY) else str(p["source"])
                    for p in ranked]
        body["source"] = " + ".join(dict.fromkeys(families))
    else:
        body["source"] = sources[0]
    body["tier"] = weakest


def _ctid_prov(link: dict, with_comment: bool) -> dict:
    prov: dict = {"source": CTID_SOURCE, "tier": CTID_TIER,
                  "mapping_type": list(link.get("mapping_type") or [])}
    if with_comment and link.get("comment"):
        prov["comment"] = link["comment"]
    return prov


def _inferred_prov(link: dict) -> dict:
    return {"source": str(link.get("source") or "TIP inference"), "tier": INFERRED_TIER,
            "rule": link.get("rule")}


def _is_layer2(cve_id: str, cve_data: dict, kev_db: dict, vulnrich_db: dict) -> bool:
    """Layer 2 (curated CVE) rule: in KEV, APT-linked, or SSVC exploitation active.

    Plain vulnrichment membership no longer qualifies: a full resync restores
    ~136k entries and would balloon entity_index.json, and a wipe would shrink
    it (ISA Decisions 2026-09-26 11:40). SSVC comes from the shard
    VULNRICHMENT block, falling back to vulnrichment_db.json.
    """
    if cve_id in kev_db or cve_data.get("APT_GROUPS"):
        return True
    for source in (cve_data.get("VULNRICHMENT"), vulnrich_db.get(cve_id)):
        if isinstance(source, dict) and str(source.get("ssvcExploitStatus", "")).lower() == "active":
            return True
    return False


def generate_entity_index(base_dir: str | Path) -> tuple[dict, dict, dict]:
    """
    Generate entity_index and search_index from all pipeline data.

    Uses sets for relationships during construction for O(1) dedup,
    then converts to sorted lists for output.

    Returns (entity_index, search_index) dicts.
    """
    base = Path(base_dir)
    data_dir = base / "docs" / "data"
    db_dir = base / "docs" / "database"

    # During construction: rels values are sets, converted to lists at end
    entities: dict[str, dict] = {}
    # Track rels as separate dict-of-dict-of-sets for speed
    rels_map: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

    def ensure(eid: str, etype: str, name: str, phase: str) -> None:
        if eid not in entities:
            entities[eid] = {"type": etype, "id": eid, "name": name, "phase": phase}

    def link(id_a: str, rel_a: str, id_b: str, rel_b: str) -> None:
        rels_map[id_a][rel_a].add(id_b)
        rels_map[id_b][rel_b].add(id_a)

    def link_one(eid: str, rel: str, target: str) -> None:
        rels_map[eid][rel].add(target)

    # Targets reached only through an inherited parent CWE (ISA I29), kept
    # apart from rels_map and published as each rel body's additive
    # "inherited" subset.
    inherited_map: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

    def mark_inherited(id_a: str, rel_a: str, id_b: str, rel_b: str) -> None:
        inherited_map[id_a][rel_a].add(id_b)
        inherited_map[id_b][rel_b].add(id_a)

    # Per-link provenance for links whose source differs from the rel
    # body's (I21): CTID official and inferred technique links, and the
    # D3FEND defenses reached only through them. Published as each rel
    # body's additive "link_prov" map, both directions.
    link_prov: dict[str, dict[str, dict[str, dict]]] = defaultdict(lambda: defaultdict(dict))

    def set_prov(id_a: str, rel_a: str, id_b: str, rel_b: str, prov_a: dict, prov_b: dict) -> None:
        link_prov[id_a][rel_a][id_b] = prov_a
        link_prov[id_b][rel_b][id_a] = prov_b

    # ── 1. Load CWE database ──────────────────────────────────────
    print("Loading CWE database...")
    cwe_db = _load_json(data_dir / "cwe_db.json")

    # CAPEC inheritance walks the full ChildOf chain (shared definition in
    # tip.core.id_normalize). CAPECs that are not the CWE's own
    # RelatedAttackPatterns are labeled inherited (ISC-8).
    cwe_parent_capecs: dict[str, set[str]] = {}
    for cwe_num in cwe_db:
        cwe_capecs_with_ancestors(cwe_db, cwe_num, cwe_parent_capecs)

    inherited_count = sum(1 for n, c in cwe_parent_capecs.items()
                         if c and not cwe_db.get(n, {}).get("RelatedAttackPatterns"))

    for cwe_num, cwe_data in cwe_db.items():
        cwe_id = normalize_cwe_id(cwe_num) or f"CWE-{cwe_num}"
        name = cwe_data.get("name") or cwe_data.get("Name") or ""
        ensure(cwe_id, "cwe", name if name else cwe_id, "weakness")

        own_capecs = {str(c) for c in cwe_data.get("RelatedAttackPatterns", []) or []}
        for capec_num in cwe_parent_capecs.get(cwe_num, set()):
            capec_ref = normalize_capec_id(capec_num)
            if capec_ref:
                link_one(cwe_id, "capec", capec_ref)
                if capec_num not in own_capecs:
                    inherited_map[cwe_id]["capec"].add(capec_ref)

    print(f"  Loaded {len(cwe_db)} CWEs ({inherited_count} inherited CAPECs from parents)")

    # ── 2. Load CAPEC database ─────────────────────────────────────
    print("Loading CAPEC database...")
    capec_db = _load_json(data_dir / "capec_db.json")
    for capec_num, capec_data in capec_db.items():
        capec_id = f"CAPEC-{capec_num}"
        name = capec_data.get("name", "")
        ensure(capec_id, "capec", name if name else capec_id, "attack_pattern")

        for tid in _parse_capec_technique_ids(capec_data.get("techniques", "")):
            technique_ref = normalize_technique_id(tid)
            if technique_ref:
                link_one(capec_id, "technique", technique_ref)

    print(f"  Loaded {len(capec_db)} CAPECs")

    # ── 3. Load Techniques database ────────────────────────────────
    print("Loading techniques database...")
    tech_db = _load_json(data_dir / "techniques_db.json")
    for tech_num, tech_data in tech_db.items():
        technique_id = f"T{tech_num}"
        name = tech_data.get("name", "")
        ensure(technique_id, "technique", name if name else technique_id, "attack")

    print(f"  Loaded {len(tech_db)} techniques")

    # ── 4. Load D3FEND database ────────────────────────────────────
    print("Loading D3FEND database...")
    defend_path = data_dir / "defend_db.jsonl"
    defend_entity_count = 0
    # Track technique -> defend IDs for transitive CVE resolution (Bug 2)
    technique_to_defend: dict[str, set[str]] = defaultdict(set)
    # Track fragment name -> canonical ID for search indexing
    defend_fragment_to_id: dict[str, str] = {}
    if defend_path.exists():
        with open(defend_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                for raw_tech_id, mapping in record.items():
                    attack_tech_id = normalize_technique_id(raw_tech_id) or raw_tech_id
                    for dt in mapping.get("defensive_techniques", []):
                        defend_id = dt["id"]
                        defend_name = dt.get("name", defend_id)
                        fragment = dt.get("d3fend_fragment", "")
                        if fragment and fragment != defend_id:
                            defend_fragment_to_id[fragment] = defend_id
                        if defend_id not in entities:
                            defend_entity_count += 1
                        ensure(defend_id, "defend", defend_name, "defense")
                        link(defend_id, "technique", attack_tech_id, "defend")
                        technique_to_defend[attack_tech_id].add(defend_id)
    else:
        print("  [SKIP] defend_db.jsonl not found")

    print(f"  Loaded {defend_entity_count} D3FEND defenses")

    # ── 5. Load Groups database ────────────────────────────────────
    print("Loading groups database...")
    groups_db = _load_json(data_dir / "groups_db.json")
    groups = groups_db.get("groups", {})
    technique_to_groups = groups_db.get("technique_to_groups", {})
    group_aliases: dict[str, list[str]] = {}

    for group_id, group_data in groups.items():
        name = group_data.get("name", group_id)
        aliases = group_data.get("aliases", [])
        ensure(group_id, "apt_group", name, "threat_actor")
        group_aliases[group_id] = aliases

        for tech_id in group_data.get("techniques", []):
            link(group_id, "technique", normalize_technique_id(tech_id) or tech_id, "apt_group")

    print(f"  Loaded {len(groups)} APT groups")

    # ── 5b. Load Campaigns database ──────────────────────────────────
    print("Loading campaigns database...")
    campaigns_db = _load_json(data_dir / "campaigns_db.json")
    campaign_aliases: dict[str, list[str]] = {}

    for campaign_id, campaign_data in campaigns_db.items():
        name = campaign_data.get("name", campaign_id)
        aliases = campaign_data.get("aliases", [])
        first_seen = campaign_data.get("first_seen", "")
        last_seen = campaign_data.get("last_seen", "")
        ensure(campaign_id, "campaign", name, "operation")
        entities[campaign_id]["first_seen"] = first_seen
        entities[campaign_id]["last_seen"] = last_seen
        campaign_aliases[campaign_id] = aliases

        for group_id in campaign_data.get("groups", []):
            link(campaign_id, "apt_group", group_id, "campaign")

        for tech_id in campaign_data.get("techniques", []):
            link(campaign_id, "technique", normalize_technique_id(tech_id) or tech_id, "campaign")

    print(f"  Loaded {len(campaigns_db)} campaigns")

    # ── 6. Load KEV database ──────────────────────────────────────
    print("Loading KEV database...")
    kev_db = _load_json(data_dir / "kev_db.json")
    print(f"  Loaded {len(kev_db)} KEV entries")

    # ── 7. Load Vulnrichment database (loaded but not entity-generating) ──
    print("Loading vulnrichment database...")
    vulnrich_db = _load_json(data_dir / "vulnrichment_db.json")
    print(f"  Loaded {len(vulnrich_db)} vulnrichment entries")

    # ── 7b. Load CTID KEV technique mappings (I21) ─────────────────
    print("Loading CTID KEV mappings...")
    ctid_db = load_ctid_db(str(data_dir / "ctid_db.json"))
    print(f"  Loaded CTID mappings for {len(ctid_db) if ctid_db is not None else 0} CVEs")
    # CTID technique ids the graph has no technique for are not linked;
    # counted. Checked 2026-09-27: CTID's file is on ATT&CK 16.1, and ATT&CK
    # 19.2 revoked T1562 and T1562.001 (revoked by T1685) and T1070.001
    # (revoked by T1685.005).
    ctid_unknown: set[tuple[str, str]] = set()

    def link_extras(cve_id: str, ctid: list[dict], inferred: list[dict],
                    reached: dict[str, set[str]]) -> None:
        """Link CTID and inferred techniques and the D3FEND defenses they
        reach. ``reached`` maps a defend id to how the chain reached it
        ("direct", "inherited"). A defense the chain reaches directly keeps
        the chain label. One reached otherwise through a CTID technique is
        derived ("CTID technique, then D3FEND": a composition nobody
        asserted about the CVE), and one reached only through an inferred
        technique is inferred."""
        for kind, links_ in (("ctid", ctid), ("inferred", inferred)):
            for t in links_:
                tech_id = normalize_technique_id(str(t.get("id")))
                if not tech_id:
                    continue
                if entities.get(tech_id, {}).get("type") != "technique":
                    if kind == "ctid":
                        ctid_unknown.add((cve_id, tech_id))
                    continue
                link(cve_id, "technique", tech_id, "cve")
                if kind == "ctid":
                    set_prov(cve_id, "technique", tech_id, "cve", _ctid_prov(t, True), _ctid_prov(t, False))
                    # A CTID statement outranks an inherited chain path.
                    inherited_map[cve_id]["technique"].discard(tech_id)
                    inherited_map[tech_id]["cve"].discard(cve_id)
                elif tech_id not in link_prov[cve_id]["technique"]:
                    set_prov(cve_id, "technique", tech_id, "cve", _inferred_prov(t), _inferred_prov(t))
                for did in technique_to_defend.get(tech_id, set()):
                    if did in entities:
                        reached.setdefault(did, set()).add(kind)
        for did, kinds in reached.items():
            if "ctid" in kinds or "inferred" in kinds:
                link(cve_id, "defend", did, "cve")
            if "direct" in kinds:
                continue
            if "ctid" in kinds:
                prov = {"source": CTID_DEFEND_SOURCE, "tier": "derived"}
                set_prov(cve_id, "defend", did, "cve", prov, dict(prov))
                inherited_map[cve_id]["defend"].discard(did)
                inherited_map[did]["cve"].discard(cve_id)
            elif kinds == {"inferred"}:
                prov = {"source": INFERRED_DEFEND_SOURCE, "tier": INFERRED_TIER}
                set_prov(cve_id, "defend", did, "cve", prov, dict(prov))

    # ── 8. Load all CVE JSONL files ───────────────────────────────
    # Only index "interesting" CVEs in entity_index (Layer 2): in CISA KEV,
    # linked to an APT group, or carrying CISA vulnrichment data. These are
    # the CVEs we want to render with the full relationship graph.
    #
    # The 'CVSS >= 7.0' criterion was tried and dropped: with NVD CVSS now
    # populated on ~91% of CVEs, that filter qualified ~126K CVEs, ballooning
    # entity_index.json to ~250 MB and breaking browser load. The tiered
    # architecture (Layer 1 cve_ids_index covers all 346K CVE IDs, Layer 3
    # shard fetch covers all enrichment data on demand) means Layer 2 does
    # NOT need to be comprehensive; it should be the curated highlight set.
    # See docs/superpowers/specs/mcp-server-scope.md and Plans/ROADMAP.md
    # for the layered design rationale.
    print("Loading CVE databases...")
    cve_files = sorted(db_dir.glob("CVE-*.jsonl.gz")) or sorted(db_dir.glob("CVE-*.jsonl"))
    cve_count = 0
    cve_skipped = 0
    cve_filtered = 0
    kev_cves: set[str] = set()

    # First pass: collect all CVE data, then filter.
    # Also accumulate the Layer 1 "all-IDs" index keyed by year so the
    # frontend search bar can find any ingested CVE even when the CVE is
    # not in the curated entity_index. Tail integers keep the file small.
    all_cve_data: list[tuple[str, dict]] = []
    shard_cve_ids: set[str] = set()
    cve_ids_by_year: dict[str, list[int]] = defaultdict(list)
    total_cve_ids = 0
    for cve_file in cve_files:
        print(f"  Processing {cve_file.name}...")
        # Strict reader: a malformed line or truncated gzip raises
        # ShardCorruptError naming the shard, instead of a bare EOFError.
        for record in _jsonl.read_jsonl(str(cve_file)):
            for cve_id, cve_data in record.items():
                # Layer 1: every ingested CVE goes into the all-IDs index,
                # regardless of CWE coverage.
                parts = cve_id.split("-")
                if len(parts) == 3 and parts[0] == "CVE":
                    try:
                        year = parts[1]
                        tail = int(parts[2])
                        cve_ids_by_year[year].append(tail)
                        total_cve_ids += 1
                    except ValueError:
                        pass
                shard_cve_ids.add(cve_id)
                # Layer 2 gate (authoritative; see _is_layer2). A curated CVE
                # is kept even without CWE data so every KEV CVE is indexed.
                if not _is_layer2(cve_id, cve_data, kev_db, vulnrich_db):
                    if not cve_data.get("CWE"):
                        cve_skipped += 1
                    else:
                        cve_filtered += 1
                    continue
                all_cve_data.append((cve_id, cve_data))

    print(f"  Found {len(all_cve_data)} Layer 2 CVEs (KEV, APT-linked or SSVC active)")

    # Inclusion is decided once, above, by _is_layer2. The browser loads
    # entity_index.json in full, so the rule balances coverage against file
    # size (ISA ISC-26: at most 20 MB, every KEV CVE present).

    def _severity_from_score(score: float) -> str:
        """Derive CVSS v3.x severity bucket from a numeric base score."""
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "NONE"

    def _cvss_from_vulnrichment_db(cve_id: str) -> dict | None:
        """Return {score,vector,severity} from vulnrichment_db.json if present."""
        vr_entry = vulnrich_db.get(cve_id)
        if not isinstance(vr_entry, dict):
            return None
        cisa_cvss = vr_entry.get("cisaCVSS")
        if not isinstance(cisa_cvss, dict):
            return None
        score = cisa_cvss.get("baseScore")
        if not isinstance(score, (int, float)):
            return None
        severity = cisa_cvss.get("baseSeverity") or _severity_from_score(float(score))
        return {
            "score": float(score),
            "vector": cisa_cvss.get("vector", ""),
            "severity": severity,
        }

    def _cve_base_score(cve_id: str, data: dict) -> float | None:
        cvss = data.get("CVSS")
        if isinstance(cvss, dict):
            score = cvss.get("score")
            if isinstance(score, (int, float)):
                return float(score)
        vr_cvss = _cvss_from_vulnrichment_db(cve_id)
        if vr_cvss is not None:
            return float(vr_cvss["score"])
        return None

    for cve_id, cve_data in all_cve_data:
        is_kev = cve_id in kev_db

        # Record fields (name, description, CVSS, dates, references, and the
        # shared tip_intel blocks) come from build_cve_entity_record, the
        # same function the cross-seam parity test drives.
        record = build_cve_entity_record(cve_id, cve_data, _cvss_from_vulnrichment_db)
        ensure(cve_id, "cve", record["name"], "vulnerability")
        cve_entity = entities[cve_id]
        for field, value in record.items():
            if field not in ("type", "id", "name", "phase"):
                cve_entity[field] = value

        cve_count += 1

        # Shards written before ingest-time normalization carry bare parent
        # CWE numbers (["74","CWE-79"]) and bare technique ids; normalize
        # here so existing shards also produce resolvable rels (ISC-22).
        # A shard with CWE_INHERITED (I29) lists NVD-assigned CWEs in CWE
        # and keeps inherited parents, and whatever only they reach, apart.
        # Legacy shards have no _INHERITED lists and link exactly as before.
        for cwe_raw in cve_data.get("CWE", []):
            cwe_ref = normalize_cwe_id(cwe_raw)
            if cwe_ref:
                link(cve_id, "cwe", cwe_ref, "cve")
        if "CWE_INHERITED" in cve_data:
            cve_entity["cwe_inherited"] = [
                c for c in (normalize_cwe_id(x) for x in cve_data.get("CWE_INHERITED") or []) if c
            ]

        def split(direct_raw: list, inherited_raw: list, norm: Callable[[str], str | None]) -> tuple[list[str], list[str]]:
            direct = [n for n in (norm(x) for x in direct_raw or []) if n]
            seen = set(direct)
            inh = [n for n in (norm(x) for x in inherited_raw or []) if n and n not in seen]
            return direct, inh

        capec_direct, capec_inh = split(cve_data.get("CAPEC", []), cve_data.get("CAPEC_INHERITED", []), normalize_capec_id)
        for capec_ref in capec_direct + capec_inh:
            link(cve_id, "capec", capec_ref, "cve")
        for capec_ref in capec_inh:
            mark_inherited(cve_id, "capec", capec_ref, "cve")

        tech_direct, tech_inh = split(cve_data.get("TECHNIQUES", []), cve_data.get("TECHNIQUES_INHERITED", []),
                                      normalize_technique_id)
        groups_direct: set[str] = set()
        groups_inh: set[str] = set()
        defend_direct: set[str] = set()
        defend_inh: set[str] = set()
        for tech_id in tech_direct + tech_inh:
            is_inh = tech_id in tech_inh
            link(cve_id, "technique", tech_id, "cve")
            for gid in technique_to_groups.get(tech_id, []):
                link(cve_id, "apt_group", gid, "cve")
                (groups_inh if is_inh else groups_direct).add(gid)
            # Chain through to D3FEND: CVE -> technique -> defend
            for did in technique_to_defend.get(tech_id, set()):
                if did in entities:
                    link(cve_id, "defend", did, "cve")
                    (defend_inh if is_inh else defend_direct).add(did)
        for tech_id in tech_inh:
            mark_inherited(cve_id, "technique", tech_id, "cve")

        # Also pick up any DEFEND entries already in CVE data (legacy format)
        for defend_entry in cve_data.get("DEFEND", []):
            if isinstance(defend_entry, dict):
                did = defend_entry.get("id", "")
                entry_inh = defend_entry.get("inherited") is True
            else:
                did = str(defend_entry)
                entry_inh = False
            if did:
                link(cve_id, "defend", did, "cve")
                (defend_inh if entry_inh else defend_direct).add(did)

        for gid in groups_inh - groups_direct:
            mark_inherited(cve_id, "apt_group", gid, "cve")
        for did in defend_inh - defend_direct:
            mark_inherited(cve_id, "defend", did, "cve")

        # I21: CTID and inferred techniques. APT groups stay on the chain.
        ctid_links, inferred_links = technique_extras(cve_id, cve_data, ctid_db, record.get("cvss_vector"))
        reached = {d: {"direct"} for d in defend_direct}
        for d in defend_inh - defend_direct:
            reached[d] = {"inherited"}
        link_extras(cve_id, ctid_links, inferred_links, reached)

        owasp_direct, owasp_inh = split(cve_data.get("OWASP", []), cve_data.get("OWASP_INHERITED", []),
                                        lambda x: str(x) if x else None)
        for owasp_id in owasp_direct + owasp_inh:
            link(cve_id, "owasp", owasp_id, "cve")
        for owasp_id in owasp_inh:
            mark_inherited(cve_id, "owasp", owasp_id, "cve")

        if is_kev:
            kev_cves.add(cve_id)

    # KEV CVEs that no shard carries yet (added to KEV after the last NVD
    # sync) still get a minimal entity so every KEV CVE resolves.
    kev_only = sorted(k for k in kev_db if k not in shard_cve_ids and k not in entities)
    for cve_id in kev_only:
        ensure(cve_id, "cve", cve_id, "vulnerability")
        cve_blocks.enrich(entities[cve_id], {"KEV": kev_db[cve_id]})
        kev_cves.add(cve_id)
        # No shard, so no chain and no vector: CTID links only.
        link_extras(cve_id, technique_extras(cve_id, {}, ctid_db, None)[0], [], {})
        cve_count += 1

    print(f"  Indexed {cve_count} interesting CVEs ({len(kev_only)} KEV-only without a shard record; "
          f"filtered {cve_filtered}, skipped {cve_skipped} no CWE)")

    # ── 9. Create OWASP entities ──────────────────────────────────
    print("Creating OWASP entities...")
    owasp_ids: set[str] = set()
    for eid, rmap in rels_map.items():
        for oid in rmap.get("owasp", set()):
            owasp_ids.add(oid)
    for owasp_id in owasp_ids:
        ensure(owasp_id, "owasp", owasp_id, "compliance")
    print(f"  Created {len(owasp_ids)} OWASP entities")

    # ── 10. Convert rels_map sets to new shape {ids, source, tier} ──
    print("Finalizing relationships with provenance...")
    # A rel whose target entity does not exist is dropped and counted: a link
    # that resolves to nothing is a bug, not a styling issue (ISC-24).
    dropped_dangling: dict[str, int] = defaultdict(int)
    for eid, entity in entities.items():
        etype = entity["type"]
        rels: dict[str, dict] = {}
        for rel_type, targets in sorted(rels_map.get(eid, {}).items()):
            live = sorted(t for t in targets if t in entities)
            if len(live) != len(targets):
                dropped_dangling[rel_type] += len(targets) - len(live)
            if not live:
                continue
            prov_key = (etype, rel_type)
            prov = REL_PROVENANCE.get(prov_key, {'source': 'Unknown', 'tier': 'derived'})
            rels[rel_type] = {
                "ids": live,
                "source": prov["source"],
                "tier": prov["tier"],
            }
            # Additive (I29): the ids reached only through an inherited
            # parent CWE, present only when there are any.
            inherited_ids = inherited_map.get(eid, {}).get(rel_type)
            if inherited_ids:
                sub = [t for t in live if t in inherited_ids]
                if sub:
                    rels[rel_type]["inherited"] = sub
            # Additive (I21): per-id provenance overriding the body's
            # source and tier, present only for ids that differ.
            per_link = link_prov.get(eid, {}).get(rel_type)
            if per_link:
                sub_prov = {t: per_link[t] for t in live if t in per_link}
                if sub_prov:
                    rels[rel_type]["link_prov"] = sub_prov
                    _relabel_body(rels[rel_type], prov, sub_prov)
        entity["rels"] = rels

        # Add entity-level provenance
        entity["prov"] = ENTITY_PROVENANCE.get(etype, {'source': 'Unknown', 'tier': 'derived'})

        # KEV as top-level boolean (moved out of rels)
        if eid in kev_cves:
            entity["kev"] = True

    # ── 11. Build search terms (for search index only, not stored in entities) ─
    print(f"  Dropped {sum(dropped_dangling.values())} dangling rel targets {dict(dropped_dangling)}")

    print("Building search terms...")
    entity_terms: dict[str, set[str]] = {}
    for entity_id, entity in entities.items():
        terms = set()
        eid_lower = entity_id.lower()
        terms.add(eid_lower)

        # Add ID without prefix
        if "-" in entity_id:
            terms.add(entity_id.split("-", 1)[1].lower())

        # Tokenize name
        name = entity.get("name", "")
        if name and name != entity_id:
            terms.add(name.lower())
            for token in _tokenize_name(name):
                terms.add(token)

        # Aliases for APT groups
        for alias in group_aliases.get(entity_id, []):
            terms.add(alias.lower())

        # Aliases for campaigns
        for alias in campaign_aliases.get(entity_id, []):
            terms.add(alias.lower())

        # D3FEND: index fragment name as search term (e.g., "fileanalysis" for D3-FA)
        for fragment, canonical_id in defend_fragment_to_id.items():
            if canonical_id == entity_id:
                terms.add(fragment.lower())
                for token in _tokenize_name(fragment):
                    terms.add(token)

        # For campaigns, also index associated group names
        if entity.get("type") == "campaign":
            for gid in rels_map.get(entity_id, {}).get("apt_group", set()):
                group_entity = entities.get(gid)
                if group_entity:
                    terms.add(group_entity["name"].lower())

        # Description-based search: index significant words from raw DB descriptions
        etype = entity.get("type", "")
        desc_text = ""
        if etype == "cwe":
            cwe_num = entity_id.replace("CWE-", "")
            desc_text = cwe_db.get(cwe_num, {}).get("description", "")
        elif etype == "technique":
            tech_num = entity_id.replace("T", "")
            desc_text = tech_db.get(tech_num, {}).get("description", "")
        elif etype == "capec":
            capec_num = entity_id.replace("CAPEC-", "")
            desc_text = capec_db.get(capec_num, {}).get("name", "")

        if desc_text:
            for token in _tokenize_name(desc_text):
                if token not in _STOP_WORDS:
                    terms.add(token)

        entity_terms[entity_id] = terms

    # ── 12. Build search index ─────────────────────────────────────
    print("Building search index...")
    search_index: dict[str, list[str]] = defaultdict(list)
    for entity_id, terms in entity_terms.items():
        for term in terms:
            search_index[term].append(entity_id)

    search_index = dict(sorted(search_index.items()))

    # ── 13. Assemble entity index ──────────────────────────────────
    entity_index = {
        "meta": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "entity_count": len(entities),
            "version": "1.5",
            # Additive: rel targets dropped because no such entity exists.
            "dropped_dangling_rels": sum(dropped_dangling.values()),
            # Additive (I29): rel bodies may carry an "inherited" id subset
            # and CVEs a cwe_inherited list; readers of older indexes treat
            # every link as direct.
            "inherited_links": True,
            # Additive (I21): rel bodies may carry a "link_prov" map of
            # id -> {source, tier, ...} for CTID (official) and inferred
            # links; readers of older indexes use the body's source/tier.
            "link_provenance": True,
            "ctid_unknown_techniques": len(ctid_unknown),
        },
        "entities": entities,
    }

    # ── 14. Build Layer 1 (all-IDs) index ──────────────────────────
    # Year-grouped sorted integer tails. Lets the frontend search bar
    # match any ingested CVE ID via prefix without loading the full
    # entity graph for the 99%+ of CVEs that are not "interesting".
    print("Building all-CVE ID index...")
    cve_ids_index = {
        "v": 1,
        "generated": datetime.now(timezone.utc).isoformat(),
        "count": total_cve_ids,
        "years": {
            year: sorted(set(tails))
            for year, tails in sorted(cve_ids_by_year.items())
        },
    }
    print(f"  Indexed {total_cve_ids} CVE IDs across {len(cve_ids_by_year)} years")

    return entity_index, search_index, cve_ids_index


def write_outputs(
    entity_index: dict,
    search_index: dict,
    base_dir: str | Path,
    cve_ids_index: dict | None = None,
    out_dir: str | Path | None = None,
) -> None:
    """Write entity_index.json, search_index.json, and the optional
    Layer 1 all-CVE-IDs index to docs/data/ (or ``out_dir``).

    All files are serialized in memory, then published together: every temp
    file is written before any target is replaced, so a failure cannot leave
    a mix of old and new indexes.
    """
    target_dir = Path(out_dir) if out_dir is not None else Path(base_dir) / "docs" / "data"
    target_dir.mkdir(parents=True, exist_ok=True)

    def _dump(obj: dict) -> bytes:
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    items: list[tuple[Path, bytes]] = [
        (target_dir / "entity_index.json", _dump(entity_index)),
        (target_dir / "search_index.json", _dump(search_index)),
    ]
    if cve_ids_index is not None:
        items.append((target_dir / "cve_ids_index.json", _dump(cve_ids_index)))

    print(f"\nWriting {len(items)} index files to {target_dir}...")
    atomic_replace_many(items)
    for path, data in items:
        print(f"  {path.name}: {len(data) / (1024 * 1024):.1f} MB")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate TIP entity and search indexes")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parents[3]),
        help="Project root directory (default: auto-detected from script location)",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Write the index files here instead of <base-dir>/docs/data",
    )
    args = parser.parse_args()

    print("=== TIP Entity Index Generator ===")
    print(f"Base dir: {args.base_dir}\n")

    entity_index, search_index, cve_ids_index = generate_entity_index(args.base_dir)
    write_outputs(entity_index, search_index, args.base_dir, cve_ids_index, out_dir=args.out_dir)

    # Summary
    type_counts: dict[str, int] = defaultdict(int)
    for e in entity_index["entities"].values():
        type_counts[e["type"]] += 1

    print("\n=== Summary ===")
    print(f"Total entities: {entity_index['meta']['entity_count']}")
    for etype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {etype}: {count}")
    print(f"Search index terms: {len(search_index)}")
    print("Done.")


if __name__ == "__main__":
    main()
