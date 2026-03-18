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


def _load_json(path: Path) -> dict:
    """Load a JSON file, return empty dict if missing."""
    if not path.exists():
        print(f"  [SKIP] {path.name} not found")
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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


def generate_entity_index(base_dir: str | Path) -> tuple[dict, dict]:
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

    def ensure(eid: str, etype: str, name: str, phase: str):
        if eid not in entities:
            entities[eid] = {"type": etype, "id": eid, "name": name, "phase": phase}

    def link(id_a: str, rel_a: str, id_b: str, rel_b: str):
        rels_map[id_a][rel_a].add(id_b)
        rels_map[id_b][rel_b].add(id_a)

    def link_one(eid: str, rel: str, target: str):
        rels_map[eid][rel].add(target)

    # ── 1. Load CWE database ──────────────────────────────────────
    print("Loading CWE database...")
    cwe_db = _load_json(data_dir / "cwe_db.json")
    for cwe_num, cwe_data in cwe_db.items():
        cwe_id = f"CWE-{cwe_num}"
        name = cwe_data.get("name") or cwe_data.get("Name") or ""
        ensure(cwe_id, "cwe", name if name else cwe_id, "weakness")

        for capec_num in cwe_data.get("RelatedAttackPatterns", []):
            link_one(cwe_id, "capec", f"CAPEC-{capec_num}")

    print(f"  Loaded {len(cwe_db)} CWEs")

    # ── 2. Load CAPEC database ─────────────────────────────────────
    print("Loading CAPEC database...")
    capec_db = _load_json(data_dir / "capec_db.json")
    for capec_num, capec_data in capec_db.items():
        capec_id = f"CAPEC-{capec_num}"
        name = capec_data.get("name", "")
        ensure(capec_id, "capec", name if name else capec_id, "attack_pattern")

        for tid in _parse_capec_technique_ids(capec_data.get("techniques", "")):
            technique_id = f"T{tid}" if not tid.startswith("T") else tid
            link_one(capec_id, "technique", technique_id)

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
    if defend_path.exists():
        with open(defend_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                for attack_tech_id, mapping in record.items():
                    for dt in mapping.get("defensive_techniques", []):
                        defend_id = dt["id"]
                        defend_name = dt.get("name", defend_id)
                        if defend_id not in entities:
                            defend_entity_count += 1
                        ensure(defend_id, "defend", defend_name, "defense")
                        link(defend_id, "technique", attack_tech_id, "defend")
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
            link(group_id, "technique", tech_id, "apt_group")

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
            link(campaign_id, "technique", tech_id, "campaign")

    print(f"  Loaded {len(campaigns_db)} campaigns")

    # ── 6. Load KEV database ──────────────────────────────────────
    print("Loading KEV database...")
    kev_db = _load_json(data_dir / "kev_db.json")
    print(f"  Loaded {len(kev_db)} KEV entries")

    # ── 7. Load Vulnrichment database (loaded but not entity-generating) ──
    print("Loading vulnrichment database...")
    vulnrich_db = _load_json(data_dir / "vulnrichment_db.json")
    print(f"  Loaded {len(vulnrich_db)} vulnrichment entries")

    # ── 8. Load all CVE JSONL files ───────────────────────────────
    # Only index "interesting" CVEs: KEV-listed, APT-linked, or 3+ relationship types.
    # This keeps entity_index.json browser-friendly (~2-4MB vs 200MB+).
    print("Loading CVE databases...")
    cve_files = sorted(db_dir.glob("CVE-*.jsonl"))
    cve_count = 0
    cve_skipped = 0
    cve_filtered = 0
    kev_cves: set[str] = set()

    # First pass: collect all CVE data, then filter
    all_cve_data: list[tuple[str, dict]] = []
    for cve_file in cve_files:
        print(f"  Processing {cve_file.name}...")
        with open(cve_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                for cve_id, cve_data in record.items():
                    cwes = cve_data.get("CWE", [])
                    if not cwes:
                        cve_skipped += 1
                        continue
                    all_cve_data.append((cve_id, cve_data))

    print(f"  Found {len(all_cve_data)} CVEs with CWE data, filtering...")

    for cve_id, cve_data in all_cve_data:
        is_kev = cve_id in kev_db
        has_apt_groups = bool(cve_data.get("APT_GROUPS"))

        # Only index CVEs that are in KEV or directly linked to APT groups
        if not (is_kev or has_apt_groups):
            cve_filtered += 1
            continue

        ensure(cve_id, "cve", cve_id, "vulnerability")
        cve_count += 1

        for cwe_ref in cve_data.get("CWE", []):
            link(cve_id, "cwe", cwe_ref, "cve")

        for capec_num in cve_data.get("CAPEC", []):
            link(cve_id, "capec", f"CAPEC-{capec_num}", "cve")

        for tech_num in cve_data.get("TECHNIQUES", []):
            tech_id = f"T{tech_num}" if not tech_num.startswith("T") else tech_num
            link(cve_id, "technique", tech_id, "cve")
            for gid in technique_to_groups.get(tech_id, []):
                link(cve_id, "apt_group", gid, "cve")

        for defend_entry in cve_data.get("DEFEND", []):
            if isinstance(defend_entry, dict):
                did = defend_entry.get("id", "")
            else:
                did = str(defend_entry)
            if did:
                link(cve_id, "defend", did, "cve")

        for owasp_id in cve_data.get("OWASP", []):
            link(cve_id, "owasp", owasp_id, "cve")

        if is_kev:
            kev_cves.add(cve_id)

    print(f"  Indexed {cve_count} interesting CVEs (filtered {cve_filtered}, skipped {cve_skipped} no CWE)")

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
    for eid, entity in entities.items():
        etype = entity["type"]
        rels = {}
        for rel_type, targets in sorted(rels_map.get(eid, {}).items()):
            prov_key = (etype, rel_type)
            prov = REL_PROVENANCE.get(prov_key, {'source': 'Unknown', 'tier': 'derived'})
            rels[rel_type] = {
                "ids": sorted(targets),
                "source": prov["source"],
                "tier": prov["tier"],
            }
        entity["rels"] = rels

        # Add entity-level provenance
        entity["prov"] = ENTITY_PROVENANCE.get(etype, {'source': 'Unknown', 'tier': 'derived'})

        # KEV as top-level boolean (moved out of rels)
        if eid in kev_cves:
            entity["kev"] = True

    # ── 11. Build search terms (for search index only, not stored in entities) ─
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

        # For campaigns, also index associated group names
        if entity.get("type") == "campaign":
            for gid in rels_map.get(entity_id, {}).get("apt_group", set()):
                group_entity = entities.get(gid)
                if group_entity:
                    terms.add(group_entity["name"].lower())

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
        },
        "entities": entities,
    }

    return entity_index, search_index


def write_outputs(entity_index: dict, search_index: dict, base_dir: str | Path):
    """Write entity_index.json and search_index.json to docs/data/."""
    base = Path(base_dir)
    out_dir = base / "docs" / "data"
    out_dir.mkdir(parents=True, exist_ok=True)

    ei_path = out_dir / "entity_index.json"
    si_path = out_dir / "search_index.json"

    print(f"\nWriting {ei_path}...")
    with open(ei_path, "w", encoding="utf-8") as f:
        json.dump(entity_index, f, separators=(",", ":"))
    ei_size = ei_path.stat().st_size / (1024 * 1024)
    print(f"  entity_index.json: {ei_size:.1f} MB")

    print(f"Writing {si_path}...")
    with open(si_path, "w", encoding="utf-8") as f:
        json.dump(search_index, f, separators=(",", ":"))
    si_size = si_path.stat().st_size / (1024 * 1024)
    print(f"  search_index.json: {si_size:.1f} MB")


def main():
    parser = argparse.ArgumentParser(description="Generate TIP entity and search indexes")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parents[3]),
        help="Project root directory (default: auto-detected from script location)",
    )
    args = parser.parse_args()

    print("=== TIP Entity Index Generator ===")
    print(f"Base dir: {args.base_dir}\n")

    entity_index, search_index = generate_entity_index(args.base_dir)
    write_outputs(entity_index, search_index, args.base_dir)

    # Summary
    type_counts = defaultdict(int)
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
