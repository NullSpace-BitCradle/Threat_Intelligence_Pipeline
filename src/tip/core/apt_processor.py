"""
APT Groups Processor

Downloads MITRE ATT&CK STIX data, extracts threat groups with aliases and
technique usage, and the CVEs ATT&CK itself cites for each group (I32).
"""
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any, Iterable, List, Optional, Set, Tuple

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger, NetworkError, create_api_context
from tip.utils.performance_optimizer import performance_timer
from tip.utils.atomic_io import write_reference_db, count_groups

config = get_config()

# ATT&CK prose also writes "CVE 2012-0158", and reference URLs carry
# lowercase ids; every match is normalized to CVE-YYYY-NNNN.
CVE_RE = re.compile(r"CVE[- ](\d{4})-(\d{4,})", re.I)

# Evidence order when several ATT&CK objects cite one CVE for one group: the
# group's own ATT&CK entry, then an attributed campaign, then the group's own
# relationship, then a campaign's relationship. Ties break by id.
VIA_RANK = {"intrusion-set": 0, "campaign": 1, "group-relationship": 2, "campaign-relationship": 3}


def _is_live(obj: Dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _attack_id(obj: Dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            return str(ref.get("external_id") or "")
    return ""


def _find_cves(text: str) -> Set[str]:
    return {f"CVE-{year}-{num}" for year, num in CVE_RE.findall(text)}


def _cited_cves(obj: Dict[str, Any]) -> Set[str]:
    """CVE ids in an object's description and external references."""
    found = _find_cves(str(obj.get("description") or ""))
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict):
            for key in ("external_id", "description", "url"):
                found.update(_find_cves(str(ref.get(key) or "")))
    return found


def extract_attributions(stix_data: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """CVE to APT group links that the ATT&CK bundle states itself (I32).

    A CVE links to a group only when a live (not revoked, not deprecated)
    object cites it: the group's intrusion-set; a relationship whose source
    is the group; or a campaign, or a relationship whose source is a
    campaign, where that campaign is attributed-to the group. Software two
    hops (a CVE cited on malware a group uses) are out of scope.

    Returns {cve: [{"id": group, "via": ATT&CK id, "via_type": type}]}, one
    entry per group, sorted. ``via`` is the group or campaign the citing
    object belongs to; a relationship has no ATT&CK id of its own, so its
    entry names the relationship's source as ``via`` and its target (a
    technique or software id) as ``via_target``. When several objects cite
    the same pair, the entry keeps the first by VIA_RANK, then by id.
    CVE ids are matched with a space or a hyphen after "CVE", in any case,
    and normalized to CVE-YYYY-NNNN.
    """
    objects = [o for o in stix_data.get("objects", []) if isinstance(o, dict)]
    groups: Dict[str, str] = {}
    campaigns: Dict[str, str] = {}
    attack_ids: Dict[str, str] = {}
    for obj in objects:
        stix_id = str(obj.get("id") or "")
        aid = _attack_id(obj)
        if aid:
            attack_ids[stix_id] = aid
        if not aid or not _is_live(obj):
            continue
        if obj.get("type") == "intrusion-set":
            groups[stix_id] = aid
        elif obj.get("type") == "campaign":
            campaigns[stix_id] = aid

    campaign_groups: Dict[str, Set[str]] = defaultdict(set)
    for obj in objects:
        if (obj.get("type") == "relationship" and _is_live(obj)
                and obj.get("relationship_type") == "attributed-to"
                and obj.get("source_ref") in campaigns and obj.get("target_ref") in groups):
            campaign_groups[str(obj["source_ref"])].add(groups[str(obj["target_ref"])])

    best: Dict[Tuple[str, str], Tuple[Tuple[int, str, str], Dict[str, str]]] = {}

    def cite(cves: Iterable[str], group_ids: Iterable[str], evidence: Dict[str, str], tier: str) -> None:
        key_rank = (VIA_RANK[tier], evidence["via"], evidence.get("via_target", ""))
        for cve in cves:
            for gid in group_ids:
                held: Optional[Tuple[Tuple[int, str, str], Dict[str, str]]] = best.get((cve, gid))
                if held is None or key_rank < held[0]:
                    best[(cve, gid)] = (key_rank, {"id": gid, **evidence})

    for obj in objects:
        if not _is_live(obj):
            continue
        stix_id = str(obj.get("id") or "")
        otype = obj.get("type")
        if otype == "intrusion-set" and stix_id in groups:
            cite(_cited_cves(obj), [groups[stix_id]], {"via": groups[stix_id], "via_type": "intrusion-set"},
                 "intrusion-set")
        elif otype == "campaign" and stix_id in campaigns:
            cite(_cited_cves(obj), campaign_groups.get(stix_id, set()),
                 {"via": campaigns[stix_id], "via_type": "campaign"}, "campaign")
        elif otype == "relationship":
            source = str(obj.get("source_ref") or "")
            if source in groups:
                owner, group_ids, tier = groups[source], {groups[source]}, "group-relationship"
            elif source in campaigns:
                owner, group_ids, tier = campaigns[source], campaign_groups.get(source, set()), "campaign-relationship"
            else:
                continue
            evidence = {"via": owner, "via_type": "relationship"}
            target = attack_ids.get(str(obj.get("target_ref") or ""))
            if target:
                evidence["via_target"] = target
            cite(_cited_cves(obj), group_ids, evidence, tier)

    out: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for (cve, _gid), (_rank, entry) in sorted(best.items()):
        out[cve].append(entry)
    return dict(out)


def count_attribution_pairs(data: Any) -> Optional[int]:
    """CVE to group pairs in a groups database, or None when it has no
    attributions key (written before I32)."""
    attributions = data.get("attributions") if isinstance(data, dict) else None
    if not isinstance(attributions, dict):
        return None
    return sum(len(v) for v in attributions.values() if isinstance(v, list))


def attributions_collapsed(new_data: Dict[str, Any], existing_path: "str | Path") -> Optional[str]:
    """Why a new groups database must not replace the existing file, or None.

    The groups floor counts groups, not citations, so a bundle whose CVE
    citations vanished would pass it. A write is refused when the new pair
    count is under half the existing file's. An existing file without
    attributions (or none at all) is a bootstrap and never refused.
    """
    path = Path(existing_path)
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            old = count_attribution_pairs(json.load(f))
    except (OSError, ValueError):
        return None
    new = count_attribution_pairs(new_data) or 0
    if old and new < old / 2:
        return f"attribution pairs fell from {old} to {new}, under half; existing {path.name} kept"
    return None


class APTProcessor:
    """Processes ATT&CK Groups STIX data for CVE enrichment"""

    def __init__(self):
        self.config = config
        self.logger = get_logger('apt_processor')
        self.groups_db: Dict[str, Any] = {}
        self.db_path = config.get('database.groups.file', 'resources/groups_db.json')

    @performance_timer("download_stix")
    def download(self) -> Dict[str, Any]:
        """Download ATT&CK Enterprise STIX bundle"""
        url = config.get(
            'database.groups.url',
            'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
        )
        context = create_api_context("download_stix", url)

        try:
            self.logger.info(f"Downloading ATT&CK STIX bundle from {url}")
            timeout = config.get('api.nvd.timeout', 120)
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            stix_data: Dict[str, Any] = response.json()
            obj_count = len(stix_data.get('objects', []))
            self.logger.info(f"Downloaded STIX bundle: {obj_count} objects")
            return stix_data
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Failed to download STIX bundle: {e}", url=url, context=context)

    def _process_stix_data(self, stix_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process STIX bundle into groups database with reverse technique index.

        Returns:
            Dict with three keys:
            - "groups": {group_id: {name, aliases, description, techniques}}
            - "technique_to_groups": {technique_id: [group_ids]}
            - "attributions": {cve: [{id, via, via_type, via_target?}]}, the
              CVEs ATT&CK cites for each group (extract_attributions)
        """
        objects = stix_data.get("objects", [])

        # Index intrusion-sets (groups) by STIX ID
        stix_groups: Dict[str, Dict[str, Any]] = {}
        for obj in objects:
            if obj.get("type") != "intrusion-set":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            stix_id = obj["id"]
            ext_refs = obj.get("external_references", [])
            mitre_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id", "")
                    break
            if not mitre_id:
                continue
            stix_groups[stix_id] = {
                "mitre_id": mitre_id,
                "name": obj.get("name", ""),
                "aliases": obj.get("aliases", []),
                "description": obj.get("description", ""),
            }

        # Index attack-patterns by STIX ID -> technique ID
        stix_to_technique: Dict[str, str] = {}
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    stix_to_technique[obj["id"]] = ref.get("external_id", "")
                    break

        # Build group -> techniques mapping from "uses" relationships
        group_techniques: Dict[str, set] = defaultdict(set)
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "uses":
                continue
            source = obj.get("source_ref", "")
            target = obj.get("target_ref", "")
            if source in stix_groups and target in stix_to_technique:
                mitre_id = stix_groups[source]["mitre_id"]
                technique_id = stix_to_technique[target]
                group_techniques[mitre_id].add(technique_id)

        # Assemble final groups dict
        groups: Dict[str, Any] = {}
        for stix_id, group_data in stix_groups.items():
            mitre_id = group_data["mitre_id"]
            groups[mitre_id] = {
                "name": group_data["name"],
                "aliases": group_data["aliases"],
                "description": group_data["description"],
                "techniques": sorted(group_techniques.get(mitre_id, set()))
            }

        # Build reverse index: technique -> list of group IDs
        technique_to_groups: Dict[str, List[str]] = defaultdict(list)
        for group_id, group_data in groups.items():
            for tech in group_data["techniques"]:
                technique_to_groups[tech].append(group_id)

        attributions = extract_attributions(stix_data)
        pairs = sum(len(v) for v in attributions.values())
        self.logger.info(
            f"Processed {len(groups)} groups, "
            f"{len(technique_to_groups)} techniques with group mappings, "
            f"{pairs} CVE attributions across {len(attributions)} CVEs"
        )

        return {
            "groups": groups,
            "technique_to_groups": dict(technique_to_groups),
            "attributions": attributions,
        }

    def update(self) -> bool:
        """Download, process, and save groups database"""
        try:
            stix_data = self.download()
            data = self._process_stix_data(stix_data)
            refused = attributions_collapsed(data, self.db_path)
            if refused:
                self.logger.warning(f"Groups database not written: {refused}")
                return False
            self.groups_db = data
            self._save(self.groups_db)
            return True
        except Exception as e:
            self.logger.error(f"Failed to update groups database: {e}")
            return False

    def load(self) -> bool:
        """Load groups database from disk"""
        try:
            if Path(self.db_path).exists():
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.groups_db = json.load(f)
                group_count = len(self.groups_db.get("groups", {}))
                self.logger.info(f"Loaded {group_count} groups from {self.db_path}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to load groups database: {e}")
            return False

    def _save(self, data: Dict[str, Any]) -> None:
        """Floor-check and atomically save the groups database"""
        write_reference_db(self.db_path, data, count_groups, indent=2)
        group_count = len(data.get("groups", {}))
        self.logger.info(f"Saved {group_count} groups to {self.db_path}")

    def lookup_attributions(self, cve_id: str) -> List[Dict[str, Any]]:
        """APT groups ATT&CK cites for this CVE, with the citing object.

        Returns [{id, name, via, via_type, via_target?}] sorted by group id,
        or [] when the CVE has no citation or the database predates I32.
        """
        attributions = self.groups_db.get("attributions") if self.groups_db else None
        if not isinstance(attributions, dict):
            return []
        groups = self.groups_db.get("groups", {})
        result = []
        for entry in attributions.get(cve_id) or []:
            group = groups.get(entry.get("id"))
            if not group:
                continue
            result.append({"id": entry["id"], "name": group.get("name", entry["id"]),
                           **{k: entry[k] for k in ("via", "via_type", "via_target") if entry.get(k)}})
        return sorted(result, key=lambda g: g["id"])
