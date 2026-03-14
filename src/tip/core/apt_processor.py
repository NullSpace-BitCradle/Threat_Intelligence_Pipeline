"""
APT Groups Processor

Downloads MITRE ATT&CK STIX data, extracts threat groups with aliases and
technique usage, builds a reverse index (technique -> groups) for CVE enrichment.
"""
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any, Optional, List

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger, NetworkError
from tip.utils.error_recovery import with_recovery, create_api_context
from tip.utils.performance_optimizer import performance_timer

config = get_config()


class APTProcessor:
    """Processes ATT&CK Groups STIX data for CVE enrichment"""

    def __init__(self):
        self.config = config
        self.logger = get_logger('apt_processor')
        self.groups_db: Dict[str, Any] = {}
        self.db_path = config.get('database.groups.file', 'resources/groups_db.json')

    @performance_timer("download_stix")
    @with_recovery("download_stix", recovery_strategy="api")
    def download(self) -> Dict[str, Any]:
        """Download ATT&CK Enterprise STIX bundle"""
        url = config.get(
            'database.groups.url',
            'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-16.1.json'
        )
        context = create_api_context("download_stix", url)

        try:
            self.logger.info(f"Downloading ATT&CK STIX bundle from {url}")
            timeout = config.get('api.nvd.timeout', 120)
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            stix_data = response.json()
            obj_count = len(stix_data.get('objects', []))
            self.logger.info(f"Downloaded STIX bundle: {obj_count} objects")
            return stix_data
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Failed to download STIX bundle: {e}", url=url, context=context)

    def _process_stix_data(self, stix_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process STIX bundle into groups database with reverse technique index.

        Returns:
            Dict with two keys:
            - "groups": {group_id: {name, aliases, description, techniques}}
            - "technique_to_groups": {technique_id: [group_ids]}
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

        self.logger.info(
            f"Processed {len(groups)} groups, "
            f"{len(technique_to_groups)} techniques with group mappings"
        )

        return {
            "groups": groups,
            "technique_to_groups": dict(technique_to_groups)
        }

    def update(self) -> bool:
        """Download, process, and save groups database"""
        try:
            stix_data = self.download()
            self.groups_db = self._process_stix_data(stix_data)
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

    def _save(self, data: Dict[str, Any]):
        """Save processed groups database to disk"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        group_count = len(data.get("groups", {}))
        self.logger.info(f"Saved {group_count} groups to {self.db_path}")

    def lookup_by_techniques(self, technique_ids: List[str]) -> List[Dict[str, Any]]:
        """Find APT groups that use any of the given techniques.

        Returns list of dicts with: id, name, aliases, techniques_overlap
        """
        if not self.groups_db:
            return []

        technique_to_groups = self.groups_db.get("technique_to_groups", {})
        groups = self.groups_db.get("groups", {})

        # Collect all matching group IDs and their overlapping techniques
        group_overlaps: Dict[str, set] = defaultdict(set)
        for tech_id in technique_ids:
            for group_id in technique_to_groups.get(tech_id, []):
                group_overlaps[group_id].add(tech_id)

        # Build result list
        result = []
        for group_id, overlap_techs in group_overlaps.items():
            group_data = groups.get(group_id)
            if not group_data:
                continue
            result.append({
                "id": group_id,
                "name": group_data["name"],
                "aliases": group_data["aliases"],
                "techniques_overlap": sorted(overlap_techs)
            })

        return sorted(result, key=lambda g: g["name"])
