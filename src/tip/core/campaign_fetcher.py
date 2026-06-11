"""
Campaign Fetcher for TIP v1.5

Downloads MITRE ATT&CK STIX data, extracts campaigns with group/technique
relationships, writes campaigns_db.json.

Follows same pattern as apt_processor.py — downloads full STIX bundle,
filters for campaign objects and their relationships.
"""
import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger, NetworkError
from tip.utils.error_recovery import with_recovery, create_api_context
from tip.utils.performance_optimizer import performance_timer

config = get_config()
logger = get_logger('campaign_fetcher')


@performance_timer("campaign_fetch")
@with_recovery("campaign_fetch", recovery_strategy="api")
def _download_stix_bundle() -> Dict[str, Any]:
    """Download ATT&CK Enterprise STIX bundle."""
    url = config.get(
        'database.groups.url',
        'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
    )
    context = create_api_context("campaign_fetch", url)
    logger.info(f"Downloading ATT&CK STIX bundle from {url}")
    timeout = config.get('api.nvd.timeout', 120)
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"Failed to download STIX bundle: {e}", url=url, context=context)


def _extract_campaigns(stix_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract campaigns and their relationships from STIX bundle.

    Returns dict keyed by campaign MITRE ID (e.g., "C0022") with:
    - name, aliases, description, first_seen, last_seen
    - groups: list of group MITRE IDs
    - techniques: list of technique IDs
    - references: list of {source, url}
    """
    objects = stix_data.get("objects", [])

    # Index campaigns by STIX ID
    stix_campaigns: Dict[str, Dict[str, Any]] = {}
    mitre_id_map: Dict[str, str] = {}  # stix_id -> mitre_id

    for obj in objects:
        if obj.get("type") != "campaign":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        stix_id = obj["id"]
        ext_refs = obj.get("external_references", [])
        mitre_id = ""
        refs = []
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
            elif ref.get("url"):
                refs.append({"source": ref.get("source_name", ""), "url": ref["url"]})

        if not mitre_id:
            continue

        stix_campaigns[stix_id] = {
            "mitre_id": mitre_id,
            "name": obj.get("name", ""),
            "aliases": obj.get("aliases", []),
            "description": obj.get("description", ""),
            "first_seen": obj.get("first_seen", ""),
            "last_seen": obj.get("last_seen", ""),
            "references": refs[:5],
        }
        mitre_id_map[stix_id] = mitre_id

    # Index all STIX objects by ID for relationship resolution
    stix_id_to_mitre: Dict[str, str] = {}
    for obj in objects:
        ext_refs = obj.get("external_references", [])
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                stix_id_to_mitre[obj["id"]] = ref.get("external_id", "")
                break

    # Process relationships: campaign -> group, campaign -> technique
    campaign_groups: Dict[str, list] = {mid: [] for mid in mitre_id_map.values()}
    campaign_techniques: Dict[str, list] = {mid: [] for mid in mitre_id_map.values()}

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        source_ref = obj.get("source_ref", "")
        target_ref = obj.get("target_ref", "")
        rel_type = obj.get("relationship_type", "")

        # Campaign attributed-to group
        if rel_type == "attributed-to" and source_ref in stix_campaigns:
            group_mitre_id = stix_id_to_mitre.get(target_ref)
            if group_mitre_id:
                campaign_mid = mitre_id_map[source_ref]
                if group_mitre_id not in campaign_groups[campaign_mid]:
                    campaign_groups[campaign_mid].append(group_mitre_id)

        # Campaign uses technique
        if rel_type == "uses" and source_ref in stix_campaigns:
            tech_mitre_id = stix_id_to_mitre.get(target_ref)
            if tech_mitre_id:
                campaign_mid = mitre_id_map[source_ref]
                if tech_mitre_id not in campaign_techniques[campaign_mid]:
                    campaign_techniques[campaign_mid].append(tech_mitre_id)

    # Build output
    campaigns_db = {}
    for stix_id, campaign in stix_campaigns.items():
        mid = campaign["mitre_id"]
        campaigns_db[mid] = {
            "name": campaign["name"],
            "aliases": campaign["aliases"],
            "description": campaign["description"],
            "first_seen": campaign["first_seen"][:10] if campaign["first_seen"] else "",
            "last_seen": campaign["last_seen"][:10] if campaign["last_seen"] else "",
            "groups": sorted(campaign_groups.get(mid, [])),
            "techniques": sorted(campaign_techniques.get(mid, [])),
            "references": campaign["references"],
        }

    return campaigns_db


def fetch_campaigns(base_dir: str | Path) -> Dict[str, Any]:
    """Fetch campaigns and write to campaigns_db.json."""
    base = Path(base_dir)
    out_path = base / "docs" / "data" / "campaigns_db.json"

    logger.info("Starting campaign fetch")
    stix_data = _download_stix_bundle()
    campaigns_db = _extract_campaigns(stix_data)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(campaigns_db, f, separators=(",", ":"))

    groups_linked = sum(1 for c in campaigns_db.values() if c["groups"])
    techniques_total = sum(len(c["techniques"]) for c in campaigns_db.values())
    logger.info(f"Wrote {len(campaigns_db)} campaigns ({groups_linked} with group attribution, {techniques_total} technique mappings)")

    return campaigns_db


def main():
    parser = argparse.ArgumentParser(description="Fetch MITRE ATT&CK Campaigns")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parents[3]),
        help="Project root directory",
    )
    args = parser.parse_args()
    fetch_campaigns(args.base_dir)


if __name__ == "__main__":
    main()
