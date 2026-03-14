"""
CISA Known Exploited Vulnerabilities (KEV) Processor

Downloads the KEV catalog from cisagov/kev-data, indexes by CVE ID,
and provides O(1) lookup during CVE enrichment.
"""
import json
from pathlib import Path
from typing import Dict, Any, Optional

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger, NetworkError, FileOperationError
from tip.utils.error_recovery import with_recovery, create_api_context
from tip.utils.performance_optimizer import performance_timer

config = get_config()


class KEVProcessor:
    """Processes CISA KEV catalog data for CVE enrichment"""

    def __init__(self):
        self.config = config
        self.logger = get_logger('kev_processor')
        self.kev_db: Dict[str, Any] = {}
        self.db_path = config.get('database.kev.file', 'resources/kev_db.json')

    @performance_timer("download_kev")
    @with_recovery("download_kev", recovery_strategy="api")
    def download(self) -> Dict[str, Any]:
        """Download KEV catalog from CISA"""
        url = config.get(
            'database.kev.url',
            'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
        )
        context = create_api_context("download_kev", url)

        try:
            self.logger.info(f"Downloading KEV catalog from {url}")
            timeout = config.get('api.nvd.timeout', 60)
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            raw_data = response.json()
            self.logger.info(
                f"Downloaded KEV catalog: {raw_data.get('count', '?')} entries"
            )
            return raw_data
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Failed to download KEV catalog: {e}", url=url, context=context)

    def _process_kev_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw KEV JSON into CVE-indexed lookup dict"""
        indexed = {}
        for vuln in raw_data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue
            indexed[cve_id] = {
                "inKEV": True,
                "dateAdded": vuln.get("dateAdded", ""),
                "dueDate": vuln.get("dueDate", ""),
                "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                "requiredAction": vuln.get("requiredAction", ""),
                "vendorProject": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
            }
        self.logger.info(f"Indexed {len(indexed)} KEV entries by CVE ID")
        return indexed

    def update(self) -> bool:
        """Download, process, and save KEV database"""
        try:
            raw_data = self.download()
            self.kev_db = self._process_kev_data(raw_data)
            self._save(self.kev_db)
            return True
        except Exception as e:
            self.logger.error(f"Failed to update KEV database: {e}")
            return False

    def load(self) -> bool:
        """Load KEV database from disk"""
        try:
            if Path(self.db_path).exists():
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.kev_db = json.load(f)
                self.logger.info(f"Loaded {len(self.kev_db)} KEV entries from {self.db_path}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to load KEV database: {e}")
            return False

    def _save(self, data: Dict[str, Any]):
        """Save processed KEV database to disk"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        self.logger.info(f"Saved {len(data)} KEV entries to {self.db_path}")

    def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a CVE in the KEV catalog. Returns entry dict or None."""
        return self.kev_db.get(cve_id)
