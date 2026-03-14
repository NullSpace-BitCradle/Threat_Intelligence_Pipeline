"""
CISA Vulnrichment Processor

Fetches CISA Vulnrichment data (SSVC decisions + CISA CVSS overrides) from
the cisagov/vulnrichment GitHub repo. Uses the GitHub API for incremental
updates and a shallow clone for bootstrap.
"""
import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, Optional

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger, NetworkError
from tip.utils.performance_optimizer import performance_timer

config = get_config()

# CISA ADP provider org ID (identifies the CISA enrichment container)
CISA_ADP_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0"


class VulnrichmentProcessor:
    """Processes CISA Vulnrichment data for CVE enrichment"""

    def __init__(self):
        self.config = config
        self.logger = get_logger('vulnrichment_processor')
        self.vulnrichment_db: Dict[str, Any] = {}
        self.db_path = config.get('database.vulnrichment.file', 'resources/vulnrichment_db.json')
        self.state_path = config.get('database.vulnrichment.state_file', 'resources/vulnrichment_state.json')
        self.repo = config.get('database.vulnrichment.repo', 'cisagov/vulnrichment')

    def _extract_enrichment(self, cve_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract SSVC decision and CISA CVSS from a per-CVE Vulnrichment JSON.

        Args:
            cve_json: Raw JSON from cisagov/vulnrichment for a single CVE

        Returns:
            Dict with ssvcExploitStatus, ssvcAutomatable, ssvcTechnicalImpact,
            and cisaCVSS if found. None if no CISA ADP data present.
        """
        adp_containers = cve_json.get("containers", {}).get("adp", [])

        # Find the CISA ADP container
        cisa_adp = None
        for container in adp_containers:
            org_id = container.get("providerMetadata", {}).get("orgId", "")
            if org_id == CISA_ADP_ORG_ID:
                cisa_adp = container
                break

        if not cisa_adp:
            return None

        metrics = cisa_adp.get("metrics", [])
        if not metrics:
            return None

        result: Dict[str, Any] = {}
        found_ssvc = False

        for metric in metrics:
            # Extract SSVC decision
            other = metric.get("other", {})
            if other.get("type") == "ssvc":
                options = other.get("content", {}).get("options", [])
                for option in options:
                    if "Exploitation" in option:
                        result["ssvcExploitStatus"] = option["Exploitation"]
                        found_ssvc = True
                    if "Automatable" in option:
                        result["ssvcAutomatable"] = option["Automatable"]
                        found_ssvc = True
                    if "Technical Impact" in option:
                        result["ssvcTechnicalImpact"] = option["Technical Impact"]
                        found_ssvc = True

            # Extract CISA CVSS
            cvss = metric.get("cvssV3_1")
            if cvss:
                result["cisaCVSS"] = {
                    "baseScore": cvss.get("baseScore"),
                    "vector": cvss.get("vectorString", "")
                }

        return result if found_ssvc else None

    @performance_timer("update_vulnrichment")
    def update(self) -> bool:
        """Update Vulnrichment database using GitHub API (incremental) or clone (bootstrap)"""
        try:
            state = self._load_state()
            last_sha = state.get("last_commit_sha")

            if last_sha:
                # Incremental update via GitHub API
                self.logger.info(f"Incremental Vulnrichment update from SHA {last_sha[:8]}...")
                success = self._incremental_update(last_sha)
            else:
                # Bootstrap via shallow clone
                self.logger.info("Bootstrap: cloning Vulnrichment repo (first run)...")
                success = self._bootstrap_clone()

            if success:
                self._save(self.vulnrichment_db)
            return success

        except Exception as e:
            self.logger.error(f"Failed to update Vulnrichment database: {e}")
            return False

    def _incremental_update(self, last_sha: str) -> bool:
        """Fetch only changed CVE files since last_sha using GitHub Compare API"""
        try:
            # Get current HEAD SHA
            url = f"https://api.github.com/repos/{self.repo}/commits?per_page=1"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            current_sha = response.json()[0]["sha"]

            if current_sha == last_sha:
                self.logger.info("Vulnrichment repo unchanged since last update")
                return True

            # Get diff between last and current
            compare_url = f"https://api.github.com/repos/{self.repo}/compare/{last_sha}...{current_sha}"
            response = requests.get(compare_url, timeout=60)
            response.raise_for_status()
            compare_data = response.json()

            # Load existing db
            self.load()

            # Process changed files
            changed_files = compare_data.get("files", [])
            cve_files = [f for f in changed_files if f["filename"].endswith(".json") and "CVE-" in f["filename"]]

            self.logger.info(f"Processing {len(cve_files)} changed Vulnrichment files...")

            for file_info in cve_files:
                if file_info["status"] == "removed":
                    cve_id = Path(file_info["filename"]).stem
                    self.vulnrichment_db.pop(cve_id, None)
                    continue

                # Fetch file content
                raw_url = file_info.get("raw_url")
                if not raw_url:
                    continue

                try:
                    resp = requests.get(raw_url, timeout=30)
                    resp.raise_for_status()
                    cve_json = resp.json()
                    cve_id = Path(file_info["filename"]).stem
                    enrichment = self._extract_enrichment(cve_json)
                    if enrichment:
                        self.vulnrichment_db[cve_id] = enrichment
                except Exception as e:
                    self.logger.debug(f"Error processing {file_info['filename']}: {e}")
                    continue

            # Save state
            self._save_state({"last_commit_sha": current_sha})
            self.logger.info(f"Incremental update complete. DB has {len(self.vulnrichment_db)} entries.")
            return True

        except Exception as e:
            self.logger.error(f"Incremental update failed: {e}")
            return False

    def _bootstrap_clone(self) -> bool:
        """Bootstrap by shallow-cloning the full repo and processing all CVEs"""
        clone_dir = Path(self.db_path).parent / "_vulnrichment_clone"
        try:
            # Shallow clone
            subprocess.run(
                ["git", "clone", "--depth=1", f"https://github.com/{self.repo}.git", str(clone_dir)],
                check=True, capture_output=True, text=True, timeout=600
            )

            # Get HEAD SHA for state tracking
            result = subprocess.run(
                ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True
            )
            head_sha = result.stdout.strip()

            # Process all CVE JSON files
            self.vulnrichment_db = {}
            cve_count = 0
            for json_file in clone_dir.rglob("CVE-*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        cve_json = json.load(f)
                    enrichment = self._extract_enrichment(cve_json)
                    if enrichment:
                        cve_id = json_file.stem
                        self.vulnrichment_db[cve_id] = enrichment
                        cve_count += 1
                except Exception as e:
                    self.logger.debug(f"Error processing {json_file.name}: {e}")
                    continue

            self._save_state({"last_commit_sha": head_sha})
            self.logger.info(f"Bootstrap complete. Processed {cve_count} CVEs with SSVC data.")
            return True

        except subprocess.TimeoutExpired:
            self.logger.error("Vulnrichment clone timed out after 10 minutes")
            return False
        except Exception as e:
            self.logger.error(f"Bootstrap clone failed: {e}")
            return False
        finally:
            # Clean up clone
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)

    def load(self) -> bool:
        """Load Vulnrichment database from disk"""
        try:
            if Path(self.db_path).exists():
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.vulnrichment_db = json.load(f)
                self.logger.info(f"Loaded {len(self.vulnrichment_db)} Vulnrichment entries")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to load Vulnrichment database: {e}")
            return False

    def _save(self, data: Dict[str, Any]):
        """Save processed Vulnrichment database to disk"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        self.logger.info(f"Saved {len(data)} Vulnrichment entries to {self.db_path}")

    def _load_state(self) -> Dict[str, Any]:
        """Load update state (last processed commit SHA)"""
        try:
            if Path(self.state_path).exists():
                with open(self.state_path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_state(self, state: Dict[str, Any]):
        """Save update state"""
        Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_path, 'w') as f:
            json.dump(state, f, indent=2)

    def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a CVE's Vulnrichment data. Returns entry dict or None."""
        return self.vulnrichment_db.get(cve_id)
