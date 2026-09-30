"""
CISA Vulnrichment Processor

Fetches CISA Vulnrichment data (SSVC decisions + CISA CVSS overrides) from
the cisagov/vulnrichment GitHub repo. One authenticated GitHub API call
detects whether upstream moved; a shallow clone refreshes the data.
"""
import json
import os
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, Optional

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger
from tip.utils.performance_optimizer import performance_timer
from tip.utils.atomic_io import atomic_write_json, write_reference_db
from tip.utils.http import get_with_retry

config = get_config()

# CISA ADP provider org ID (identifies the CISA enrichment container)
CISA_ADP_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0"


class VulnrichmentProcessor:
    """Processes CISA Vulnrichment data for CVE enrichment"""

    def __init__(self):
        self.config = config
        self.logger = get_logger('vulnrichment_processor')
        self.vulnrichment_db: Dict[str, Any] = {}
        # HEAD sha of the data now in memory; persisted only after the DB is.
        self._pending_sha: Optional[str] = None
        self.db_path = config.get('database.vulnrichment.file', 'resources/vulnrichment_db.json')
        self.state_path = config.get('database.vulnrichment.state_file', 'resources/vulnrichment_state.json')
        self.repo = config.get('database.vulnrichment.repo', 'cisagov/vulnrichment')

    def _api_headers(self) -> Dict[str, str]:
        """Headers for api.github.com calls.

        CI passes GITHUB_TOKEN so the HEAD check is not rate
        limited per runner IP. The token goes in a header only, never in a URL,
        and only to the API, never to raw file hosts.
        """
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

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
        """Update the Vulnrichment database: HEAD check, then a clone only if upstream moved"""
        try:
            state = self._load_state()
            last_sha = state.get("last_commit_sha")

            if last_sha:
                # Clone only when upstream moved
                self.logger.info(f"Checking Vulnrichment for changes since SHA {last_sha[:8]}...")
                success = self._incremental_update(last_sha)
            else:
                # Bootstrap via shallow clone
                self.logger.info("Bootstrap: cloning Vulnrichment repo (first run)...")
                success = self._bootstrap_clone()

            if success:
                # DB first, state second: a refused or failed DB write must
                # not advance last_commit_sha past data that never landed.
                self._save(self.vulnrichment_db)
                if self._pending_sha:
                    self._save_state({"last_commit_sha": self._pending_sha})
            return success

        except Exception as e:
            self.logger.error(f"Failed to update Vulnrichment database: {e}")
            return False

    def _incremental_update(self, last_sha: str) -> bool:
        """Refresh only when upstream moved, and then by a full shallow clone.

        One authenticated API call checks HEAD. When it moved, the refresh is
        a clone rather than a compare delta: the delta meant up to 299
        anonymous per-file fetches from a shared runner IP, and those get
        rate limited. Fail-closed: the on-disk DB is loaded first, and a
        failed HEAD check or clone returns False without advancing
        ``last_commit_sha``.
        """
        try:
            # Load first: every path that returns True leads update() to save
            # self.vulnrichment_db, so it must never be the empty initial dict.
            if not self.load():
                self.logger.warning("Existing Vulnrichment DB missing or unreadable; falling back to full resync")
                return self._bootstrap_clone()

            url = f"https://api.github.com/repos/{self.repo}/commits?per_page=1"
            response = get_with_retry(url, headers=self._api_headers(), timeout=30)
            response.raise_for_status()
            current_sha = response.json()[0]["sha"]

            if current_sha == last_sha:
                self.logger.info("Vulnrichment repo unchanged since last update")
                return True

            self.logger.info(f"Vulnrichment moved to {current_sha[:8]}; refreshing by shallow clone")
            return self._bootstrap_clone()

        except Exception as e:
            self.logger.error(f"Incremental update failed: {e}")
            return False

    def _bootstrap_clone(self) -> bool:
        """Bootstrap by shallow-cloning the full repo and processing all CVEs"""
        clone_dir = Path(self.db_path).parent / "_vulnrichment_clone"
        try:
            # Shallow clone, with one retry: it now runs on most days, and a
            # dropped connection should not fail the whole run.
            for attempt in (1, 2):
                try:
                    subprocess.run(
                        ["git", "clone", "--depth=1", f"https://github.com/{self.repo}.git", str(clone_dir)],
                        check=True, capture_output=True, text=True, timeout=600
                    )
                    break
                except subprocess.CalledProcessError as e:
                    if attempt == 2:
                        raise
                    self.logger.warning(f"Vulnrichment clone failed (exit {e.returncode}); retrying once")
                    shutil.rmtree(clone_dir, ignore_errors=True)

            # Get HEAD SHA for state tracking
            result = subprocess.run(
                ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True
            )
            head_sha = result.stdout.strip()

            # Process all CVE JSON files into a fresh dict; it replaces the
            # in-memory DB only once the whole clone has been read. Any file
            # that cannot be read or parsed aborts the resync: an incomplete
            # dict must not be saved, and last_commit_sha must not advance.
            fresh: Dict[str, Any] = {}
            cve_count = 0
            for json_file in clone_dir.rglob("CVE-*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        cve_json = json.load(f)
                    enrichment = self._extract_enrichment(cve_json)
                except Exception as e:
                    self.logger.error(
                        f"Vulnrichment resync aborted: {json_file.name} unreadable "
                        f"({type(e).__name__}: {e}); DB and state left unchanged"
                    )
                    return False
                if enrichment:
                    fresh[json_file.stem] = enrichment
                    cve_count += 1

            self.vulnrichment_db = fresh
            self._pending_sha = head_sha
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

    def _save(self, data: Dict[str, Any]) -> None:
        """Floor-check and atomically save the Vulnrichment database"""
        write_reference_db(self.db_path, data, indent=2)
        self.logger.info(f"Saved {len(data)} Vulnrichment entries to {self.db_path}")

    def _load_state(self) -> Dict[str, Any]:
        """Load update state (last processed commit SHA)"""
        try:
            if Path(self.state_path).exists():
                with open(self.state_path, 'r') as f:
                    state = json.load(f)
                    if isinstance(state, dict):
                        return state
        except Exception:
            pass
        return {}

    def _save_state(self, state: Dict[str, Any]) -> None:
        """Atomically save update state"""
        atomic_write_json(self.state_path, state, indent=2)

    def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a CVE's Vulnrichment data. Returns entry dict or None."""
        return self.vulnrichment_db.get(cve_id)
