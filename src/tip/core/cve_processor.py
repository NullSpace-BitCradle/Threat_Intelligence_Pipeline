#!/usr/bin/env python3
"""
Unified CVE processing pipeline
Combines all CVE processing steps into a single, efficient class
"""
import json
import re
import sys
import time
import requests
from typing import Dict, Any, List, Optional, cast
from pathlib import Path

from tip.utils.config import get_config
from tip.database.database_optimizer import get_jsonl_manager
from tip.utils.performance_optimizer import performance_timer, get_global_cache
from tip.utils.error_handler import log_operation, NVDUnavailableError, get_logger
from tip.utils.validation import validate_cve_data, safe_parse_capec_techniques
from tip.core.owasp_processor import OWASPProcessor
from tip.core.kev_processor import KEVProcessor
from tip.core.vulnrichment_processor import VulnrichmentProcessor
from tip.core.apt_processor import APTProcessor
from tip.core.id_normalize import cwe_number, cwe_parents, expand_cwe_list
from tip.utils.atomic_io import atomic_write_bytes, atomic_write_json, jsonl_bytes

config = get_config()
config.setup_logging()

# NVD API 2.0 guidance: sleep 6 s between requests without a key, 0.6 s with
# one (5 and 50 requests per rolling 30 s window).
NVD_DELAY_KEYLESS = 6.0
NVD_DELAY_KEYED = 0.6

# A CVE whose enrichment throws is not written. The cve_processing step fails
# when such failures exceed 1% of the CVEs processed or 50, whichever is
# smaller.
ENRICHMENT_FAILURE_RATE = 0.01
ENRICHMENT_FAILURE_MAX = 50


def nvd_request_delay(has_api_key: bool) -> float:
    """Seconds to wait between successful NVD page requests."""
    return NVD_DELAY_KEYED if has_api_key else NVD_DELAY_KEYLESS


class CVEProcessor:
    """Unified CVE processing pipeline"""

    # Counts from the last process_cve_pipeline call: attempted, failed,
    # failed_ids. None before the first call.
    last_enrichment: Optional[Dict[str, Any]] = None

    def __init__(self):
        self.config = config
        self.cache = get_global_cache()
        self.last_fetch_resumed_from = 0
        self.jsonl_manager = get_jsonl_manager()
        self.logger = get_logger('cve_processor')
        
        # File paths
        self.cve_file = config.get_output_path('cve_output')
        self.cwe_file = config.get_database_path('cwe')
        self.capec_file = config.get_database_path('capec')
        self.techniques_file = config.get_database_path('techniques')
        
        # Load databases
        self.cwe_db = self._load_cwe_db()
        self.capec_db = self._load_capec_db()
        self.techniques_db = self._load_techniques_db()
        
        # Initialize OWASP processor
        self.owasp_processor = OWASPProcessor(self.config.config)

        # Initialize KEV processor
        self.kev_processor = KEVProcessor()
        self.kev_processor.load()

        # Initialize Vulnrichment processor
        self.vulnrichment_processor = VulnrichmentProcessor()
        self.vulnrichment_processor.load()

        # Initialize APT Groups processor
        self.apt_processor = APTProcessor()
        self.apt_processor.load()
    
    def retrieve_cves_from_nvd(self, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve CVEs from NVD API with progress tracking and resume capability.

        Completion is decided by NVD's ``totalResults``: the crawl ends only
        when ``startIndex`` reaches it. An empty page before that point is an
        outage, not the end of the corpus. Pages are paced by
        ``nvd_request_delay``. When the fetch resumes from a progress file,
        ``self.last_fetch_resumed_from`` records the start index so the caller
        can report a partial refresh.
        """
        self.last_fetch_resumed_from = 0
        try:
            api_key = self.config.get_api_key('nvd')
            base_url = self.config.get('api.nvd.base_url')

            headers = {}
            if api_key:
                headers['apiKey'] = api_key

            params: Dict[str, Any] = {
                'resultsPerPage': self.config.get('api.nvd.results_per_page', 2000),
                'startIndex': 0
            }

            if start_date:
                params['pubStartDate'] = start_date
            if end_date:
                params['pubEndDate'] = end_date

            # Progress tracking - use config value
            progress_file = Path(self.config.get('files.progress_file', 'cve_progress.json'))
            save_interval = self.config.get('progress_tracking.save_interval', 5000)
            log_interval = self.config.get('progress_tracking.log_interval', 10000)
            all_cves: List[Dict[str, Any]] = []
            start_index = 0

            # Try to resume from previous progress
            if progress_file.exists():
                try:
                    with open(progress_file, 'r') as f:
                        progress_data = json.load(f)
                        start_index = int(progress_data.get('last_index', 0))
                        self.logger.info(f"Resuming CVE retrieval from index {start_index}")
                except Exception as e:
                    self.logger.warning(f"Could not load progress file: {e}")
            self.last_fetch_resumed_from = start_index

            self.logger.info("Retrieving CVEs from NVD API...")

            # Retry backoff for 429/5xx/timeouts comes from config; the pacing
            # between successful pages is NVD's documented limit.
            rate_limit_config = self.config.get('api.nvd.rate_limit', {})
            base_delay = rate_limit_config.get('base_delay', 0.5)
            max_delay = rate_limit_config.get('max_delay', 60.0)
            backoff_multiplier = rate_limit_config.get('backoff_multiplier', 2.5)
            # NVD periodically returns 503/read-timeouts during brownouts that can
            # last minutes; 8 retries with capped exponential backoff gives the
            # endpoint a multi-minute window to recover before the run fails.
            max_retries = rate_limit_config.get('max_retries', 8)
            page_delay = nvd_request_delay(bool(api_key))
            total_results: Optional[int] = None

            while True:
                params['startIndex'] = start_index
                retry_delay = base_delay

                for attempt in range(max_retries):
                    try:
                        response = requests.get(base_url, headers=headers, params=params,
                                             timeout=self.config.get('api.nvd.timeout', 30))

                        if response.status_code == 429:
                            if attempt < max_retries - 1:
                                # Exponential backoff with jitter
                                jitter = time.time() % 1.0
                                actual_delay = retry_delay + jitter

                                self.logger.warning(f"Rate limited (429), waiting {actual_delay:.2f}s before retry {attempt + 1}/{max_retries}")
                                time.sleep(actual_delay)
                                # Cap the backoff so deep retry chains stay bounded.
                                retry_delay = min(retry_delay * backoff_multiplier, max_delay)
                                continue
                            else:
                                self.logger.error("Rate limited, max retries exceeded")
                                break

                        response.raise_for_status()
                        break

                    except requests.exceptions.RequestException as e:
                        if attempt < max_retries - 1:
                            self.logger.warning(
                                f"Request failed ({e}); retrying in {retry_delay:.2f}s "
                                f"(attempt {attempt + 1}/{max_retries})"
                            )
                            time.sleep(retry_delay)
                            # Cap the backoff so deep retry chains stay bounded.
                            retry_delay = min(retry_delay * 2, max_delay)
                        else:
                            # Retry budget exhausted against an unreachable/slow
                            # NVD. Raise a typed error instead of letting an empty
                            # return masquerade as "no new CVEs" downstream.
                            raise NVDUnavailableError(
                                f"NVD unreachable after {max_retries} attempts: {e}",
                                url=base_url,
                                partial_count=len(all_cves),
                                last_index=start_index,
                            ) from e

                if response.status_code == 429:
                    # Rate-limit retries exhausted mid-pagination. Raise rather
                    # than break-and-return the partial page set as if the fetch
                    # were complete (silent truncation). Resume picks up from the
                    # progress file on the next run.
                    self.logger.error(
                        "NVD rate-limited (429) past retry budget at index "
                        f"{start_index} ({len(all_cves)} collected this run)"
                    )
                    raise NVDUnavailableError(
                        f"NVD rate-limited (429) past {max_retries} retries",
                        url=base_url,
                        partial_count=len(all_cves),
                        last_index=start_index,
                    )

                data = response.json()
                if (
                    not isinstance(data, dict)
                    or not isinstance(data.get('vulnerabilities'), list)
                    or not isinstance(data.get('totalResults'), int)
                ):
                    # A 200 that lacks the expected NVD envelope (an error or
                    # maintenance page served with status 200 during a brownout)
                    # is an outage, not a genuine empty result.
                    raise NVDUnavailableError(
                        "NVD returned 200 without 'vulnerabilities' and 'totalResults' "
                        "(malformed/maintenance response)",
                        url=base_url,
                        partial_count=len(all_cves),
                        last_index=start_index,
                    )
                total_results = data['totalResults']
                cves = data['vulnerabilities']

                if not cves:
                    if start_index >= total_results:
                        break
                    # An empty page before totalResults is a truncated corpus,
                    # never the end of it.
                    raise NVDUnavailableError(
                        f"NVD returned an empty page at index {start_index} of "
                        f"{total_results}",
                        url=base_url,
                        partial_count=len(all_cves),
                        last_index=start_index,
                    )

                all_cves.extend(cves)
                start_index += len(cves)

                if len(all_cves) % log_interval == 0 or start_index >= total_results:
                    self.logger.info(f"Retrieved {len(cves)} CVEs (index {start_index}/{total_results})")

                # Save progress at configured interval
                if len(all_cves) % save_interval == 0:
                    progress_data = {
                        'last_index': start_index,
                        'total_retrieved': len(all_cves),
                        'timestamp': time.time()
                    }
                    try:
                        atomic_write_json(progress_file, progress_data)
                    except Exception as e:
                        self.logger.warning(f"Could not save progress: {e}")

                if start_index >= total_results:
                    break

                # A short page before totalResults just means "keep going":
                # the next request starts where this one ended.
                time.sleep(page_delay)

            self.logger.info(f"Total CVEs retrieved: {len(all_cves)} (totalResults {total_results})")

            # Clean up progress file on successful completion
            if progress_file.exists():
                try:
                    progress_file.unlink()
                    self.logger.info("Progress file cleaned up")
                except Exception as e:
                    self.logger.warning(f"Could not clean up progress file: {e}")

            return all_cves

        except NVDUnavailableError:
            # Already typed and logged at the failure point; propagate so the
            # orchestrator records a degraded run instead of false success.
            raise
        except Exception as e:
            # Any other unexpected failure must surface too. Returning [] here is
            # what made an outage read downstream as "no new CVEs".
            self.logger.error(f"Failed to retrieve CVEs from NVD: {e}")
            raise NVDUnavailableError(
                f"Unexpected failure retrieving CVEs from NVD: {e}",
                url=self.config.get('api.nvd.base_url'),
            ) from e

    def process_nvd_cves(self, nvd_cves: List[Dict]) -> Dict[str, Any]:
        """Process NVD CVE data into our format"""
        processed_cves = {}
        
        for cve_data in nvd_cves:
            try:
                cve_id = cve_data.get('cve', {}).get('id', '')
                if not cve_id:
                    continue
                
                # Extract CWE IDs - Primary method: from weaknesses field
                cwe_ids = []
                
                # Method 1: Extract from weaknesses field (proper NVD API structure)
                weaknesses = cve_data.get('cve', {}).get('weaknesses', [])
                for weakness in weaknesses:
                    for desc in weakness.get('description', []):
                        cwe_value = desc.get('value', '')
                        if cwe_value and cwe_value.startswith('CWE-'):
                            cwe_ids.append(cwe_value)
                
                # Method 2: Fallback - Extract from description text (for incomplete entries)
                if not cwe_ids:
                    descriptions = cve_data.get('cve', {}).get('descriptions', [])
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            desc_text = desc.get('value', '')
                            # Look for CWE patterns in description
                            cwe_matches = re.findall(r'CWE-(\d+)', desc_text)
                            cwe_ids.extend([f"CWE-{match}" for match in cwe_matches])
                
                # Remove duplicates while preserving order
                seen = set()
                unique_cwe_ids = []
                for cwe_id in cwe_ids:
                    if cwe_id not in seen:
                        seen.add(cwe_id)
                        unique_cwe_ids.append(cwe_id)
                
                # Extract English description
                description = ''
                for desc in cve_data.get('cve', {}).get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                # Extract CVSS metrics, newest version first. v2 fallback matters
                # for pre-2016 CVEs that NVD never re-scored against v3.
                cvss_score = None
                cvss_vector = ''
                cvss_severity = ''
                cvss_version = ''
                metrics = cve_data.get('cve', {}).get('metrics', {})
                for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                    metric_list = metrics.get(key) or []
                    primary = next(
                        (m for m in metric_list if m.get('type') == 'Primary'),
                        metric_list[0] if metric_list else None,
                    )
                    if primary:
                        cvss_data = primary.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString', '')
                        cvss_severity = (
                            cvss_data.get('baseSeverity')
                            or primary.get('baseSeverity', '')
                        )
                        cvss_version = cvss_data.get('version', '')
                        break

                # Extract publication / modification timestamps
                published = cve_data.get('cve', {}).get('published', '')
                last_modified = cve_data.get('cve', {}).get('lastModified', '')

                # Extract deduplicated reference URLs
                reference_urls: List[str] = []
                seen_urls: set = set()
                for ref in cve_data.get('cve', {}).get('references', []):
                    url = ref.get('url', '').strip()
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        reference_urls.append(url)

                record: Dict[str, Any] = {
                    'CWE': unique_cwe_ids,
                    'CAPEC': [],
                    'TECHNIQUES': [],
                    'DEFEND': [],
                    'DESCRIPTION': description,
                    'PUBLISHED': published,
                    'LAST_MODIFIED': last_modified,
                    'REFERENCES': reference_urls,
                }
                if cvss_score is not None:
                    record['CVSS'] = {
                        'score': cvss_score,
                        'vector': cvss_vector,
                        'severity': cvss_severity,
                        'version': cvss_version,
                    }
                processed_cves[cve_id] = record
                
            except Exception as e:
                self.logger.warning(f"Error processing CVE {cve_id}: {e}")
                continue
        
        return processed_cves
    
    def _load_cwe_db(self) -> Dict[str, Any]:
        """Load CWE database"""
        try:
            with open(self.cwe_file, 'r') as f:
                db: Dict[str, Any] = json.load(f)
                return db
        except Exception as e:
            self.logger.error(f"Failed to load CWE database: {e}")
            return {}
    
    def _load_capec_db(self) -> Dict[str, Any]:
        """Load CAPEC database"""
        try:
            with open(self.capec_file, 'r') as f:
                db: Dict[str, Any] = json.load(f)
                return db
        except Exception as e:
            self.logger.error(f"Failed to load CAPEC database: {e}")
            return {}
    
    def _load_techniques_db(self) -> Dict[str, Any]:
        """Load techniques database"""
        try:
            with open(self.techniques_file, 'r') as f:
                db: Dict[str, Any] = json.load(f)
                return db
        except Exception as e:
            self.logger.error(f"Failed to load techniques database: {e}")
            return {}
    
    def get_parent_cwe(self, cwe: str) -> Optional[List[str]]:
        """One level of ChildOf parents as normalized ``CWE-<n>`` ids, or None.

        Delegates to the shared definition in ``tip.core.id_normalize`` so the
        processor and the entity index generator cannot disagree.
        """
        parents = cwe_parents(self.cwe_db, cwe)
        return parents or None

    def fetch_capec_for_cwe(self, cwe: str) -> List[str]:
        """Fetch CAPEC entries for a CWE (``'79'`` or ``'CWE-79'``)"""
        try:
            result = self.cwe_db.get(cwe_number(cwe) or cwe, {})
            capec_list = result.get("RelatedAttackPatterns", [])
            return list(capec_list) if capec_list else []
        except Exception as e:
            self.logger.warning(f"Exception for CWE-{cwe}: {str(e)}")
            return []
    
    def get_techniques_for_capec(self, capec_id: str) -> List[str]:
        """Get techniques for a CAPEC ID"""
        try:
            capec_data = self.capec_db.get(capec_id, {})
            techniques_string = capec_data.get("techniques", "")
            if techniques_string:
                return safe_parse_capec_techniques(techniques_string)
            return []
        except Exception as e:
            self.logger.warning(f"Exception for CAPEC-{capec_id}: {str(e)}")
            return []
    
    def get_defend_techniques(self, technique_id: str) -> List[Dict[str, str]]:
        """Get D3FEND defensive techniques for a MITRE ATT&CK technique"""
        # Load D3FEND database
        defend_file = self.config.get_database_path('defend')
        
        # Check cache first
        cache_key = f"defend_{technique_id}"
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            return cast(List[Dict[str, str]], cached_result)

        try:
            # Normalize technique ID
            attack_id = technique_id if technique_id.startswith('T') else f"T{technique_id}"
            
            # Try to load from JSONL file first
            if Path(defend_file).exists():
                for entry in self.jsonl_manager.read_jsonl(defend_file):
                    if attack_id in entry:
                        result: List[Dict[str, str]] = entry[attack_id].get('defensive_techniques', [])
                        self.cache.set(cache_key, result, ttl=3600)
                        return result
            
            # Try JSON file as fallback
            defend_json = defend_file.replace('.jsonl', '.json')
            if Path(defend_json).exists():
                with open(defend_json, 'r') as f:
                    defend_db = json.load(f)
                    if attack_id in defend_db:
                        result = defend_db[attack_id].get('defensive_techniques', [])
                        self.cache.set(cache_key, result, ttl=3600)
                        return result
            
            # Cache empty result to avoid repeated lookups
            self.cache.set(cache_key, [], ttl=3600)
            return []
            
        except Exception as e:
            self.logger.debug(f"Error getting D3FEND techniques for {technique_id}: {e}")
            return []
    
    @log_operation("process_cve_pipeline", "cve_processing")
    def process_cve_pipeline(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single CVE through the entire pipeline"""
        result: Dict[str, Dict[str, Any]] = {}
        failed_ids: List[str] = []

        # Fields preserved verbatim from ingest (raw NVD data) through enrichment.
        PRESERVED_FIELDS = (
            'DESCRIPTION', 'PUBLISHED', 'LAST_MODIFIED', 'REFERENCES', 'CVSS',
        )

        for cve_id, data in cve_data.items():
            try:
                # Step 1: CWE list plus one level of ChildOf parents, every
                # id normalized to CWE-<n> (shared definition, ISC-21/23).
                cwe_list = expand_cwe_list(self.cwe_db, data.get('CWE', []))

                result[cve_id] = {"CWE": cwe_list}
                # Carry forward raw NVD fields that enrichment does not regenerate.
                for field in PRESERVED_FIELDS:
                    if field in data:
                        result[cve_id][field] = data[field]
                
                # Step 2: Get CAPEC entries
                capec_list = set()
                for cwe in cwe_list:
                    capec_list.update(self.fetch_capec_for_cwe(cwe))
                
                result[cve_id]["CAPEC"] = list(sorted(capec_list))
                
                # Step 3: Get techniques
                techniques_list = set()
                for capec in capec_list:
                    techniques = self.get_techniques_for_capec(capec)
                    techniques_list.update(techniques)
                
                result[cve_id]["TECHNIQUES"] = list(sorted(techniques_list))
                
                # Step 4: Get D3FEND techniques
                defend_list: List[Dict[str, str]] = []
                seen_defend_ids: set = set()
                for technique in techniques_list:
                    defend_techniques = self.get_defend_techniques(technique)
                    for dt in defend_techniques:
                        dt_id = dt.get('id', '')
                        if dt_id and dt_id not in seen_defend_ids:
                            seen_defend_ids.add(dt_id)
                            defend_list.append(dt)
                
                # Sort by ID for consistent output
                result[cve_id]["DEFEND"] = sorted(defend_list, key=lambda x: x.get('id', ''))
                
                # Step 5: Get OWASP Top 10 categories
                # Use result[cve_id] which contains enriched CWE list with parent CWEs
                owasp_categories = self.owasp_processor.get_owasp_categories_for_cve(result[cve_id])
                result[cve_id]["OWASP"] = owasp_categories

                # Step 6: KEV lookup
                kev_data = self.kev_processor.lookup(cve_id)
                if kev_data:
                    result[cve_id]["KEV"] = kev_data

                # Step 7: Vulnrichment SSVC + CVSS lookup
                vr_data = self.vulnrichment_processor.lookup(cve_id)
                if vr_data:
                    result[cve_id]["VULNRICHMENT"] = vr_data
                    # Merge cisaCVSS into the top-level CVSS field when NVD
                    # did not provide one. Keeps the shard self-contained so
                    # the entity_index generator does not need to re-open
                    # vulnrichment_db.json on every rebuild.
                    existing_cvss = result[cve_id].get("CVSS")
                    has_nvd_cvss = (
                        isinstance(existing_cvss, dict)
                        and existing_cvss.get("score") is not None
                    )
                    cisa_cvss = vr_data.get("cisaCVSS") if isinstance(vr_data, dict) else None
                    if not has_nvd_cvss and isinstance(cisa_cvss, dict):
                        score = cisa_cvss.get("baseScore")
                        if isinstance(score, (int, float)):
                            score_f = float(score)
                            if score_f >= 9.0:
                                severity = "CRITICAL"
                            elif score_f >= 7.0:
                                severity = "HIGH"
                            elif score_f >= 4.0:
                                severity = "MEDIUM"
                            elif score_f > 0.0:
                                severity = "LOW"
                            else:
                                severity = "NONE"
                            result[cve_id]["CVSS"] = {
                                "score": score_f,
                                "vector": cisa_cvss.get("vector", ""),
                                "severity": cisa_cvss.get("baseSeverity") or severity,
                                "version": "3.1",
                                "source": "cisa_vulnrichment",
                            }

                # Step 8: APT Groups reverse lookup from techniques
                if result[cve_id].get("TECHNIQUES"):
                    apt_groups = self.apt_processor.lookup_by_techniques(result[cve_id]["TECHNIQUES"])
                    if apt_groups:
                        result[cve_id]["APT_GROUPS"] = apt_groups

            except Exception as e:
                # Never publish a stripped record: a partial result would
                # replace the complete one already in the shard. The CVE is
                # left out, its previous record stays, and the failure is
                # counted so process_file can fail the step.
                self.logger.error(f"Error processing CVE {cve_id}: {e}")
                result.pop(cve_id, None)
                failed_ids.append(cve_id)

        self.last_enrichment = {
            "attempted": len(cve_data),
            "failed": len(failed_ids),
            "failed_ids": failed_ids,
        }
        return result
    
    @staticmethod
    def enrichment_failures_exceed_threshold(failed: int, attempted: int) -> bool:
        """True when failures exceed 1% of attempted CVEs or 50, whichever
        is smaller. Above it the cve_processing step fails."""
        return failed > min(attempted * ENRICHMENT_FAILURE_RATE, ENRICHMENT_FAILURE_MAX)

    def save_results(self, results: Dict[str, Any]) -> None:
        """Save results to JSONL file and update database"""
        # Save to main output file
        atomic_write_bytes(self.cve_file, jsonl_bytes(results.items()))
        
        # Update database files by year
        new_cves: Dict[str, Dict[str, Any]] = {}
        for cve_id, data in results.items():
            year = cve_id.split('-')[1]
            if year not in new_cves:
                new_cves[year] = {}
            new_cves[year][cve_id] = data
        
        # Update database files incrementally
        for year, cves in new_cves.items():
            database_dir = config.get('files.database_dir', 'database')
            db_file = f'{database_dir}/CVE-{year}.jsonl'
            self.jsonl_manager.save_jsonl_incremental(db_file, cves)
            self.logger.info(f"Updated {len(cves)} CVEs in {db_file}")
    
    def process_file(self, input_file: Optional[str] = None) -> bool:
        """Process CVE data from file"""
        file_path = input_file or self.cve_file
        
        if not Path(file_path).exists():
            self.logger.error(f"Input file not found: {file_path}")
            return False
        
        # Load CVE data
        cve_data = {}
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    cve_entry = json.loads(line.strip())
                    cve_data.update(cve_entry)
        except Exception as e:
            self.logger.error(f"Failed to load CVE data: {e}")
            return False
        
        if not cve_data:
            self.logger.info("No CVE data found")
            return True
        
        # Validate data structure
        if not validate_cve_data(cve_data):
            self.logger.error("Invalid CVE data structure")
            return False
        
        # Process through pipeline
        try:
            results = self.process_cve_pipeline(cve_data)
            # Successful records are saved even when the run fails below:
            # they are correct, failed CVEs keep their previous record, and
            # the workflow publishes nothing unless the run exits 0.
            self.save_results(results)
            stats = self.last_enrichment or {}
            failed = int(stats.get("failed", 0))
            attempted = int(stats.get("attempted", len(cve_data)))
            if failed:
                self.logger.warning(
                    f"{failed} of {attempted} CVEs failed enrichment and were not "
                    "written; their previous records are kept"
                )
            if self.enrichment_failures_exceed_threshold(failed, attempted):
                self.logger.error(
                    f"Enrichment failures ({failed} of {attempted}) exceed the "
                    f"threshold of min(1%, {ENRICHMENT_FAILURE_MAX})"
                )
                return False
            self.logger.info(f"Successfully processed {len(results)} CVEs")
            return True
        except Exception as e:
            self.logger.error(f"Pipeline processing failed: {e}")
            return False

def main():
    """Main entry point"""
    processor = CVEProcessor()
    
    input_file = sys.argv[1] if len(sys.argv) > 1 else None
    success = processor.process_file(input_file)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
