#!/usr/bin/env python3
"""
Unified CVE processing pipeline
Combines all CVE processing steps into a single, efficient class
"""
import json
import re
import sys
import time
import requests  # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm  # type: ignore
from typing import Dict, Any, List, Optional
from pathlib import Path

from tip.utils.config import get_config
from tip.database.database_optimizer import get_database_optimizer, get_jsonl_manager
from tip.utils.performance_optimizer import (
    OptimizedThreadPool, performance_timer, get_performance_monitor,
    BatchProcessor, get_global_cache, optimize_data_structures
)
from tip.utils.error_handler import (
    error_handler, log_operation, ProcessingError, DatabaseError,
    get_logger
)
from tip.utils.error_recovery import (
    with_recovery, with_retry, RetryConfig, RetryStrategy,
    create_data_context
)
from tip.utils.validation import (
    validate_cve_data, validate_cwe_id, validate_capec_id,
    safe_parse_capec_techniques, logger
)
from tip.core.owasp_processor import OWASPProcessor
from tip.core.kev_processor import KEVProcessor
from tip.core.vulnrichment_processor import VulnrichmentProcessor
from tip.core.apt_processor import APTProcessor
from tip.utils.rate_limiter import rate_limit, adaptive_rate_limit
from tip.monitoring.metrics import track_api_metrics, track_cve_processing_metrics, record_error
from tip.monitoring.request_tracker import track_request, get_current_request_id

config = get_config()
config.setup_logging()

class CVEProcessor:
    """Unified CVE processing pipeline"""
    
    def __init__(self):
        self.config = config
        self.cache = get_global_cache()
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
    
    @track_api_metrics("nvd", "GET")
    @track_request("retrieve_cves", "cve_processor")
    def retrieve_cves_from_nvd(self, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict]:
        """Retrieve CVEs from NVD API with progress tracking and resume capability"""
        try:
            api_key = self.config.get_api_key('nvd')
            base_url = self.config.get('api.nvd.base_url')
            
            headers = {}
            if api_key:
                headers['apiKey'] = api_key
            
            params = {
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
            all_cves = []
            start_index = 0
            
            # Try to resume from previous progress
            if progress_file.exists():
                try:
                    with open(progress_file, 'r') as f:
                        progress_data = json.load(f)
                        start_index = progress_data.get('last_index', 0)
                        self.logger.info(f"Resuming CVE retrieval from index {start_index}")
                except Exception as e:
                    self.logger.warning(f"Could not load progress file: {e}")
            
            self.logger.info("Retrieving CVEs from NVD API...")
            
            # Adaptive rate limiting variables - use config values
            rate_limit_config = self.config.get('api.nvd.rate_limit', {})
            base_delay = rate_limit_config.get('base_delay', 0.5)
            max_delay = rate_limit_config.get('max_delay', 30.0)
            backoff_multiplier = rate_limit_config.get('backoff_multiplier', 2.5)
            max_retries = rate_limit_config.get('max_retries', 5)
            current_delay = base_delay
            consecutive_429s = 0
            successful_requests = 0
            
            while True:
                params['startIndex'] = start_index
                
                # Adaptive retry logic for 429 errors
                retry_delay = current_delay
                
                for attempt in range(max_retries):
                    try:
                        response = requests.get(base_url, headers=headers, params=params, 
                                             timeout=self.config.get('api.nvd.timeout', 30))
                        
                        if response.status_code == 429:
                            consecutive_429s += 1
                            if attempt < max_retries - 1:
                                # Exponential backoff with jitter
                                jitter = time.time() % 1.0  # Add some randomness
                                actual_delay = retry_delay + jitter
                                
                                self.logger.warning(f"Rate limited (429), waiting {actual_delay:.2f}s before retry {attempt + 1}/{max_retries}")
                                time.sleep(actual_delay)
                                retry_delay *= backoff_multiplier
                                continue
                            else:
                                self.logger.error("Rate limited, max retries exceeded")
                                break
                        
                        # Success - reset counters and adjust delay
                        consecutive_429s = 0
                        successful_requests += 1
                        
                        # Gradually increase delay if we've been getting 429s recently
                        if successful_requests > 0 and successful_requests % 10 == 0:
                            current_delay = min(current_delay * 1.1, max_delay)
                        
                        response.raise_for_status()
                        break
                        
                    except requests.exceptions.RequestException as e:
                        if attempt < max_retries - 1:
                            self.logger.warning(f"Request failed: {e}, retrying in {retry_delay:.2f}s")
                            time.sleep(retry_delay)
                            retry_delay *= 2
                        else:
                            raise
                
                if response.status_code == 429:
                    # If we get too many consecutive 429s, increase base delay significantly
                    if consecutive_429s >= 3:
                        current_delay = min(current_delay * 2, max_delay)
                        self.logger.warning(f"Too many consecutive 429s, increasing delay to {current_delay:.2f}s")
                        consecutive_429s = 0
                    
                    self.logger.error("Rate limited, stopping CVE retrieval")
                    break
                
                data = response.json()
                cves = data.get('vulnerabilities', [])
                
                if not cves:
                    break
                    
                all_cves.extend(cves)
                start_index += len(cves)
                
                # Progress reporting and saving
                if len(all_cves) % log_interval == 0 or len(cves) < params['resultsPerPage']:
                    self.logger.info(f"Retrieved {len(cves)} CVEs (total: {len(all_cves)}) - Current delay: {current_delay:.2f}s")
                
                # Save progress at configured interval
                if len(all_cves) % save_interval == 0:
                    progress_data = {
                        'last_index': start_index,
                        'total_retrieved': len(all_cves),
                        'current_delay': current_delay,
                        'timestamp': time.time()
                    }
                    try:
                        with open(progress_file, 'w') as f:
                            json.dump(progress_data, f)
                    except Exception as e:
                        self.logger.warning(f"Could not save progress: {e}")
                
                if len(cves) < params['resultsPerPage']:
                    break
                
                # Adaptive delay between requests
                time.sleep(current_delay)
            
            self.logger.info(f"Total CVEs retrieved: {len(all_cves)}")
            
            # Clean up progress file on successful completion
            if progress_file.exists():
                try:
                    progress_file.unlink()
                    self.logger.info("Progress file cleaned up")
                except Exception as e:
                    self.logger.warning(f"Could not clean up progress file: {e}")
            
            return all_cves
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve CVEs from NVD: {e}")
            return []
    
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
                
                processed_cves[cve_id] = {
                    'CWE': unique_cwe_ids,
                    'CAPEC': [],
                    'TECHNIQUES': [],
                    'DEFEND': []
                }
                
            except Exception as e:
                self.logger.warning(f"Error processing CVE {cve_id}: {e}")
                continue
        
        return processed_cves
    
    def _load_cwe_db(self) -> Dict[str, Any]:
        """Load CWE database"""
        try:
            with open(self.cwe_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load CWE database: {e}")
            return {}
    
    def _load_capec_db(self) -> Dict[str, Any]:
        """Load CAPEC database"""
        try:
            with open(self.capec_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load CAPEC database: {e}")
            return {}
    
    def _load_techniques_db(self) -> Dict[str, Any]:
        """Load techniques database"""
        try:
            with open(self.techniques_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load techniques database: {e}")
            return {}
    
    @performance_timer("get_parent_cwe")
    def get_parent_cwe(self, cwe: str) -> Optional[List[str]]:
        """Get parent CWE relationships with caching"""
        cache_key = f"parent_cwe_{cwe}"
        
        # Check cache first
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        cwe_list = set()
        try:
            # Handle both CWE-XXX and XXX formats
            if cwe.startswith("CWE-"):
                cwe_key = cwe
                result = self.cwe_db.get(cwe_key, {})
                if not result:
                    cwe_key = cwe[4:]  # Remove "CWE-" prefix
                    result = self.cwe_db.get(cwe_key, {})
            else:
                cwe_key = cwe
                result = self.cwe_db.get(cwe_key, {})
            
            if result.get("ChildOf", []):
                for related_cwe in result["ChildOf"]:
                    cwe_list.add(related_cwe)
                result = list(cwe_list)
            else:
                result = None
            
            # Cache the result
            self.cache.set(cache_key, result, ttl=3600)
            return result
        except Exception as e:
            self.logger.warning(f"Exception occurred for {cwe}: {e}")
        return None
    
    def fetch_capec_for_cwe(self, cwe: str) -> List[str]:
        """Fetch CAPEC entries for a CWE"""
        try:
            result = self.cwe_db.get(cwe, {})
            capec_list = result.get("RelatedAttackPatterns", [])
            return capec_list if capec_list else []
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
            return cached_result
        
        try:
            # Normalize technique ID
            attack_id = technique_id if technique_id.startswith('T') else f"T{technique_id}"
            
            # Try to load from JSONL file first
            if Path(defend_file).exists():
                for entry in self.jsonl_manager.read_jsonl(defend_file):
                    if attack_id in entry:
                        result = entry[attack_id].get('defensive_techniques', [])
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
    @track_cve_processing_metrics("process_cve_pipeline")
    @track_request("process_cve_pipeline", "cve_processor")
    def process_cve_pipeline(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single CVE through the entire pipeline"""
        result = {}
        
        for cve_id, data in cve_data.items():
            try:
                # Step 1: Process CWE relationships
                cwe_list = set(data.get('CWE', []))
                for cwe in data.get('CWE', []):
                    cwe_list.add(cwe)
                    # Extract numeric CWE ID (remove "CWE-" prefix if present)
                    cwe_id = cwe.replace("CWE-", "") if cwe.startswith("CWE-") else cwe
                    parent_cwes = self.get_parent_cwe(cwe_id)
                    if parent_cwes:
                        cwe_list.update(parent_cwes)
                
                result[cve_id] = {"CWE": list(sorted(cwe_list))}
                
                # Step 2: Get CAPEC entries
                capec_list = set()
                for cwe in cwe_list:
                    # Extract numeric CWE ID (remove "CWE-" prefix if present)
                    cwe_id = cwe.replace("CWE-", "") if cwe.startswith("CWE-") else cwe
                    capecs = self.fetch_capec_for_cwe(cwe_id)
                    capec_list.update(capecs)
                
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

                # Step 8: APT Groups reverse lookup from techniques
                if result[cve_id].get("TECHNIQUES"):
                    apt_groups = self.apt_processor.lookup_by_techniques(result[cve_id]["TECHNIQUES"])
                    if apt_groups:
                        result[cve_id]["APT_GROUPS"] = apt_groups

            except Exception as e:
                self.logger.error(f"Error processing CVE {cve_id}: {e}")
                # Return partial result
                result[cve_id] = {
                    "CWE": data.get('CWE', []),
                    "CAPEC": [],
                    "TECHNIQUES": [],
                    "DEFEND": [],
                    "OWASP": []
                }
        
        return result
    
    def save_results(self, results: Dict[str, Any]):
        """Save results to JSONL file and update database"""
        # Save to main output file
        with open(self.cve_file, 'w', encoding='utf-8') as f:
            for cve_id, data in results.items():
                f.write(json.dumps({cve_id: data}) + "\n")
        
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
            self.save_results(results)
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
