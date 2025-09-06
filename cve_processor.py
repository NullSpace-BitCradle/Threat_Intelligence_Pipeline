#!/usr/bin/env python3
"""
Unified CVE processing pipeline
Combines all CVE processing steps into a single, efficient class
"""
import json
import sys
import requests  # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm  # type: ignore
from typing import Dict, Any, List, Optional
from pathlib import Path

from config import get_config
from database_optimizer import get_database_optimizer, get_jsonl_manager
from performance_optimizer import (
    OptimizedThreadPool, performance_timer, get_performance_monitor,
    BatchProcessor, get_global_cache, optimize_data_structures
)
from error_handler import (
    error_handler, log_operation, ProcessingError, DatabaseError,
    get_logger
)
from error_recovery import (
    with_recovery, with_retry, RetryConfig, RetryStrategy,
    create_data_context
)
from validation import (
    validate_cve_data, validate_cwe_id, validate_capec_id,
    safe_parse_capec_techniques, logger
)

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
    
    def retrieve_cves_from_nvd(self, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict]:
        """Retrieve CVEs from NVD API"""
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
            
            all_cves = []
            start_index = 0
            
            self.logger.info("Retrieving CVEs from NVD API...")
            
            while True:
                params['startIndex'] = start_index
                response = requests.get(base_url, headers=headers, params=params, 
                                     timeout=self.config.get('api.nvd.timeout', 30))
                response.raise_for_status()
                
                data = response.json()
                cves = data.get('vulnerabilities', [])
                
                if not cves:
                    break
                    
                all_cves.extend(cves)
                start_index += len(cves)
                
                self.logger.info(f"Retrieved {len(cves)} CVEs (total: {len(all_cves)})")
                
                if len(cves) < params['resultsPerPage']:
                    break
            
            self.logger.info(f"Total CVEs retrieved: {len(all_cves)}")
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
                
                # Extract CWE IDs from descriptions
                cwe_ids = []
                descriptions = cve_data.get('cve', {}).get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        desc_text = desc.get('value', '')
                        # Look for CWE patterns in description
                        import re
                        cwe_matches = re.findall(r'CWE-(\d+)', desc_text)
                        cwe_ids.extend([f"CWE-{match}" for match in cwe_matches])
                
                # Remove duplicates
                cwe_ids = list(set(cwe_ids))
                
                processed_cves[cve_id] = {
                    'CWE': cwe_ids,
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
    
    def get_defend_techniques(self, technique_id: str) -> List[str]:
        """Get D3FEND techniques for a MITRE technique"""
        # This would integrate with the D3FEND API
        # For now, return empty list
        return []
    
    @log_operation("process_cve_pipeline", "cve_processing")
    def process_cve_pipeline(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single CVE through the entire pipeline"""
        result = {}
        
        for cve_id, data in cve_data.items():
            try:
                # Step 1: Process CWE relationships
                cwe_list = set(data.get('CWE', []))
                for cwe in data.get('CWE', []):
                    cwe_list.add(cwe)
                    parent_cwes = self.get_parent_cwe(cwe)
                    if parent_cwes:
                        cwe_list.update(parent_cwes)
                
                result[cve_id] = {"CWE": list(sorted(cwe_list))}
                
                # Step 2: Get CAPEC entries
                capec_list = set()
                for cwe in cwe_list:
                    capecs = self.fetch_capec_for_cwe(cwe)
                    capec_list.update(capecs)
                
                result[cve_id]["CAPEC"] = list(sorted(capec_list))
                
                # Step 3: Get techniques
                techniques_list = set()
                for capec in capec_list:
                    techniques = self.get_techniques_for_capec(capec)
                    techniques_list.update(techniques)
                
                result[cve_id]["TECHNIQUES"] = list(sorted(techniques_list))
                
                # Step 4: Get D3FEND techniques
                defend_list = set()
                for technique in techniques_list:
                    defend_techniques = self.get_defend_techniques(technique)
                    defend_list.update(defend_techniques)
                
                result[cve_id]["DEFEND"] = list(sorted(defend_list))
                
            except Exception as e:
                self.logger.error(f"Error processing CVE {cve_id}: {e}")
                # Return partial result
                result[cve_id] = {
                    "CWE": data.get('CWE', []),
                    "CAPEC": [],
                    "TECHNIQUES": [],
                    "DEFEND": []
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
