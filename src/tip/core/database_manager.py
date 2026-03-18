#!/usr/bin/env python3
"""
Unified database management system
Combines all database update operations into a single, efficient manager
"""
import os
import requests  # type: ignore
import json
import csv
import logging
import time
from zipfile import ZipFile
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd  # type: ignore
from datetime import datetime

from tip.utils.config import get_config
from tip.database.database_optimizer import get_database_optimizer
from tip.utils.performance_optimizer import performance_timer, get_performance_monitor
from tip.utils.error_handler import (
    log_operation, APIError, NetworkError, FileOperationError,
    get_logger
)
from tip.utils.error_recovery import with_recovery, create_api_context
from tip.utils.validation import validate_file_exists, logger
from tip.core.kev_processor import KEVProcessor
from tip.core.vulnrichment_processor import VulnrichmentProcessor
from tip.core.apt_processor import APTProcessor

config = get_config()
config.setup_logging()

class DatabaseManager:
    """Unified database management for all Threat Intelligence Pipeline databases"""
    
    def __init__(self):
        self.config = config
        self.logger = get_logger('database_manager')
        
        # Database configurations
        self.databases = {
            'capec': {
                'url': config.get('database.capec.url'),
                'file': config.get_database_path('capec'),
                'processor': self._process_capec_data
            },
            'cwe': {
                'url': config.get('database.cwe.url'),
                'file': config.get_database_path('cwe'),
                'processor': self._process_cwe_data
            },
            'techniques': {
                'enterprise': {
                    'url': config.get('database.techniques.enterprise.url'),
                    'column': config.get('database.techniques.enterprise.column', 9)
                },
                'mobile': {
                    'url': config.get('database.techniques.mobile.url'),
                    'column': config.get('database.techniques.mobile.column', 10)
                },
                'ics': {
                    'url': config.get('database.techniques.ics.url'),
                    'column': config.get('database.techniques.ics.column', 9)
                },
                'file': config.get_database_path('techniques'),
                'processor': self._process_techniques_data
            },
            'defend': {
                'file': config.get_database_path('defend'),
                'processor': self._process_defend_data
            },
            'kev': {
                'url': config.get('database.kev.url'),
                'file': config.get_database_path('kev'),
                'processor': self._update_kev_database
            },
            'vulnrichment': {
                'file': config.get_database_path('vulnrichment'),
                'processor': self._update_vulnrichment_database
            },
            'groups': {
                'url': config.get('database.groups.url'),
                'file': config.get_database_path('groups'),
                'processor': self._update_groups_database
            }
        }
    
    @performance_timer("download_file")
    @with_recovery("download_file", recovery_strategy="api")
    def _download_file(self, url: str, filename: str) -> bool:
        """Download a file with error handling"""
        context = create_api_context("download_database", url)
        
        try:
            self.logger.info(f"Downloading {filename} from {url}")
            timeout = config.get('api.nvd.timeout', 60)
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            
            with open(filename, 'wb') as f:
                f.write(response.content)
            
            self.logger.info(f"Successfully downloaded {filename}")
            return True
            
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Failed to download {filename}: {e}", url=url, context=context)
        except Exception as e:
            raise FileOperationError(f"Error saving {filename}: {e}", file_path=filename, context=context)
    
    @log_operation("process_capec", "database_update")
    def _process_capec_data(self, zip_file: str) -> Dict[str, Any]:
        """Process CAPEC CSV data"""
        try:
            # Extract CSV from zip
            with ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall()
            
            csv_file = "1000.csv"
            if not validate_file_exists(csv_file):
                raise FileOperationError("CAPEC CSV file not found after extraction")
            
            # Process CSV data
            capec_data = {}
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        capec_id = row.get("'ID", "")
                        name = row.get("Name", "")
                        techniques = row.get("Taxonomy Mappings", "")
                        
                        if not capec_id:
                            self.logger.warning("CAPEC entry missing ID, skipping")
                            continue
                        
                        capec_data[capec_id] = {
                            "name": name,
                            "techniques": techniques
                        }
                    except Exception as e:
                        self.logger.warning(f"Error processing CAPEC entry: {e}")
                        continue
            
            # Clean up
            os.remove(csv_file)
            os.remove(zip_file)
            
            self.logger.info(f"Processed {len(capec_data)} CAPEC entries")
            return capec_data
            
        except Exception as e:
            self.logger.error(f"Error processing CAPEC data: {e}")
            raise
    
    @log_operation("process_cwe", "database_update")
    def _process_cwe_data(self, zip_file: str) -> Dict[str, Any]:
        """Process CWE XML data"""
        try:
            import xml.etree.ElementTree as ET
            
            # Extract XML from zip
            with ZipFile(zip_file, 'r') as zip_ref:
                # List files in the zip to find the actual XML filename
                file_list = zip_ref.namelist()
                xml_files = [f for f in file_list if f.endswith('.xml')]
                
                if not xml_files:
                    raise FileOperationError("No XML file found in CWE zip")
                
                # Extract the first XML file found
                xml_file = xml_files[0]
                zip_ref.extract(xml_file)
            
            if not validate_file_exists(xml_file):
                raise FileOperationError("CWE XML file not found after extraction")
            
            # Process XML data
            cwe_data: Dict[str, Any] = {}
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Parse CWE entries
            for weakness in root.findall('.//{http://cwe.mitre.org/cwe-7}Weakness'):
                cwe_id = weakness.get('ID')
                if cwe_id:
                    # Extract name
                    name_elem = weakness.find('.//{http://cwe.mitre.org/cwe-7}Name')
                    name = name_elem.text if name_elem is not None else ''
                    
                    # Extract description
                    desc_elem = weakness.find('.//{http://cwe.mitre.org/cwe-7}Description')
                    description = desc_elem.text if desc_elem is not None else ''
                    
                    # Extract parent relationships
                    child_of = []
                    for rel in weakness.findall('.//{http://cwe.mitre.org/cwe-7}ChildOf/{http://cwe.mitre.org/cwe-7}Weakness'):
                        parent_id = rel.get('CWE_ID')
                        if parent_id:
                            child_of.append(parent_id)
                    
                    # Extract related attack patterns
                    related_capecs = []
                    for rel in weakness.findall('.//{http://cwe.mitre.org/cwe-7}Related_Attack_Patterns/{http://cwe.mitre.org/cwe-7}Related_Attack_Pattern'):
                        capec_id = rel.get('CAPEC_ID')
                        if capec_id:
                            related_capecs.append(capec_id)
                    
                    cwe_data[cwe_id] = {
                        'name': name,
                        'description': description,
                        'ChildOf': child_of,
                        'RelatedAttackPatterns': related_capecs
                    }
            
            # Clean up
            os.remove(xml_file)
            os.remove(zip_file)
            
            self.logger.info(f"Processed {len(cwe_data)} CWE entries")
            return cwe_data
            
        except Exception as e:
            self.logger.error(f"Error processing CWE data: {e}")
            raise
    
    @log_operation("process_techniques", "database_update")
    def _process_techniques_data(self) -> Dict[str, Any]:
        """Process MITRE ATT&CK techniques data from STIX bundle"""
        try:
            techniques_data = {}

            # Download the enterprise ATT&CK STIX bundle (same source as APT processor)
            stix_url = config.get(
                'database.groups.url',
                'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-16.1.json'
            )

            self.logger.info(f"Downloading ATT&CK STIX bundle for techniques...")
            timeout = config.get('api.nvd.timeout', 120)
            response = requests.get(stix_url, timeout=timeout)
            response.raise_for_status()
            stix_data = response.json()

            for obj in stix_data.get('objects', []):
                if obj.get('type') != 'attack-pattern':
                    continue
                if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue

                # Extract technique ID from external references
                technique_id = ''
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id', '')
                        break

                if not technique_id:
                    continue

                # Strip the 'T' prefix for the lookup key (existing code expects numeric IDs)
                key = technique_id[1:] if technique_id.startswith('T') else technique_id

                # Determine framework from x_mitre_domains
                domains = obj.get('x_mitre_domains', [])
                framework = 'enterprise'
                if 'mobile-attack' in domains:
                    framework = 'mobile'
                elif 'ics-attack' in domains:
                    framework = 'ics'

                techniques_data[key] = {
                    'framework': framework,
                    'name': obj.get('name', ''),
                    'description': obj.get('description', '')[:200] if obj.get('description') else ''
                }

            self.logger.info(f"Processed {len(techniques_data)} technique entries from STIX")
            return techniques_data

        except Exception as e:
            self.logger.error(f"Error processing techniques data: {e}")
            raise
    
    @log_operation("process_defend", "database_update")
    def _process_defend_data(self) -> Dict[str, Any]:
        """
        Process D3FEND data by querying the D3FEND API for defensive techniques
        that counter ATT&CK techniques.
        """
        try:
            defend_data: Dict[str, Any] = {}
            
            # Check if D3FEND is enabled in config
            if not config.get('api.d3fend.enabled', True):
                self.logger.info("D3FEND integration is disabled in config")
                return defend_data
            
            # Load the techniques database to get ATT&CK technique IDs
            techniques_file = config.get_database_path('techniques')
            if not os.path.exists(techniques_file):
                self.logger.warning("Techniques database not found, skipping D3FEND update")
                return defend_data
            
            with open(techniques_file, 'r') as f:
                techniques_db = json.load(f)
            
            d3fend_base_url = config.get('api.d3fend.base_url')
            timeout = config.get('api.d3fend.timeout', 30)
            
            self.logger.info(f"Fetching D3FEND countermeasures for {len(techniques_db)} techniques...")
            
            # Process each technique to find D3FEND countermeasures
            processed_count = 0
            error_count = 0
            
            for technique_id in techniques_db.keys():
                try:
                    # Normalize technique ID format (e.g., "1059" -> "T1059")
                    attack_id = technique_id if technique_id.startswith('T') else f"T{technique_id}"
                    
                    # Query D3FEND API (requires .json extension)
                    url = f"{d3fend_base_url}{attack_id}.json"
                    response = requests.get(url, timeout=timeout)
                    
                    if response.status_code == 200:
                        d3fend_response = response.json()
                        
                        # Extract defensive techniques from the response
                        defensive_techniques = self._extract_d3fend_techniques(d3fend_response)
                        
                        if defensive_techniques:
                            defend_data[attack_id] = {
                                'attack_technique': attack_id,
                                'defensive_techniques': defensive_techniques
                            }
                            processed_count += 1
                    
                    elif response.status_code == 404:
                        # No D3FEND data for this technique - this is expected for some
                        pass
                    else:
                        self.logger.debug(f"D3FEND API returned {response.status_code} for {attack_id}")
                    
                    # Rate limiting - be respectful to the API
                    time.sleep(0.1)
                    
                except requests.exceptions.RequestException as e:
                    error_count += 1
                    self.logger.debug(f"Error fetching D3FEND data for {technique_id}: {e}")
                    continue
                except Exception as e:
                    error_count += 1
                    self.logger.warning(f"Unexpected error processing {technique_id}: {e}")
                    continue
            
            self.logger.info(f"D3FEND processing complete: {processed_count} techniques with countermeasures, {error_count} errors")
            return defend_data
            
        except Exception as e:
            self.logger.error(f"Error processing D3FEND data: {e}")
            raise
    
    def _extract_d3fend_techniques(self, d3fend_response: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract defensive technique information from D3FEND API response"""
        defensive_techniques = []
        
        try:
            # D3FEND API returns data in a specific format
            # Navigate the response structure to find defensive techniques
            # D3FEND API response nests data under off_to_def
            off_to_def = d3fend_response.get('off_to_def', d3fend_response)
            bindings = off_to_def.get('results', {}).get('bindings', [])
            
            for binding in bindings:
                technique_info = {}
                
                # Extract defensive technique ID
                if 'def_tech' in binding:
                    def_tech_uri = binding['def_tech'].get('value', '')
                    # Extract ID from URI (e.g., "http://d3fend.mitre.org/ontologies/d3fend.owl#UserAccountManagement")
                    if '#' in def_tech_uri:
                        technique_info['id'] = def_tech_uri.split('#')[-1]
                
                # Extract technique label/name
                if 'def_tech_label' in binding:
                    technique_info['name'] = binding['def_tech_label'].get('value', '')
                
                # Extract definition if available
                if 'def_artifact_rel_label' in binding:
                    technique_info['relationship'] = binding['def_artifact_rel_label'].get('value', '')
                
                if technique_info.get('id'):
                    defensive_techniques.append(technique_info)
            
            # Remove duplicates based on ID
            seen_ids = set()
            unique_techniques = []
            for tech in defensive_techniques:
                if tech['id'] not in seen_ids:
                    seen_ids.add(tech['id'])
                    unique_techniques.append(tech)
            
            return unique_techniques
            
        except Exception as e:
            self.logger.debug(f"Error extracting D3FEND techniques: {e}")
            return []
    
    def _update_kev_database(self) -> Dict[str, Any]:
        """Download and process CISA KEV data"""
        kev_processor = KEVProcessor()
        raw_data = kev_processor.download()
        return kev_processor._process_kev_data(raw_data)

    def _update_vulnrichment_database(self) -> Dict[str, Any]:
        """Download and process CISA Vulnrichment data"""
        vr_processor = VulnrichmentProcessor()
        vr_processor.update()
        return vr_processor.vulnrichment_db

    def _update_groups_database(self) -> Dict[str, Any]:
        """Download and process ATT&CK Groups STIX data"""
        apt_processor = APTProcessor()
        stix_data = apt_processor.download()
        return apt_processor._process_stix_data(stix_data)

    def _save_database(self, data: Dict[str, Any], file_path: str):
        """Save database data to JSON or JSONL file based on extension"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            with open(file_path, 'w', encoding='utf-8') as f:
                if file_path.endswith('.jsonl'):
                    # JSONL: one JSON object per line (key: value)
                    for key, value in data.items():
                        json.dump({key: value}, f)
                        f.write('\n')
                else:
                    json.dump(data, f, indent=4)

            self.logger.info(f"Saved {len(data)} entries to {file_path}")

        except Exception as e:
            self.logger.error(f"Error saving database to {file_path}: {e}")
            raise
    
    @performance_timer("update_database")
    def update_database(self, db_name: str) -> bool:
        """Update a specific database"""
        if db_name not in self.databases:
            self.logger.error(f"Unknown database: {db_name}")
            return False
        
        db_config = self.databases[db_name]
        
        try:
            if db_name == 'capec':
                # Download and process CAPEC
                zip_file = "capec_data.zip"
                if self._download_file(db_config['url'], zip_file):
                    data = db_config['processor'](zip_file)
                    self._save_database(data, db_config['file'])
                    return True
            
            elif db_name == 'cwe':
                # Download and process CWE
                zip_file = "cwe_data.zip"
                if self._download_file(db_config['url'], zip_file):
                    data = db_config['processor'](zip_file)
                    self._save_database(data, db_config['file'])
                    return True
            
            elif db_name == 'techniques':
                # Process techniques
                data = db_config['processor']()
                self._save_database(data, db_config['file'])
                return True
            
            elif db_name == 'defend':
                # Process D3FEND
                data = db_config['processor']()
                self._save_database(data, db_config['file'])
                return True

            elif db_name == 'kev':
                # Process KEV
                data = db_config['processor']()
                self._save_database(data, db_config['file'])
                return True

            elif db_name == 'vulnrichment':
                # Process Vulnrichment
                data = db_config['processor']()
                self._save_database(data, db_config['file'])
                return True

            elif db_name == 'groups':
                # Process ATT&CK Groups
                data = db_config['processor']()
                self._save_database(data, db_config['file'])
                return True

            return False
            
        except Exception as e:
            self.logger.error(f"Failed to update {db_name} database: {e}")
            return False
    
    @performance_timer("update_all_databases")
    def update_all_databases(self) -> Dict[str, bool]:
        """Update all databases"""
        results = {}
        
        # Update databases in dependency order
        update_order = ['capec', 'cwe', 'techniques', 'defend', 'kev', 'vulnrichment', 'groups']
        
        for db_name in update_order:
            self.logger.info(f"Updating {db_name} database...")
            results[db_name] = self.update_database(db_name)
            
            if not results[db_name]:
                self.logger.error(f"Failed to update {db_name} database")
                # Continue with other databases
        
        return results
    
    def get_database_status(self) -> Dict[str, Any]:
        """Get status of all databases"""
        status = {}
        
        for db_name, config in self.databases.items():
            if db_name == 'techniques':
                # Handle techniques special case
                file_path = config['file']
            else:
                file_path = config['file']
            
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    status[db_name] = {
                        'exists': True,
                        'entries': len(data),
                        'last_modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                    }
                except Exception as e:
                    status[db_name] = {
                        'exists': True,
                        'error': str(e)
                    }
            else:
                status[db_name] = {
                    'exists': False
                }
        
        return status

def main():
    """Main entry point for database updates"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Update Threat Intelligence Pipeline databases')
    parser.add_argument('--database', '-d', choices=['capec', 'cwe', 'techniques', 'defend', 'all'],
                       default='all', help='Database to update')
    parser.add_argument('--status', '-s', action='store_true',
                       help='Show database status')
    
    args = parser.parse_args()
    
    manager = DatabaseManager()
    
    if args.status:
        status = manager.get_database_status()
        print(json.dumps(status, indent=2))
        return
    
    if args.database == 'all':
        results = manager.update_all_databases()
        print(f"Database update results: {results}")
    else:
        success = manager.update_database(args.database)
        print(f"Database {args.database} update: {'Success' if success else 'Failed'}")

if __name__ == "__main__":
    main()
