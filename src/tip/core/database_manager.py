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
            for weakness in root.findall('.//{http://cwe.mitre.org/cwe-6}Weakness'):
                cwe_id = weakness.get('ID')
                if cwe_id:
                    # Extract name
                    name_elem = weakness.find('.//{http://cwe.mitre.org/cwe-6}Name')
                    name = name_elem.text if name_elem is not None else ''
                    
                    # Extract description
                    desc_elem = weakness.find('.//{http://cwe.mitre.org/cwe-6}Description')
                    description = desc_elem.text if desc_elem is not None else ''
                    
                    # Extract parent relationships
                    child_of = []
                    for rel in weakness.findall('.//{http://cwe.mitre.org/cwe-6}ChildOf/{http://cwe.mitre.org/cwe-6}Weakness'):
                        parent_id = rel.get('CWE_ID')
                        if parent_id:
                            child_of.append(parent_id)
                    
                    # Extract related attack patterns
                    related_capecs = []
                    for rel in weakness.findall('.//{http://cwe.mitre.org/cwe-6}Related_Attack_Patterns/{http://cwe.mitre.org/cwe-6}Related_Attack_Pattern'):
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
        """Process MITRE ATT&CK techniques data"""
        try:
            techniques_data = {}
            
            for framework, config_data in self.databases['techniques'].items():
                if framework == 'file' or framework == 'processor':
                    continue
                
                try:
                    url = config_data['url']
                    column = config_data['column']
                    
                    # Download Excel file
                    excel_file = f"{framework}_techniques.xlsx"
                    if self._download_file(url, excel_file):
                        # Process Excel data
                        df = pd.read_excel(excel_file)
                        
                        for _, row in df.iterrows():
                            technique_id = str(row.iloc[column]) if len(row) > column else ""
                            if technique_id and technique_id != 'nan':
                                techniques_data[technique_id] = {
                                    'framework': framework,
                                    'name': str(row.iloc[1]) if len(row) > 1 else "",
                                    'description': str(row.iloc[2]) if len(row) > 2 else ""
                                }
                        
                        # Clean up
                        os.remove(excel_file)
                        
                except Exception as e:
                    self.logger.warning(f"Error processing {framework} techniques: {e}")
                    continue
            
            self.logger.info(f"Processed {len(techniques_data)} technique entries")
            return techniques_data
            
        except Exception as e:
            self.logger.error(f"Error processing techniques data: {e}")
            raise
    
    @log_operation("process_defend", "database_update")
    def _process_defend_data(self) -> Dict[str, Any]:
        """Process D3FEND data"""
        try:
            # D3FEND processing would go here
            # For now, return empty dict
            defend_data: Dict[str, Any] = {}
            self.logger.info("D3FEND processing not yet implemented")
            return defend_data
            
        except Exception as e:
            self.logger.error(f"Error processing D3FEND data: {e}")
            raise
    
    def _save_database(self, data: Dict[str, Any], file_path: str):
        """Save database data to JSON file"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
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
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to update {db_name} database: {e}")
            return False
    
    @performance_timer("update_all_databases")
    def update_all_databases(self) -> Dict[str, bool]:
        """Update all databases"""
        results = {}
        
        # Update databases in dependency order
        update_order = ['capec', 'cwe', 'techniques', 'defend']
        
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
