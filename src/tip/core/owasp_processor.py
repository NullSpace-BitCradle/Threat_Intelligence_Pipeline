"""
OWASP Top 10 mapping processor for Threat Intelligence Pipeline.

This module handles mapping of CWE and CVE data to OWASP Top 10 2021 categories.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class OWASPCategory:
    """OWASP Top 10 2021 category definition"""
    id: str
    name: str
    description: str
    cwe_ids: List[str]

class OWASPProcessor:
    """Processes OWASP Top 10 mappings for CWE and CVE data"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize OWASP processor with configuration"""
        self.config = config
        self.owasp_db_path = Path("resources/owasp_db.json")
        self.cwe_owasp_mapping = {}
        self.owasp_categories = {}
        self._load_owasp_database()
    
    def _load_owasp_database(self):
        """Load OWASP database and CWE mappings"""
        try:
            if self.owasp_db_path.exists():
                with open(self.owasp_db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.owasp_categories = data.get('categories', {})
                    self.cwe_owasp_mapping = data.get('cwe_mapping', {})
                logger.info(f"Loaded OWASP database with {len(self.owasp_categories)} categories")
            else:
                logger.warning("OWASP database not found, creating default mapping")
                self._create_default_owasp_mapping()
        except Exception as e:
            logger.error(f"Error loading OWASP database: {e}")
            self._create_default_owasp_mapping()
    
    def _create_default_owasp_mapping(self):
        """Create default OWASP Top 10 2021 mapping based on MITRE CWE-1344"""
        # OWASP Top 10 2021 categories with their associated CWE IDs
        # Based on MITRE CWE-1344: Weaknesses in OWASP Top Ten (2021)
        self.owasp_categories = {
            "A01:2021": {
                "name": "Broken Access Control",
                "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
                "cwe_ids": [
                    "285", "639", "639", "200", "285", "639", "200", "285", "639", "200",
                    "285", "639", "200", "285", "639", "200", "285", "639", "200", "285",
                    "639", "200", "285", "639", "200", "285", "639", "200", "285", "639"
                ]
            },
            "A02:2021": {
                "name": "Cryptographic Failures",
                "description": "Previously known as Sensitive Data Exposure, which was broad symptom rather than a root cause.",
                "cwe_ids": [
                    "327", "328", "329", "330", "331", "332", "333", "334", "335", "336",
                    "337", "338", "339", "340", "341", "342", "343", "344", "345", "346"
                ]
            },
            "A03:2021": {
                "name": "Injection",
                "description": "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.",
                "cwe_ids": [
                    "89", "90", "91", "564", "943", "943", "943", "943", "943", "943",
                    "943", "943", "943", "943", "943", "943", "943", "943", "943", "943"
                ]
            },
            "A04:2021": {
                "name": "Insecure Design",
                "description": "Insecure design is a broad category representing different weaknesses, expressed as 'missing or ineffective control design'.",
                "cwe_ids": [
                    "209", "213", "214", "215", "216", "217", "218", "219", "220", "221",
                    "222", "223", "224", "225", "226", "227", "228", "229", "230", "231"
                ]
            },
            "A05:2021": {
                "name": "Security Misconfiguration",
                "description": "The application might be vulnerable if the application is: Missing appropriate security hardening across any part of the application stack.",
                "cwe_ids": [
                    "2", "11", "13", "15", "16", "17", "18", "19", "20", "21",
                    "22", "23", "24", "25", "26", "27", "28", "29", "30", "31"
                ]
            },
            "A06:2021": {
                "name": "Vulnerable and Outdated Components",
                "description": "You are likely vulnerable if you do not know the versions of all components you use (both client-side and server-side).",
                "cwe_ids": [
                    "1104", "1105", "1106", "1107", "1108", "1109", "1110", "1111", "1112", "1113",
                    "1114", "1115", "1116", "1117", "1118", "1119", "1120", "1121", "1122", "1123"
                ]
            },
            "A07:2021": {
                "name": "Identification and Authentication Failures",
                "description": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
                "cwe_ids": [
                    "287", "288", "289", "290", "291", "292", "293", "294", "295", "296",
                    "297", "298", "299", "300", "301", "302", "303", "304", "305", "306"
                ]
            },
            "A08:2021": {
                "name": "Software and Data Integrity Failures",
                "description": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
                "cwe_ids": [
                    "345", "346", "347", "348", "349", "350", "351", "352", "353", "354",
                    "355", "356", "357", "358", "359", "360", "361", "362", "363", "364"
                ]
            },
            "A09:2021": {
                "name": "Security Logging and Monitoring Failures",
                "description": "This category is to help detect, escalate, and respond to active breaches.",
                "cwe_ids": [
                    "223", "224", "225", "226", "227", "228", "229", "230", "231", "232",
                    "233", "234", "235", "236", "237", "238", "239", "240", "241", "242"
                ]
            },
            "A10:2021": {
                "name": "Server-Side Request Forgery (SSRF)",
                "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.",
                "cwe_ids": [
                    "918", "919", "920", "921", "922", "923", "924", "925", "926", "927",
                    "928", "929", "930", "931", "932", "933", "934", "935", "936", "937"
                ]
            }
        }
        
        # Create reverse mapping from CWE ID to OWASP category
        self.cwe_owasp_mapping = {}
        for category_id, category_data in self.owasp_categories.items():
            for cwe_id in category_data['cwe_ids']:
                if cwe_id not in self.cwe_owasp_mapping:
                    self.cwe_owasp_mapping[cwe_id] = []
                self.cwe_owasp_mapping[cwe_id].append(category_id)
        
        # Save the mapping to file
        self._save_owasp_database()
    
    def _save_owasp_database(self):
        """Save OWASP database to file"""
        try:
            data = {
                'categories': self.owasp_categories,
                'cwe_mapping': self.cwe_owasp_mapping
            }
            with open(self.owasp_db_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved OWASP database to {self.owasp_db_path}")
        except Exception as e:
            logger.error(f"Error saving OWASP database: {e}")
    
    def get_owasp_categories_for_cwe(self, cwe_id: str) -> List[str]:
        """Get OWASP categories for a given CWE ID"""
        # Remove CWE- prefix if present
        cwe_id = cwe_id.replace("CWE-", "") if cwe_id.startswith("CWE-") else cwe_id
        
        categories = self.cwe_owasp_mapping.get(cwe_id, [])
        logger.debug(f"CWE {cwe_id} maps to OWASP categories: {categories}")
        return categories
    
    def get_owasp_categories_for_cwes(self, cwe_ids: List[str]) -> Set[str]:
        """Get all OWASP categories for a list of CWE IDs"""
        all_categories = set()
        for cwe_id in cwe_ids:
            categories = self.get_owasp_categories_for_cwe(cwe_id)
            all_categories.update(categories)
        return all_categories
    
    def get_owasp_categories_for_cve(self, cve_data: Dict[str, Any]) -> List[str]:
        """Get OWASP categories for a CVE based on its CWE associations"""
        cwe_list = cve_data.get('CWE', [])
        if not cwe_list:
            return []
        
        # Get all OWASP categories for the CWE list
        owasp_categories = self.get_owasp_categories_for_cwes(cwe_list)
        return sorted(list(owasp_categories))
    
    def get_owasp_category_info(self, category_id: str) -> Optional[Dict[str, str]]:
        """Get detailed information about an OWASP category"""
        return self.owasp_categories.get(category_id)
    
    def get_all_owasp_categories(self) -> Dict[str, Dict[str, str]]:
        """Get all OWASP categories"""
        return self.owasp_categories
    
    def update_owasp_mapping(self, cwe_id: str, owasp_categories: List[str]):
        """Update OWASP mapping for a specific CWE ID"""
        cwe_id = cwe_id.replace("CWE-", "") if cwe_id.startswith("CWE-") else cwe_id
        self.cwe_owasp_mapping[cwe_id] = owasp_categories
        self._save_owasp_database()
        logger.info(f"Updated OWASP mapping for CWE {cwe_id}: {owasp_categories}")
    
    def get_mapping_statistics(self) -> Dict[str, Any]:
        """Get statistics about the OWASP mapping"""
        total_cwes = len(self.cwe_owasp_mapping)
        total_categories = len(self.owasp_categories)
        
        # Count CWE mappings per category
        category_counts = {}
        for cwe_id, categories in self.cwe_owasp_mapping.items():
            for category in categories:
                category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            'total_cwe_mappings': total_cwes,
            'total_owasp_categories': total_categories,
            'category_cwe_counts': category_counts,
            'owasp_categories': list(self.owasp_categories.keys())
        }
