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
        self.cwe_owasp_mapping: Dict[str, List[str]] = {}
        self.owasp_categories: Dict[str, Dict[str, Any]] = {}
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
        """Create default OWASP Top 10 2021 mapping based on MITRE CWE-1344 and official OWASP sources"""
        # OWASP Top 10 2021 categories with their associated CWE IDs
        # Combined from MITRE CWE-1344 and OWASP official documentation
        self.owasp_categories = {
            "A01:2021": {
                "name": "Broken Access Control",
                "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
                "cwe_ids": [
                    "22", "23", "35", "59", "200", "201", "219", "264", "275", "276", "284", "285",
                    "352", "359", "377", "402", "425", "441", "497", "538", "540", "548", "552",
                    "566", "601", "639", "651", "668", "706", "732", "766", "770", "774", "862",
                    "863", "913", "922", "1275", "1321", "1220"
                ]
            },
            "A02:2021": {
                "name": "Cryptographic Failures",
                "description": "Previously known as Sensitive Data Exposure, which was broad symptom rather than a root cause.",
                "cwe_ids": [
                    "261", "296", "310", "319", "321", "322", "323", "324", "325", "326", "327",
                    "328", "329", "330", "331", "335", "336", "337", "338", "340", "347", "359",
                    "523", "720", "757", "759", "760", "780", "818", "916"
                ]
            },
            "A03:2021": {
                "name": "Injection",
                "description": "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.",
                "cwe_ids": [
                    "20", "74", "75", "77", "78", "79", "80", "83", "87", "88", "89", "90", "91",
                    "93", "94", "95", "96", "97", "98", "99", "100", "113", "116", "138", "184",
                    "470", "471", "564", "610", "643", "644", "652", "917", "1275", "1287", "1321"
                ]
            },
            "A04:2021": {
                "name": "Insecure Design",
                "description": "Insecure design is a broad category representing different weaknesses, expressed as 'missing or ineffective control design'.",
                "cwe_ids": [
                    "73", "183", "184", "209", "213", "235", "256", "257", "266", "269", "280",
                    "311", "312", "313", "316", "325", "326", "327", "328", "329", "330", "331",
                    "335", "336", "337", "338", "340", "347", "359", "384", "400", "434", "441",
                    "501", "522", "525", "539", "540", "595", "598", "602", "642", "646", "650",
                    "653", "656", "657", "799", "807", "840", "841", "927", "1021", "1173", "1220"
                ]
            },
            "A05:2021": {
                "name": "Security Misconfiguration",
                "description": "The application might be vulnerable if the application is: Missing appropriate security hardening across any part of the application stack.",
                "cwe_ids": [
                    "2", "11", "13", "15", "16", "260", "315", "520", "526", "537", "541", "547",
                    "611", "614", "756", "776", "942", "1004", "1032", "1174", "1177", "1188",
                    "1233", "1236", "1250", "1260", "1262", "1263", "1272", "1275", "1276"
                ]
            },
            "A06:2021": {
                "name": "Vulnerable and Outdated Components",
                "description": "You are likely vulnerable if you do not know the versions of all components you use (both client-side and server-side).",
                "cwe_ids": [
                    "829", "1035", "1104"
                ]
            },
            "A07:2021": {
                "name": "Identification and Authentication Failures",
                "description": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
                "cwe_ids": [
                    "255", "259", "287", "288", "290", "294", "295", "297", "300", "302", "304",
                    "306", "307", "309", "311", "312", "319", "321", "322", "323", "324", "325",
                    "326", "327", "328", "329", "330", "331", "335", "336", "337", "338", "340",
                    "347", "384", "521", "522", "523", "549", "560", "561", "562", "563", "564",
                    "565", "620", "640", "798", "1216", "1244", "1274", "1275", "1295", "1390"
                ]
            },
            "A08:2021": {
                "name": "Software and Data Integrity Failures",
                "description": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
                "cwe_ids": [
                    "345", "353", "426", "494", "502", "565", "784", "829", "830", "912", "915",
                    "1321"
                ]
            },
            "A09:2021": {
                "name": "Security Logging and Monitoring Failures",
                "description": "This category is to help detect, escalate, and respond to active breaches.",
                "cwe_ids": [
                    "117", "223", "224", "225", "319", "532", "533", "534", "537", "538", "539",
                    "540", "541", "778", "779", "780", "862", "863", "1009", "1275", "1295"
                ]
            },
            "A10:2021": {
                "name": "Server-Side Request Forgery (SSRF)",
                "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.",
                "cwe_ids": [
                    "918"
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
        category_counts: Dict[str, int] = {}
        for cwe_id, categories in self.cwe_owasp_mapping.items():
            for category in categories:
                category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            'total_cwe_mappings': total_cwes,
            'total_owasp_categories': total_categories,
            'category_cwe_counts': category_counts,
            'owasp_categories': list(self.owasp_categories.keys())
        }
