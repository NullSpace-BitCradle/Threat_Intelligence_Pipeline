"""
Validation utilities for Threat Intelligence Pipeline
"""
import logging
from typing import List, Any

logger = logging.getLogger(__name__)

def validate_cve_data(cve_data: Any) -> bool:
    """
    Validate CVE data structure
    
    Args:
        cve_data: Dictionary containing CVE data
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not isinstance(cve_data, dict):
        logger.error("CVE data must be a dictionary")
        return False
    
    required_keys = ['CWE', 'CAPEC', 'TECHNIQUES']
    
    for cve_id, data in cve_data.items():
        if not isinstance(cve_id, str) or not cve_id.startswith('CVE-'):
            logger.error(f"Invalid CVE ID format: {cve_id}")
            return False
            
        if not isinstance(data, dict):
            logger.error(f"CVE {cve_id}: data must be a dictionary")
            return False
            
        for key in required_keys:
            if key not in data:
                logger.warning(f"CVE {cve_id}: missing required key '{key}'")
                data[key] = []  # Add missing key with empty list
            elif not isinstance(data[key], list):
                logger.error(f"CVE {cve_id}: '{key}' must be a list")
                return False
    
    return True

def validate_technique_id(technique_id: Any) -> bool:
    """
    Validate MITRE ATT&CK technique ID format
    
    Args:
        technique_id: Technique identifier
        
    Returns:
        bool: True if valid format
    """
    if not isinstance(technique_id, str):
        return False
    
    # Technique IDs follow pattern T#### or T####.###
    # Also accept numeric format like 1574.010 (from CAPEC data)
    if technique_id.startswith('T'):
        remaining = technique_id[1:]
        if '.' in remaining:
            main_part, sub_part = remaining.split('.', 1)
            return main_part.isdigit() and sub_part.isdigit()
        else:
            return remaining.isdigit()
    else:
        # Accept numeric format like 1574.010
        if '.' in technique_id:
            main_part, sub_part = technique_id.split('.', 1)
            return main_part.isdigit() and sub_part.isdigit()
        else:
            return technique_id.isdigit()


def safe_parse_capec_techniques(techniques_string: str) -> List[str]:
    """
    Safely parse CAPEC techniques with validation
    
    Args:
        techniques_string: Raw techniques string from CAPEC data
        
    Returns:
        List of technique IDs
    """
    if not techniques_string or not isinstance(techniques_string, str):
        return []
    
    try:
        # Split by the known pattern
        entries = techniques_string.split("NAME:ATTACK:ENTRY ")[1:]
        techniques = []
        
        for entry in entries:
            parts = entry.split(":")
            if len(parts) > 1:
                technique_id = parts[1]
                if validate_technique_id(technique_id):
                    techniques.append(technique_id)
                else:
                    logger.warning(f"Invalid technique ID format: {technique_id}")
        
        return techniques
    except (IndexError, AttributeError) as e:
        logger.warning(f"Failed to parse techniques from: {techniques_string[:100]}... Error: {e}")
        return []

def validate_file_exists(file_path: str) -> bool:
    """
    Validate that a file exists and is readable
    
    Args:
        file_path: Path to the file
        
    Returns:
        bool: True if file exists and is readable
    """
    import os
    if not os.path.exists(file_path):
        logger.error(f"File does not exist: {file_path}")
        return False
    
    if not os.access(file_path, os.R_OK):
        logger.error(f"File is not readable: {file_path}")
        return False
    
    return True
