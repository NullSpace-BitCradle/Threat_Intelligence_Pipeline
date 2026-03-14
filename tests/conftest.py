"""
Pytest configuration and fixtures for Threat Intelligence Pipeline tests
"""
import pytest
import json
import tempfile
import os
from pathlib import Path
from typing import Dict, Any
import sys

# Add src to path for imports - must be first to avoid tip.py conflict
_src_path = str(Path(__file__).parent.parent / "src")
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)


@pytest.fixture
def sample_cve_data() -> Dict[str, Any]:
    """Sample CVE data for testing"""
    return {
        "CVE-2024-1234": {
            "CWE": ["CWE-79", "CWE-89"],
            "CAPEC": [],
            "TECHNIQUES": [],
            "DEFEND": []
        },
        "CVE-2024-5678": {
            "CWE": ["CWE-22"],
            "CAPEC": [],
            "TECHNIQUES": [],
            "DEFEND": []
        }
    }


@pytest.fixture
def sample_cwe_db() -> Dict[str, Any]:
    """Sample CWE database for testing"""
    return {
        "79": {
            "name": "Improper Neutralization of Input During Web Page Generation",
            "description": "Cross-site Scripting (XSS)",
            "ChildOf": ["74"],
            "RelatedAttackPatterns": ["86", "588"]
        },
        "89": {
            "name": "Improper Neutralization of Special Elements used in an SQL Command",
            "description": "SQL Injection",
            "ChildOf": ["74"],
            "RelatedAttackPatterns": ["66"]
        },
        "22": {
            "name": "Improper Limitation of a Pathname to a Restricted Directory",
            "description": "Path Traversal",
            "ChildOf": ["668"],
            "RelatedAttackPatterns": ["126"]
        },
        "74": {
            "name": "Improper Neutralization of Special Elements in Output Used by a Downstream Component",
            "description": "Injection",
            "ChildOf": [],
            "RelatedAttackPatterns": []
        }
    }


@pytest.fixture
def sample_capec_db() -> Dict[str, Any]:
    """Sample CAPEC database for testing"""
    return {
        "86": {
            "name": "XSS Through HTTP Headers",
            "techniques": "SCOPE:NAME:ATTACK:ENTRY ID:1059:NAME:Command and Scripting Interpreter"
        },
        "66": {
            "name": "SQL Injection",
            "techniques": "SCOPE:NAME:ATTACK:ENTRY ID:1190:NAME:Exploit Public-Facing Application"
        },
        "126": {
            "name": "Path Traversal",
            "techniques": "SCOPE:NAME:ATTACK:ENTRY ID:1083:NAME:File and Directory Discovery"
        }
    }


@pytest.fixture
def sample_owasp_categories() -> Dict[str, Any]:
    """Sample OWASP Top 10 categories for testing"""
    return {
        "A01:2021": {
            "name": "Broken Access Control",
            "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
            "cwe_ids": ["22", "23", "35"]
        },
        "A03:2021": {
            "name": "Injection",
            "description": "Injection flaws occur when untrusted data is sent to an interpreter.",
            "cwe_ids": ["79", "89", "94"]
        }
    }


@pytest.fixture
def temp_config_file(tmp_path) -> Path:
    """Create a temporary config file for testing"""
    config = {
        "api": {
            "nvd": {
                "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0/",
                "api_key_env": "NVD_API_KEY",
                "timeout": 30,
                "retry_limit": 3,
                "results_per_page": 100,
                "rate_limit": {
                    "base_delay": 0.1,
                    "max_delay": 1.0,
                    "backoff_multiplier": 2.0,
                    "max_retries": 3
                }
            },
            "d3fend": {
                "base_url": "https://d3fend.mitre.org/api/offensive-technique/attack/",
                "timeout": 30,
                "enabled": False
            }
        },
        "database": {
            "capec": {"file": str(tmp_path / "capec_db.json")},
            "cwe": {"file": str(tmp_path / "cwe_db.json")},
            "techniques": {"file": str(tmp_path / "techniques_db.json")},
            "defend": {"file": str(tmp_path / "defend_db.jsonl")}
        },
        "processing": {
            "max_threads": 2,
            "batch_size": 100,
            "cache_size": 100,
            "cache_ttl": 60
        },
        "files": {
            "cve_output": str(tmp_path / "cves.jsonl"),
            "last_update": str(tmp_path / "lastUpdate.txt"),
            "database_dir": str(tmp_path / "database"),
            "progress_file": str(tmp_path / "progress.json")
        },
        "progress_tracking": {
            "save_interval": 100,
            "log_interval": 100
        },
        "logging": {
            "level": "WARNING",
            "file": str(tmp_path / "test.log")
        }
    }
    
    config_path = tmp_path / "config.json"
    with open(config_path, 'w') as f:
        json.dump(config, f)
    
    return config_path


@pytest.fixture
def temp_database_files(tmp_path, sample_cwe_db, sample_capec_db) -> Dict[str, Path]:
    """Create temporary database files for testing"""
    # Create resources directory
    resources_dir = tmp_path / "resources"
    resources_dir.mkdir(exist_ok=True)
    
    # Write CWE database
    cwe_path = resources_dir / "cwe_db.json"
    with open(cwe_path, 'w') as f:
        json.dump(sample_cwe_db, f)
    
    # Write CAPEC database
    capec_path = resources_dir / "capec_db.json"
    with open(capec_path, 'w') as f:
        json.dump(sample_capec_db, f)
    
    # Write empty techniques database
    techniques_path = resources_dir / "techniques_db.json"
    with open(techniques_path, 'w') as f:
        json.dump({}, f)
    
    return {
        "cwe": cwe_path,
        "capec": capec_path,
        "techniques": techniques_path,
        "resources_dir": resources_dir
    }


@pytest.fixture
def sample_kev_data() -> Dict[str, Any]:
    """Sample CISA KEV catalog data (raw format from cisagov/kev-data)"""
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.03.14",
        "dateReleased": "2026-03-14T00:00:00.0000Z",
        "count": 3,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "TestVendor",
                "product": "TestProduct",
                "vulnerabilityName": "TestVendor TestProduct SQL Injection",
                "dateAdded": "2024-06-15",
                "shortDescription": "A SQL injection vulnerability exists.",
                "requiredAction": "Apply vendor patch.",
                "dueDate": "2024-07-06",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
                "cwes": ["CWE-89"]
            },
            {
                "cveID": "CVE-2024-9999",
                "vendorProject": "OtherVendor",
                "product": "OtherProduct",
                "vulnerabilityName": "OtherVendor RCE",
                "dateAdded": "2024-08-01",
                "shortDescription": "Remote code execution.",
                "requiredAction": "Apply update.",
                "dueDate": "2024-08-22",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": ""
            },
            {
                "cveID": "CVE-2024-5678",
                "vendorProject": "AcmeCorp",
                "product": "WebServer",
                "vulnerabilityName": "AcmeCorp Path Traversal",
                "dateAdded": "2024-09-10",
                "shortDescription": "Path traversal vulnerability.",
                "requiredAction": "Upgrade to latest version.",
                "dueDate": "2024-10-01",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": ""
            }
        ]
    }


@pytest.fixture
def sample_kev_db() -> Dict[str, Any]:
    """Sample KEV database indexed by CVE ID (processed format, matches sample_kev_data)"""
    return {
        "CVE-2024-1234": {
            "inKEV": True,
            "dateAdded": "2024-06-15",
            "dueDate": "2024-07-06",
            "knownRansomwareCampaignUse": "Known",
            "requiredAction": "Apply vendor patch.",
            "vendorProject": "TestVendor",
            "product": "TestProduct"
        },
        "CVE-2024-9999": {
            "inKEV": True,
            "dateAdded": "2024-08-01",
            "dueDate": "2024-08-22",
            "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "Apply update.",
            "vendorProject": "OtherVendor",
            "product": "OtherProduct"
        },
        "CVE-2024-5678": {
            "inKEV": True,
            "dateAdded": "2024-09-10",
            "dueDate": "2024-10-01",
            "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "Upgrade to latest version.",
            "vendorProject": "AcmeCorp",
            "product": "WebServer"
        }
    }


@pytest.fixture
def sample_vulnrichment_cve() -> Dict[str, Any]:
    """Sample Vulnrichment per-CVE JSON (simplified from cisagov/vulnrichment format)"""
    return {
        "containers": {
            "adp": [
                {
                    "providerMetadata": {
                        "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0"
                    },
                    "title": "CISA ADP Vulnrichment",
                    "metrics": [
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {
                                    "id": "CVE-2024-1234",
                                    "options": [
                                        {"Exploitation": "active"},
                                        {"Automatable": "yes"},
                                        {"Technical Impact": "total"}
                                    ]
                                }
                            }
                        },
                        {
                            "cvssV3_1": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            ]
        }
    }


@pytest.fixture
def sample_vulnrichment_db() -> Dict[str, Any]:
    """Sample Vulnrichment database indexed by CVE ID (processed format)"""
    return {
        "CVE-2024-1234": {
            "ssvcExploitStatus": "active",
            "ssvcAutomatable": "yes",
            "ssvcTechnicalImpact": "total",
            "cisaCVSS": {
                "baseScore": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
        }
    }


@pytest.fixture
def mock_nvd_response() -> Dict[str, Any]:
    """Mock NVD API response"""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "A vulnerability in the application allows SQL injection."
                        }
                    ],
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-89"}
                            ]
                        }
                    ]
                }
            }
        ]
    }
