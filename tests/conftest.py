"""
Pytest configuration and fixtures for Threat Intelligence Pipeline tests
"""
import pytest
from pathlib import Path
from typing import Dict, Any
import sys

# Add src to path for imports - must be first to avoid tip.py conflict
_src_path = str(Path(__file__).parent.parent / "src")
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)


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
def sample_stix_bundle() -> Dict[str, Any]:
    """Sample STIX bundle with groups, attack patterns, and uses relationships"""
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--aaa",
                "name": "APT29",
                "aliases": ["APT29", "Cozy Bear", "The Dukes", "YTTRIUM"],
                "description": "APT29 is a threat group attributed to Russia.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}]
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--bbb",
                "name": "APT28",
                "aliases": ["APT28", "Fancy Bear", "Sofacy"],
                "description": "APT28 is a threat group attributed to Russia.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0007"}]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--111",
                "name": "File and Directory Discovery",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1083"}]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--222",
                "name": "Phishing",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--333",
                "name": "Data from Local System",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1005"}]
            },
            {
                "type": "relationship",
                "id": "relationship--r1",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--aaa",
                "target_ref": "attack-pattern--111"
            },
            {
                "type": "relationship",
                "id": "relationship--r2",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--aaa",
                "target_ref": "attack-pattern--333"
            },
            {
                "type": "relationship",
                "id": "relationship--r3",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--bbb",
                "target_ref": "attack-pattern--111"
            },
            {
                "type": "relationship",
                "id": "relationship--r4",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--bbb",
                "target_ref": "attack-pattern--222"
            }
        ]
    }


@pytest.fixture
def sample_groups_db() -> Dict[str, Any]:
    """Sample groups database: groups indexed by ID + reverse technique index"""
    return {
        "groups": {
            "G0016": {
                "name": "APT29",
                "aliases": ["APT29", "Cozy Bear", "The Dukes", "YTTRIUM"],
                "description": "APT29 is a threat group attributed to Russia.",
                "techniques": ["T1005", "T1083"]
            },
            "G0007": {
                "name": "APT28",
                "aliases": ["APT28", "Fancy Bear", "Sofacy"],
                "description": "APT28 is a threat group attributed to Russia.",
                "techniques": ["T1083", "T1566"]
            }
        },
        "technique_to_groups": {
            "T1083": ["G0016", "G0007"],
            "T1005": ["G0016"],
            "T1566": ["G0007"]
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
