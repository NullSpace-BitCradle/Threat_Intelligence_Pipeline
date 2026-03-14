"""Tests for CISA Vulnrichment Processor"""
import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestVulnrichmentProcessor:
    """Tests for Vulnrichment data processing"""

    def test_extract_ssvc_from_cve_json(self, sample_vulnrichment_cve):
        """Extracting SSVC data from a per-CVE JSON should return structured result"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        result = processor._extract_enrichment(sample_vulnrichment_cve)

        assert result is not None
        assert result["ssvcExploitStatus"] == "active"
        assert result["ssvcAutomatable"] == "yes"
        assert result["ssvcTechnicalImpact"] == "total"

    def test_extract_cisa_cvss(self, sample_vulnrichment_cve):
        """CISA CVSS score and vector should be extracted"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        result = processor._extract_enrichment(sample_vulnrichment_cve)

        assert result is not None
        assert result["cisaCVSS"]["baseScore"] == 9.8
        assert "CVSS:3.1" in result["cisaCVSS"]["vector"]

    def test_extract_no_adp_container(self):
        """CVE JSON without ADP container should return None"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        result = processor._extract_enrichment({"containers": {}})
        assert result is None

    def test_extract_no_ssvc_metrics(self):
        """ADP container without SSVC metrics should return None"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        data = {
            "containers": {
                "adp": [
                    {
                        "providerMetadata": {"orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0"},
                        "title": "CISA ADP Vulnrichment",
                        "metrics": []
                    }
                ]
            }
        }
        result = processor._extract_enrichment(data)
        assert result is None

    def test_lookup_found(self, sample_vulnrichment_db):
        """Looking up a CVE with Vulnrichment data should return it"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        processor.vulnrichment_db = sample_vulnrichment_db

        result = processor.lookup("CVE-2024-1234")
        assert result is not None
        assert result["ssvcExploitStatus"] == "active"

    def test_lookup_not_found(self, sample_vulnrichment_db):
        """Looking up a CVE without Vulnrichment data should return None"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        processor.vulnrichment_db = sample_vulnrichment_db

        result = processor.lookup("CVE-2024-0000")
        assert result is None

    def test_lookup_before_load(self):
        """Looking up before loading should return None"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        result = processor.lookup("CVE-2024-1234")
        assert result is None
