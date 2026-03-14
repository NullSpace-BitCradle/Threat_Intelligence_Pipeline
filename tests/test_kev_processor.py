"""Tests for CISA KEV Processor"""
import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestKEVProcessor:
    """Tests for KEV data processing"""

    def test_process_kev_data_indexes_by_cve_id(self, sample_kev_data):
        """Processing raw KEV data should produce a dict indexed by CVE ID"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        result = processor._process_kev_data(sample_kev_data)

        assert "CVE-2024-1234" in result
        assert "CVE-2024-9999" in result
        assert "CVE-2024-5678" in result
        assert len(result) == 3

    def test_process_kev_data_extracts_required_fields(self, sample_kev_data):
        """Each indexed entry should contain the expected KEV fields"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        result = processor._process_kev_data(sample_kev_data)

        entry = result["CVE-2024-1234"]
        assert entry["inKEV"] is True
        assert entry["dateAdded"] == "2024-06-15"
        assert entry["dueDate"] == "2024-07-06"
        assert entry["knownRansomwareCampaignUse"] == "Known"
        assert entry["requiredAction"] == "Apply vendor patch."
        assert entry["vendorProject"] == "TestVendor"
        assert entry["product"] == "TestProduct"

    def test_process_kev_data_handles_missing_optional_fields(self):
        """Entries without optional fields (cwes, notes) should still process"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        raw = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "V",
                    "product": "P",
                    "vulnerabilityName": "N",
                    "dateAdded": "2024-01-01",
                    "shortDescription": "D",
                    "requiredAction": "A",
                    "dueDate": "2024-02-01"
                }
            ]
        }
        result = processor._process_kev_data(raw)
        assert "CVE-2024-0001" in result
        assert result["CVE-2024-0001"]["inKEV"] is True

    def test_process_kev_data_empty_catalog(self):
        """Empty vulnerability list should return empty dict"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        result = processor._process_kev_data({"vulnerabilities": []})
        assert result == {}

    def test_lookup_cve_found(self, sample_kev_db):
        """Looking up a CVE that is in KEV should return its data"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        processor.kev_db = sample_kev_db

        result = processor.lookup("CVE-2024-1234")
        assert result is not None
        assert result["inKEV"] is True
        assert result["vendorProject"] == "TestVendor"

    def test_lookup_cve_not_found(self, sample_kev_db):
        """Looking up a CVE not in KEV should return None"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        processor.kev_db = sample_kev_db

        result = processor.lookup("CVE-2024-0000")
        assert result is None

    def test_lookup_before_load_returns_none(self):
        """Looking up before loading the database should return None"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        result = processor.lookup("CVE-2024-1234")
        assert result is None
