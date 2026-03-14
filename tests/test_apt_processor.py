"""Tests for APT Groups Processor"""
import pytest
import json
from pathlib import Path


class TestAPTProcessor:
    """Tests for ATT&CK Groups STIX processing"""

    def test_process_stix_extracts_groups(self, sample_stix_bundle):
        """Processing STIX bundle should extract all intrusion-set groups"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        result = processor._process_stix_data(sample_stix_bundle)

        assert "groups" in result
        assert "G0016" in result["groups"]
        assert "G0007" in result["groups"]
        assert len(result["groups"]) == 2

    def test_process_stix_extracts_aliases(self, sample_stix_bundle):
        """Each group should include its aliases"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        result = processor._process_stix_data(sample_stix_bundle)

        apt29 = result["groups"]["G0016"]
        assert apt29["name"] == "APT29"
        assert "Cozy Bear" in apt29["aliases"]
        assert "The Dukes" in apt29["aliases"]
        assert "YTTRIUM" in apt29["aliases"]

    def test_process_stix_maps_techniques_to_groups(self, sample_stix_bundle):
        """Groups should list the techniques they use"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        result = processor._process_stix_data(sample_stix_bundle)

        apt29 = result["groups"]["G0016"]
        assert "T1083" in apt29["techniques"]
        assert "T1005" in apt29["techniques"]

    def test_process_stix_builds_reverse_index(self, sample_stix_bundle):
        """Reverse index should map technique IDs to group IDs"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        result = processor._process_stix_data(sample_stix_bundle)

        assert "technique_to_groups" in result
        t1083_groups = result["technique_to_groups"]["T1083"]
        assert "G0016" in t1083_groups
        assert "G0007" in t1083_groups

    def test_process_stix_reverse_index_exclusive_technique(self, sample_stix_bundle):
        """T1005 is only used by APT29, not APT28"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        result = processor._process_stix_data(sample_stix_bundle)

        t1005_groups = result["technique_to_groups"]["T1005"]
        assert "G0016" in t1005_groups
        assert "G0007" not in t1005_groups

    def test_lookup_by_techniques_found(self, sample_groups_db):
        """Looking up groups by technique should return matching groups"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        processor.groups_db = sample_groups_db

        result = processor.lookup_by_techniques(["T1083"])
        assert len(result) == 2
        names = [g["name"] for g in result]
        assert "APT29" in names
        assert "APT28" in names

    def test_lookup_by_techniques_with_overlap(self, sample_groups_db):
        """Each result should include which queried techniques overlap"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        processor.groups_db = sample_groups_db

        result = processor.lookup_by_techniques(["T1083", "T1005"])
        apt29 = [g for g in result if g["name"] == "APT29"][0]
        assert "T1083" in apt29["techniques_overlap"]
        assert "T1005" in apt29["techniques_overlap"]

        apt28 = [g for g in result if g["name"] == "APT28"][0]
        assert "T1083" in apt28["techniques_overlap"]
        assert "T1005" not in apt28["techniques_overlap"]

    def test_lookup_by_techniques_not_found(self, sample_groups_db):
        """Looking up an unknown technique should return empty list"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        processor.groups_db = sample_groups_db

        result = processor.lookup_by_techniques(["T9999"])
        assert result == []

    def test_lookup_before_load(self):
        """Looking up before loading should return empty list"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        result = processor.lookup_by_techniques(["T1083"])
        assert result == []

    def test_process_stix_empty_bundle(self):
        """Empty STIX bundle should return empty structures"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        result = processor._process_stix_data({"objects": []})
        assert result["groups"] == {}
        assert result["technique_to_groups"] == {}
