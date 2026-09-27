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

    def test_lookup_attributions_returns_group_and_evidence(self, sample_groups_db):
        """A cited CVE returns its group with the citing ATT&CK object (I32)"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        processor.groups_db = dict(sample_groups_db, attributions={
            "CVE-2024-1234": [
                {"id": "G0016", "via": "C0024", "via_type": "campaign"},
                {"id": "G0007", "via": "G0007", "via_type": "relationship", "via_target": "T1083"},
            ]})

        result = processor.lookup_attributions("CVE-2024-1234")
        assert result == [
            {"id": "G0007", "name": "APT28", "via": "G0007", "via_type": "relationship", "via_target": "T1083"},
            {"id": "G0016", "name": "APT29", "via": "C0024", "via_type": "campaign"},
        ]

    def test_lookup_attributions_uncited_cve_is_empty(self, sample_groups_db):
        """A CVE ATT&CK does not cite has no groups, whatever its techniques"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        processor.groups_db = dict(sample_groups_db, attributions={})
        assert processor.lookup_attributions("CVE-2024-9999") == []

    def test_lookup_attributions_pre_i32_database_is_empty(self, sample_groups_db):
        """A groups_db.json with no attributions key links nothing"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        processor.groups_db = sample_groups_db
        assert processor.lookup_attributions("CVE-2024-1234") == []

    def test_lookup_attributions_skips_unknown_group(self, sample_groups_db):
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        processor.groups_db = dict(sample_groups_db, attributions={
            "CVE-2024-1234": [{"id": "G9999", "via": "G9999", "via_type": "intrusion-set"}]})
        assert processor.lookup_attributions("CVE-2024-1234") == []

    def test_lookup_before_load(self):
        """Looking up before loading should return empty list"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        assert processor.lookup_attributions("CVE-2024-1234") == []

    def test_no_technique_overlap_lookup_remains(self):
        """I30: the overlap lookup is deleted, not repaired"""
        from tip.core.apt_processor import APTProcessor
        assert not hasattr(APTProcessor, "lookup_by_techniques")

    def test_process_stix_empty_bundle(self):
        """Empty STIX bundle should return empty structures"""
        from tip.core.apt_processor import APTProcessor
        processor = APTProcessor()
        result = processor._process_stix_data({"objects": []})
        assert result["groups"] == {}
        assert result["technique_to_groups"] == {}
        assert result["attributions"] == {}
