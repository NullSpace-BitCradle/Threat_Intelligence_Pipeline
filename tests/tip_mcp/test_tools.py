"""Tests for tip_mcp.tools."""

import pytest

from tip_mcp.tools import (
    lookup_entity_impl,
    pivot_from_entity_impl,
    search_threat_intel_impl,
)


@pytest.fixture
def sample_entity_id(loader):
    """Pick a known entity ID from the fixture that has rels."""
    for eid, ent in loader.entities.items():
        if ent.get("rels"):
            return eid
    raise AssertionError("fixture must contain at least one entity with rels")


def test_lookup_entity_known_id_returns_ok(loader, sample_entity_id):
    resp = lookup_entity_impl(loader, sample_entity_id)
    assert resp["ok"] is True
    assert resp["data"]["id"] == sample_entity_id
    assert "type" in resp["data"]
    assert "name" in resp["data"]
    assert isinstance(resp["data"]["rels"], list)
    assert resp["meta"]["source"] == "entity_index.json"


def test_lookup_entity_unknown_id_returns_not_found(loader):
    resp = lookup_entity_impl(loader, "CVE-9999-99999")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"
    assert "hint" in resp["error"]


def test_lookup_entity_empty_string_returns_bad_param(loader):
    resp = lookup_entity_impl(loader, "")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "bad_param"


def test_pivot_returns_all_when_no_target_type(loader):
    resp = pivot_from_entity_impl(loader, "CVE-2002-0367")
    assert resp["ok"] is True
    assert resp["meta"]["count"] == len(resp["data"]) == 11
    assert {h["rel_type"] for h in resp["data"]} == {"capec", "cwe", "defend", "owasp", "technique"}


def test_pivot_invalid_type_returns_error(loader, sample_entity_id):
    resp = pivot_from_entity_impl(loader, sample_entity_id, target_type="bogus")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "invalid_type"


def test_pivot_unknown_entity_returns_not_found(loader):
    resp = pivot_from_entity_impl(loader, "CVE-0000-0000")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"


def test_pivot_filters_by_target_type(loader):
    resp = pivot_from_entity_impl(loader, "CVE-2002-0367", target_type="capec")
    assert resp["ok"] is True
    assert sorted(h["id"] for h in resp["data"]) == ["CAPEC-122", "CAPEC-233", "CAPEC-58"]
    assert all(h["type"] == "capec" for h in resp["data"])


def test_search_returns_structure(loader):
    resp = search_threat_intel_impl(loader, "privilege")
    assert resp["ok"] is True
    assert len(resp["data"]) == 4
    assert resp["meta"]["source"] == "search_index.json"
    assert resp["meta"]["query_tokens"] == ["privilege"]
    for hit in resp["data"]:
        assert set(hit) == {"id", "type", "name", "score"}
        assert hit["score"] == 1


def test_search_respects_limit(loader):
    # "privilege" has 4 hits in the fixture; limit must cut to exactly 1.
    assert len(loader.search_index["privilege"]) >= 2
    resp = search_threat_intel_impl(loader, "privilege", limit=1)
    assert resp["ok"] is True
    assert len(resp["data"]) == 1


def test_search_empty_query_returns_bad_param(loader):
    resp = search_threat_intel_impl(loader, "")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "bad_param"


def test_search_ranks_by_match_count(loader):
    resp = search_threat_intel_impl(loader, "privilege abuse")
    scores = [h["score"] for h in resp["data"]]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] == 2


def test_search_bad_limit_returns_bad_param(loader):
    resp = search_threat_intel_impl(loader, "test", limit=0)
    assert resp["ok"] is False
    assert resp["error"]["code"] == "bad_param"


def test_search_empty_tokens_returns_empty_list(loader):
    resp = search_threat_intel_impl(loader, "   ")
    assert resp["ok"] is True
    assert resp["data"] == []
