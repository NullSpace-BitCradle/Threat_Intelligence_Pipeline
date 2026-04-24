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


def test_pivot_returns_all_when_no_target_type(loader, sample_entity_id):
    resp = pivot_from_entity_impl(loader, sample_entity_id)
    assert resp["ok"] is True
    assert isinstance(resp["data"], list)
    assert resp["meta"]["count"] == len(resp["data"])


def test_pivot_invalid_type_returns_error(loader, sample_entity_id):
    resp = pivot_from_entity_impl(loader, sample_entity_id, target_type="bogus")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "invalid_type"


def test_pivot_unknown_entity_returns_not_found(loader):
    resp = pivot_from_entity_impl(loader, "CVE-0000-0000")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"


def test_pivot_filters_by_target_type(loader, sample_entity_id):
    # Find a target_type actually present in the sample entity's rels
    ent = loader.entities[sample_entity_id]
    rel_types = list(ent.get("rels", {}).keys())
    if not rel_types:
        pytest.skip("fixture entity has no rels")
    chosen = rel_types[0]
    # Normalize chosen to a VALID_TYPES member (rel_types often match type names)
    from tip_mcp.tools import VALID_TYPES
    if chosen not in VALID_TYPES:
        pytest.skip(f"rel_type {chosen} is not in VALID_TYPES; test needs different fixture")
    resp = pivot_from_entity_impl(loader, sample_entity_id, target_type=chosen)
    assert resp["ok"] is True
    for hit in resp["data"]:
        # Either the target's type matches, or the rel_type that linked it matches
        assert hit["type"] == chosen or hit["rel_type"] == chosen


def test_search_returns_structure(loader):
    resp = search_threat_intel_impl(loader, "a")
    assert resp["ok"] is True
    assert isinstance(resp["data"], list)
    assert resp["meta"]["source"] == "search_index.json"
    assert "query_tokens" in resp["meta"]


def test_search_respects_limit(loader):
    # Pick a token that exists in the fixture's search index so we have >= 1 hit
    sample_term = next(iter(loader.search_index.keys()))
    resp = search_threat_intel_impl(loader, sample_term, limit=1)
    assert resp["ok"] is True
    assert len(resp["data"]) <= 1


def test_search_empty_query_returns_bad_param(loader):
    resp = search_threat_intel_impl(loader, "")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "bad_param"


def test_search_bad_limit_returns_bad_param(loader):
    resp = search_threat_intel_impl(loader, "test", limit=0)
    assert resp["ok"] is False
    assert resp["error"]["code"] == "bad_param"


def test_search_empty_tokens_returns_empty_list(loader):
    resp = search_threat_intel_impl(loader, "   ")
    assert resp["ok"] is True
    assert resp["data"] == []
