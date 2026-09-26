"""search_threat_intel rejects a types value that is not a list of strings
with an envelope instead of raising."""

from __future__ import annotations

import pytest

from tip_mcp.tools import search_threat_intel_impl


@pytest.mark.parametrize("types", [5, "cve", {"cve": 1}, 3.5, True])
def test_non_list_types_is_bad_param(loader, types):
    resp = search_threat_intel_impl(loader, "injection", types=types)
    assert resp["ok"] is False
    assert resp["error"]["code"] == "bad_param"


@pytest.mark.parametrize("types", [[5], ["cve", None], [["cve"]]])
def test_non_string_member_is_invalid_type(loader, types):
    resp = search_threat_intel_impl(loader, "injection", types=types)
    assert resp["ok"] is False
    assert resp["error"]["code"] == "invalid_type"


def test_empty_list_means_no_filter(loader):
    assert search_threat_intel_impl(loader, "injection", types=[]) == \
        search_threat_intel_impl(loader, "injection")
