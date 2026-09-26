"""server.py: the registered tool wrappers delegate to the impls, the data
dir resolves from env or the repo default, and main() loads before serving
or exits with a clear message. Skipped when the mcp package is absent."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("mcp")

from tip_mcp import server  # noqa: E402  (import after the skip guard)
from tip_mcp.loader import IndexLoader  # noqa: E402


@pytest.fixture
def served(monkeypatch, loader):
    monkeypatch.setattr(server, "_loader", loader)
    return loader


def test_wrappers_delegate_to_impls(served):
    assert server.lookup_entity("CVE-2002-0367")["data"]["id"] == "CVE-2002-0367"
    assert server.pivot_from_entity("T1548", "d3fend")["meta"]["count"] == 5
    assert server.search_threat_intel("access", 5, None)["ok"] is True
    chain = server.build_attack_chain("T1548")
    assert chain["meta"]["limit"] == 50 and chain["data"]["cves"]
    assert server.build_attack_chain("T1548", 1)["meta"]["limit"] == 1
    assert server.get_defenses(technique_id="T1548")["meta"]["count"] == 5
    assert server.get_defenses(cve_id="CVE-2002-0367")["ok"] is True
    assert server.get_defenses()["error"]["code"] == "bad_param"
    assert server.kev_status("CVE-2002-0367")["data"]["in_kev"] is True


def test_data_dir_resolution(monkeypatch, tmp_path):
    monkeypatch.setenv("TIP_DATA_DIR", str(tmp_path))
    assert server._resolve_data_dir() == tmp_path
    monkeypatch.delenv("TIP_DATA_DIR")
    assert server._resolve_data_dir() == Path(server.__file__).resolve().parents[2] / "docs" / "data"
    monkeypatch.setenv("TIP_SHARDS_DIR", str(tmp_path))
    assert server._resolve_shards_dir() == tmp_path
    monkeypatch.delenv("TIP_SHARDS_DIR")
    assert server._resolve_shards_dir() is None


def test_main_loads_then_runs(monkeypatch, fixture_data_dir, fixture_shards_dir):
    ld = IndexLoader(fixture_data_dir, shards_dir=fixture_shards_dir)
    monkeypatch.setattr(server, "_loader", ld)
    ran = []
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: ran.append(ld.loaded))
    server.main()
    assert ran == [True]


def test_main_exits_when_indexes_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_loader", IndexLoader(tmp_path / "nope"))
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: pytest.fail("must not serve"))
    with pytest.raises(SystemExit, match="Run the TIP pipeline first"):
        server.main()
