"""ISC-31: stdio smoke test. Launches `python -m tip_mcp.server` as a real
subprocess on the fixture index, lists its tools over MCP stdio, and calls
lookup_entity, pivot_from_entity, and the three Phase B tools. Skipped when the mcp package is not installed (the rest of the
tip_mcp suite runs without it)."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")

import anyio  # noqa: E402  (mcp dependency; import after the skip guard)

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


async def _session() -> tuple[list, dict, dict, dict, dict, dict]:
    params = mcp.StdioServerParameters(
        command=sys.executable,
        args=["-m", "tip_mcp.server"],
        cwd=str(REPO),
        env={
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "TIP_DATA_DIR": str(FIXTURES),
            "TIP_SHARDS_DIR": str(FIXTURES / "database"),
        },
    )
    with anyio.fail_after(60):
        async with mcp.Client(params) as client:
            listed = await client.list_tools()
            entity = await client.call_tool("lookup_entity", {"entity_id": " cve-2002-0367 "})
            pivot = await client.call_tool(
                "pivot_from_entity", {"entity_id": "T1548", "target_type": "d3fend"}
            )
            chain = await client.call_tool("build_attack_chain", {"technique_id": "T1548"})
            defenses = await client.call_tool("get_defenses", {"cve_id": "CVE-2002-0367"})
            kev = await client.call_tool("kev_status", {"cve_id": "CVE-2002-0367"})
    tools = [(t.name, t.input_schema) for t in listed.tools]
    return (
        tools,
        json.loads(entity.content[0].text),
        pivot.structured_content,
        chain.structured_content,
        defenses.structured_content,
        kev.structured_content,
    )


def test_stdio_server_lists_tools_and_answers_lookup():
    tools, entity, pivot, chain, defenses, kev = anyio.run(_session)

    by_name = dict(tools)
    assert set(by_name) == {
        "lookup_entity",
        "pivot_from_entity",
        "search_threat_intel",
        "build_attack_chain",
        "get_defenses",
        "kev_status",
    }
    assert by_name["lookup_entity"]["required"] == ["entity_id"]
    assert set(by_name["search_threat_intel"]["properties"]) == {"query", "limit", "types"}

    assert entity["ok"] is True
    assert entity["data"]["id"] == "CVE-2002-0367"
    assert entity["meta"]["source"] == "entity_index.json"

    assert pivot["ok"] is True
    assert pivot["meta"]["count"] == 5

    assert set(by_name["build_attack_chain"]["properties"]) == {"technique_id", "limit"}
    assert by_name["kev_status"]["required"] == ["cve_id"]
    assert "required" not in by_name["get_defenses"] or not by_name["get_defenses"]["required"]

    assert chain["ok"] is True
    assert [c["id"] for c in chain["data"]["cwes"]] == ["CWE-269"]
    assert defenses["ok"] is True and defenses["meta"]["count"] == 5
    assert kev["ok"] is True and kev["data"]["in_kev"] is True


def _expand(value: str, env: dict) -> str:
    """Expand ${VAR} and ${VAR:-default} the way Claude Code does for .mcp.json."""
    return re.sub(
        r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}",
        lambda m: env.get(m.group(1)) or (m.group(2) or ""),
        value,
    )


def test_repo_mcp_json_is_portable_and_launches_server():
    config = json.loads((REPO / ".mcp.json").read_text())
    server = config["mcpServers"]["tip-mcp"]
    assert server["type"] == "stdio"
    for value in [server["command"], *server["args"], *server["env"].values()]:
        assert not os.path.isabs(value), value
        assert "/home/" not in value and ":\\" not in value, value

    # Claude Code runs a project .mcp.json server with the project root as
    # its working directory. Point TIP_PYTHON at this interpreter (it has
    # mcp installed) and launch exactly what the config says.
    env = {**os.environ, "TIP_PYTHON": sys.executable}
    command = _expand(server["command"], env)
    env.update(server["env"])
    env["TIP_DATA_DIR"] = str(FIXTURES)
    env["TIP_SHARDS_DIR"] = str(FIXTURES / "database")

    async def listed() -> set:
        params = mcp.StdioServerParameters(
            command=command, args=server["args"], cwd=str(REPO), env=env
        )
        with anyio.fail_after(60):
            async with mcp.Client(params) as client:
                return {t.name for t in (await client.list_tools()).tools}

    assert len(anyio.run(listed)) == 6
