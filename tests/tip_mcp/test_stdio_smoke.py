"""ISC-31: stdio smoke test. Launches `python -m tip_mcp.server` as a real
subprocess on the fixture index, lists its tools over MCP stdio, and calls
lookup_entity. Skipped when the mcp package is not installed (the rest of the
tip_mcp suite runs without it)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")

import anyio  # noqa: E402  (mcp dependency; import after the skip guard)

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


async def _session() -> tuple[list, dict, dict]:
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
    tools = [(t.name, t.input_schema) for t in listed.tools]
    return tools, json.loads(entity.content[0].text), pivot.structured_content


def test_stdio_server_lists_tools_and_answers_lookup():
    tools, entity, pivot = anyio.run(_session)

    by_name = dict(tools)
    assert set(by_name) == {"lookup_entity", "pivot_from_entity", "search_threat_intel"}
    assert by_name["lookup_entity"]["required"] == ["entity_id"]
    assert set(by_name["search_threat_intel"]["properties"]) == {"query", "limit", "types"}

    assert entity["ok"] is True
    assert entity["data"]["id"] == "CVE-2002-0367"
    assert entity["meta"]["source"] == "entity_index.json"

    assert pivot["ok"] is True
    assert pivot["meta"]["count"] == 5
