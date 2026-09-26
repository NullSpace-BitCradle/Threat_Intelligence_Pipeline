#!/usr/bin/env python3
"""Run the CVE-2023-44487 walkthrough against the TIP MCP server over stdio.

Launches `python -m tip_mcp.server` exactly as an MCP client would (the
mcp SDK client, stdio transport), against the repo's own docs/data, and
writes a readable transcript to src/tip_mcp/DEMO.md: the analyst question,
the tool call, and a trimmed JSON result for each step.

The output is deterministic (no timestamps, timings, or absolute paths), so
re-running on the same data reproduces the file byte for byte.

    python scripts/mcp_demo.py           # write src/tip_mcp/DEMO.md
    python scripts/mcp_demo.py --check   # exit 1 if DEMO.md is out of date

Requires the packages in requirements-mcp.txt.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from pathlib import Path
from typing import Any

import anyio
import mcp

REPO = Path(__file__).resolve().parents[1]
DEMO_PATH = REPO / "src" / "tip_mcp" / "DEMO.md"

# Longest list and string shown in the transcript; the rest is elided with
# a count so the reader knows how much was cut.
MAX_ITEMS = 8
MAX_CHARS = 240

STEPS: list[tuple[str, str, dict[str, Any]]] = [
    (
        "What is CVE-2023-44487?",
        "lookup_entity",
        {"entity_id": "CVE-2023-44487"},
    ),
    (
        "Which ATT&CK techniques does it map to?",
        "pivot_from_entity",
        {"entity_id": "CVE-2023-44487", "target_type": "technique"},
    ),
    (
        "What is the attack chain behind T1499 (Endpoint Denial of Service)?",
        "build_attack_chain",
        {"technique_id": "T1499", "limit": 10},
    ),
    (
        "How do I defend against CVE-2023-44487?",
        "get_defenses",
        {"cve_id": "CVE-2023-44487"},
    ),
    (
        "Is it in CISA KEV, and how urgent is the patch?",
        "kev_status",
        {"cve_id": "CVE-2023-44487"},
    ),
]


def trim(value: Any) -> Any:
    """Shorten long lists and strings for display, recursively."""
    if isinstance(value, dict):
        return {k: trim(v) for k, v in value.items()}
    if isinstance(value, list):
        head = [trim(v) for v in value[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            head.append(f"... {len(value) - MAX_ITEMS} more")
        return head
    if isinstance(value, str) and len(value) > MAX_CHARS:
        return value[:MAX_CHARS] + f"... ({len(value)} chars)"
    return value


def summarize(tool: str, result: dict) -> str:
    """One plain sentence stating what came back, computed from the result."""
    if not result.get("ok"):
        return f"Error: {result['error']['code']}."
    data, meta = result["data"], result.get("meta", {})
    if tool == "lookup_entity":
        return (
            f"{data['id']}: CVSS {data.get('cvss_score')} {data.get('severity')}, "
            f"KEV {data['kev']}, {meta['rel_count']} relationships."
        )
    if tool == "pivot_from_entity":
        return f"{meta['count']} techniques: " + ", ".join(h["id"] for h in data) + "."
    if tool == "build_attack_chain":
        t = meta["totals"]
        kev = sum(1 for c in data["cves"] if c["kev"])
        return (
            f"{t['capecs']} CAPEC patterns, {t['cwes']} weaknesses, {t['cves']} CVEs, "
            f"{t['defenses']} D3FEND defenses (lists capped at {meta['limit']}; "
            f"{kev} of the {len(data['cves'])} CVEs shown are in KEV)."
        )
    if tool == "get_defenses":
        verbs = sum(1 for d in data if "relationship" in d)
        return (
            f"{meta['count']} D3FEND defenses reached through {len(meta['techniques'])} "
            f"techniques; {verbs} carry a relationship verb."
        )
    if tool == "kev_status":
        return (
            f"In KEV: {data['in_kev']}; added {data['date_added']}, due {data['due_date']}, "
            f"ransomware use {data['known_ransomware_campaign_use']}."
        )
    return ""


def render(results: list[dict]) -> str:
    out = [
        "# TIP MCP demo: CVE-2023-44487 (HTTP/2 Rapid Reset)",
        "",
        "A scripted MCP client session against the TIP MCP server over stdio, run on",
        "this repo's `docs/data` index and `docs/database` shards. Each step shows the",
        "analyst question, the tool call a model would make, and the result (long",
        "lists and strings trimmed for reading; `meta` counts are the full numbers).",
        "",
        "Regenerate with `python scripts/mcp_demo.py`; `python scripts/mcp_demo.py",
        "--check` fails if this file no longer matches a fresh run. To ask the same",
        "questions interactively, open the repo in Claude Code, which reads `.mcp.json`",
        "and launches the `tip-mcp` server.",
        "",
    ]
    for n, ((question, tool, args), result) in enumerate(zip(STEPS, results), 1):
        call = f"{tool}({json.dumps(args)})"
        out += [
            f"## Step {n}: {question}",
            "",
            "```text",
            call,
            "```",
            "",
            summarize(tool, result),
            "",
            "```json",
            json.dumps(trim(result), indent=2, ensure_ascii=False),
            "```",
            "",
        ]
    return "\n".join(out)


async def run_session() -> list[dict]:
    env = {k: v for k, v in os.environ.items() if k not in ("TIP_DATA_DIR", "TIP_SHARDS_DIR")}
    env["PYTHONPATH"] = str(REPO / "src")
    params = mcp.StdioServerParameters(
        command=sys.executable, args=["-m", "tip_mcp.server"], cwd=str(REPO), env=env
    )
    results = []
    with anyio.fail_after(300):
        async with mcp.Client(params) as client:
            for _, tool, args in STEPS:
                res = await client.call_tool(tool, args)
                results.append(res.structured_content)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="diff against DEMO.md instead of writing it")
    args = parser.parse_args()
    text = render(anyio.run(run_session))
    if args.check:
        current = DEMO_PATH.read_text(encoding="utf-8") if DEMO_PATH.exists() else ""
        if current == text:
            print("DEMO.md matches a fresh run.")
            return 0
        sys.stdout.writelines(
            difflib.unified_diff(
                current.splitlines(True), text.splitlines(True), "DEMO.md", "fresh run"
            )
        )
        return 1
    DEMO_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {DEMO_PATH.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
