# TIP MCP Server

An MCP server that exposes the Threat Intelligence Pipeline (TIP) entity graph
to Claude agents over stdio. See `docs/superpowers/specs/mcp-server-scope.md`
for design rationale.

## Status

Phase A (v1 MVP). Three read-only tools implemented against the pre-built
entity graph.

## Tools

- `lookup_entity(entity_id)` returns a single entity record and its relationships
- `pivot_from_entity(entity_id, target_type?)` returns entities related by type
- `search_threat_intel(query, limit?, types?)` returns ranked hits from the inverted index

## Install

The MCP layer keeps its dependency separate from TIP's core pipeline:

```bash
cd Threat_Intelligence_Pipeline
pip install -r requirements-mcp.txt
```

You also need TIP's pre-built indexes at `docs/data/entity_index.json` and
`docs/data/search_index.json`. If they are not present, run the TIP pipeline
first; see the top-level project README for pipeline instructions.

## Run

```bash
PYTHONPATH=src python -m tip_mcp.server
```

The server speaks MCP over stdio. On start it loads both indexes into memory
then waits for a client to connect. No output on stdout until JSON-RPC messages
arrive from a client.

## Claude Code / Claude Desktop configuration

Add an entry to your Claude Code `.mcp.json` (or the equivalent Claude Desktop
config):

```json
{
  "mcpServers": {
    "tip": {
      "command": "python",
      "args": ["-m", "tip_mcp.server"],
      "cwd": "/absolute/path/to/Threat_Intelligence_Pipeline",
      "env": {
        "PYTHONPATH": "src"
      }
    }
  }
}
```

Optionally set `TIP_DATA_DIR` in `env` to override the default `docs/data/`
location, which is useful if you share TIP data across multiple checkouts.

## Demo prompt

Once configured, try a prompt like:

> I'm looking at CVE-2023-44487 (HTTP/2 Rapid Reset). Use the TIP tools to walk
> me through the attack chain and what defends against it. Cite entity IDs.

Expected tool sequence:

1. `lookup_entity("CVE-2023-44487")` returns the CVE record with associated CWE
2. `pivot_from_entity("CVE-2023-44487", "technique")` returns ATT&CK techniques
3. `pivot_from_entity(<technique_id>, "d3fend")` returns D3FEND defenses

The agent produces a grounded narrative with real TIP entity citations instead
of hallucinated MITRE IDs.

## Data coverage

v1 reads only the pre-built entity graph (`docs/data/entity_index.json`), which
currently indexes the 1,351 CVEs with CWE mappings. For CVEs outside this set,
`lookup_entity` returns `not_found` with a hint. Broader CVE coverage depends
on TIP roadmap item #1 (all-CVE search architecture); the MCP layer will grow
a JSONL shard fallback in v1.1 once that roadmap item lands.

## Tests

Tests for schema, loader, and tools run without the `mcp` package installed
(only `server.py` imports it):

```bash
cd Threat_Intelligence_Pipeline
PYTHONPATH=src pytest tests/tip_mcp/ -v
```

## Design notes

- **FastMCP over low-level Server.** Less boilerplate; tool schemas auto-infer from Python type hints.
- **Package at `src/tip_mcp/`** so TIP's existing `PYTHONPATH=src` pattern works without reinstalling.
- **Split wrappers: `tools.py` vs `server.py`.** Impl functions in tools.py are testable with a fixture loader; server.py wraps them with the MCP decorators and a module-level loader. This is why tests pass without mcp installed.
