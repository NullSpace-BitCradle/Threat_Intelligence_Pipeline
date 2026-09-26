# TIP MCP Server

An MCP server that exposes the Threat Intelligence Pipeline (TIP) entity graph
and per-year CVE shards to Claude agents over stdio.

## Status

Phase A. Three read-only tools over the pre-built entity graph, with a shard
fallback that serves any ingested CVE. Phase B tools (`build_attack_chain`,
`get_defenses`, `kev_status`) are roadmap item P10.

## Tools

- `lookup_entity(entity_id)` returns one entity record and its relationships
- `pivot_from_entity(entity_id, target_type?)` returns related entities, optionally filtered by type
- `search_threat_intel(query, limit?, types?)` returns ranked hits from the inverted index

Every tool returns an envelope: `{ok: true, data, meta}` or
`{ok: false, error: {code, message, hint?}}`. Error codes: `not_found`,
`invalid_type`, `bad_param`, `index_not_loaded` (an index file is missing,
unreadable, or the wrong shape), `data_corrupt` (a CVE year shard exists but
cannot be read).

### Type vocabulary

Types use the entity graph's names: `cve`, `cwe`, `capec`, `technique`,
`defend`, `apt_group`, `owasp`, `campaign`. `kev` filters to CVEs flagged
KEV. The legacy names `d3fend` (for `defend`) and `apt` (for `apt_group`) are
accepted on input; output always uses the graph names, on both the entity
path and the shard path.

### IDs

IDs are stripped and upper-cased where the canonical form is upper case
(`CVE-`, `CWE-`, `CAPEC-`, `T1234.001`, `G0016`, `D3-`, `A03:2021`), so
`" cve-2023-44487 "` and `"CVE-2023-44487"` return the same record. Other IDs
fall back to a case-insensitive match.

## Install

The MCP layer keeps its dependency separate from TIP's core pipeline:

```bash
cd Threat_Intelligence_Pipeline
pip install -r requirements-mcp.txt
```

`requirements-mcp.txt` pins `mcp==2.2.0`. The server uses the 2.x API
(`mcp.server.mcpserver.MCPServer`, the renamed FastMCP); it does not import
on mcp 1.x.

You also need TIP's pre-built indexes in `docs/data/` (`entity_index.json`,
`search_index.json`, and optionally `cve_ids_index.json`) and the year shards
in `docs/database/CVE-YYYY.jsonl.gz`. If they are not present, run the TIP
pipeline first; see the top-level project README.

## Run

```bash
PYTHONPATH=src python -m tip_mcp.server
```

The server speaks MCP over stdio. On start it loads both indexes into memory
then waits for a client to connect. No output on stdout until JSON-RPC
messages arrive from a client. Tool results carry the envelope both as JSON
text content and as `structuredContent`.

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

Optionally set `TIP_DATA_DIR` to override the default `docs/data/` location
and `TIP_SHARDS_DIR` to override the default `docs/database/` shard location,
which is useful if you share TIP data across multiple checkouts.

## Demo prompt

Once configured, try a prompt like:

> I'm looking at CVE-2023-44487 (HTTP/2 Rapid Reset). Use the TIP tools to walk
> me through the attack chain and what defends against it. Cite entity IDs.

Expected tool sequence (results from the 2026-09-20 data):

1. `lookup_entity("CVE-2023-44487")` returns the KEV record with `kev_detail` and 83 relationships
2. `pivot_from_entity("CVE-2023-44487", "technique")` returns 9 ATT&CK techniques, including T1499
3. `pivot_from_entity("T1499", "defend")` returns 11 D3FEND defenses (`"d3fend"` works too)

The agent produces a grounded narrative with real TIP entity citations instead
of hallucinated MITRE IDs.

## Data coverage

Three layers, all served:

- **Entity graph** (`docs/data/entity_index.json`): 5,585 entities, including
  2,971 curated CVEs (KEV, CISA vulnrichment, or APT-linked) with their CWE,
  CAPEC, technique, D3FEND, APT group, OWASP, and campaign links. CVE records
  carry description, CVSS, dates, references, and the `tip_intel` blocks
  (`kev_detail`, `ssvc`, `cisa_cvss`, `cvss_version`, `cvss_source`) when the
  pipeline captured them, so these survive without the shards.
- **All-IDs index** (`docs/data/cve_ids_index.json`): all 395,617 ingested CVE
  IDs. A CVE ID not listed there returns `not_found` without reading a shard.
- **Year shards** (`docs/database/CVE-1999.jsonl.gz` to `CVE-2026.jsonl.gz`):
  any ingested CVE outside the curated graph is served from its year shard
  (`meta.source` is `shard`). Curated CVEs also read the shard to add D3FEND
  relationship semantics (`meta.enriched_from_shard`).

### Shard cache

The first lookup in a year streams that shard once (about 2.4 s for
CVE-2026, the largest at 24.6 MB gzipped and 303 MB decompressed) and keeps
each line zlib-compressed in memory, keyed by CVE ID (about 100 MB for
CVE-2026). Later lookups in that year take well under a millisecond. The
cache keeps the 3 most recently used years (`IndexLoader(shard_cache_years=)`),
so memory stays around 200 to 300 MB in the worst case.

## Tests

Tests for schema, loader, and tools run without the `mcp` package installed
(only `server.py` imports it). `test_stdio_smoke.py` launches the real server
over stdio and is skipped when `mcp` is absent:

```bash
cd Threat_Intelligence_Pipeline
PYTHONPATH=src pytest tests/tip_mcp/ tests/test_cve_intel_parity.py -v
```

## Design notes

- **MCPServer over the low-level Server.** Less boilerplate; tool schemas infer from Python type hints.
- **Package at `src/tip_mcp/`** so TIP's existing `PYTHONPATH=src` pattern works without reinstalling.
- **Split wrappers: `tools.py` vs `server.py`.** Impl functions in tools.py are testable with a fixture loader; server.py wraps them with the MCP decorators and a module-level loader. This is why tests pass without mcp installed.
- **One intel contract.** `src/tip_intel/cve_blocks.py` defines the CVE intelligence blocks for both the entity-index generator and this server; `tests/test_cve_intel_parity.py` drives the generator's real record builder to keep them in step.
