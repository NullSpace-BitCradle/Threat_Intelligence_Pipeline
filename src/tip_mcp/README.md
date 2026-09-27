# TIP MCP Server

An MCP server that exposes the Threat Intelligence Pipeline (TIP) entity graph
and per-year CVE shards to Claude agents over stdio.

## Status

Phase B (P10). Six read-only tools over the pre-built entity graph, the CISA
KEV catalog, and a shard fallback that serves any ingested CVE. A recorded
session of all of them on real data is in [DEMO.md](DEMO.md).

## Tools

| Tool | What it returns | Example prompt |
|---|---|---|
| `lookup_entity(entity_id)` | One entity record and its relationships | "What is CVE-2023-44487?" |
| `pivot_from_entity(entity_id, target_type?)` | Related entities, optionally filtered by type | "Which ATT&CK techniques does CVE-2023-44487 map to?" |
| `search_threat_intel(query, limit?, types?)` | Ranked hits from the inverted index | "Find TIP entities about HTTP/2 denial of service." |
| `build_attack_chain(technique_id, limit?)` | The CVEs linked to a technique (KEV first, then CVSS), each explained by its CWE and CAPEC path, plus D3FEND defenses; every element carries the tier of its weakest hop | "What is the attack chain behind T1499, and which KEV CVEs sit on it?" |
| `get_defenses(technique_id? \| cve_id?)` | D3FEND countermeasures for exactly one technique or CVE, with mapping source, tier, the technique each was reached through, and the relationship verb when known; CVE-side defenses are derived | "Which D3FEND countermeasures map to T1499?" |
| `kev_status(cve_id)` | KEV membership, date added, due date, ransomware use, required action, vendor, product, and SSVC when known | "Is CVE-2023-44487 in CISA KEV, and when was it due?" |

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

### Phase B tool notes

- **`build_attack_chain`** returns exactly the CVEs the graph links to the
  technique (its own `cve` rels); the CAPEC and CWE path only explains them.
  `capecs` are the CAPEC patterns whose `capec -> technique` rel names the
  technique. Each CVE lists `via_cwes` (its CWEs that reach one of those
  CAPECs) and `via_capecs` (the CAPECs reached); a CVE with no such CWE still
  appears, with empty via lists, and `meta.cves_without_path` counts them.
  `cwes` lists only the CWEs a returned CVE goes through, each with
  `via_capecs`, `inherited_capecs`, and an `inherited` flag: true when a CWE
  to CAPEC link is not in the CWE's own RelatedAttackPatterns in
  `docs/data/cwe_db.json` (the generator inherited it from a ChildOf parent),
  null when `cwe_db.json` is unavailable. The entity index stores the capec
  and cwe edges in one direction only, so the server builds a reverse
  adjacency map once, on first use, instead of changing the generator.
- **Provenance is the weakest hop.** Every chain element and every CVE-side
  defense carries the `source` and `tier` of the weakest hop on its path
  (authoritative > official > derived). An inherited or unverified CWE to
  CAPEC hop is derived. A chain CVE is as strong as the `technique -> cve`
  rel that put it there, which TIP derives (`Pipeline (CAPEC→Technique
  chain)`), so chain CVEs are derived today. Nothing on a path with a derived
  or inherited hop is labeled authoritative or official.
- **`build_attack_chain` limits and notes.** Each list is capped at `limit`
  (default 50); `meta.totals` holds the uncapped counts and
  `meta.truncated` says whether anything was cut. A technique with no CAPEC
  link (T1498, T1190 and T1059 on current data) returns empty CAPEC and CWE
  lists, its own CVEs if any, its D3FEND defenses, and a `meta.note` saying
  why.
- **`get_defenses`** takes exactly one of `technique_id` or `cve_id`
  (`bad_param` for both, neither, or a non-string). For a technique, each
  defense keeps the mapping's own provenance (`MITRE D3FEND`, official). For
  a CVE, each defense lists the ATT&CK techniques it was reached through in
  `via_techniques` (empty for a defense only on the CVE's own D3FEND rels),
  carries the weakest tier of the CVE to technique and technique to D3FEND
  hops (derived, since TIP derives CVE to technique links), and names that
  composed path in `mapping_source`. The D3FEND relationship verb (isolates,
  monitors, hardens, ...) comes from the CVE's shard when present. Read
  CVE-side defenses as leads through the CVE's techniques, not as MITRE
  mappings of the CVE.
- **Inherited links (I29).** An index generated after I29 sets
  `meta.inherited_links` and marks every link reached only through an
  inherited parent CWE (a ChildOf parent NVD did not assign; pillars are
  never inherited). `pivot_from_entity` hits and `lookup_entity` rels carry
  `inherited: true` for such links, on the entity path and on the shard path
  (from the shard's `_INHERITED` lists); a CVE record carries
  `cwe_inherited`, and its `cwe` rels are the NVD-assigned CWEs only.
  `build_attack_chain` reads each CWE's `inherited` CAPECs from the index
  instead of recomputing them from `cwe_db.json`; a chain CVE that no
  assigned CWE explains is explained through its inherited parents, listed
  in `inherited_cwes`, with the CWE element flagged `inherited_parent` and
  the CVE derived; a chain CVE whose technique link is inherited carries
  `inherited: true`. `get_defenses` marks a CVE-side defense `inherited:
  true` when every link that reaches it is inherited. Each flag appears only
  when true, so an older index or shard produces the same output as before.
- **`kev_status`** decides KEV membership from `docs/data/kev_db.json`, the
  CISA catalog, so a KEV CVE outside the curated graph still reports
  `in_kev: true`. A CVE not in KEV returns `ok` with `in_kev: false` and null
  KEV fields. SSVC comes from the entity record, else the shard, else null.
  If `kev_db.json` is missing, the graph's flag is used and `meta.note` says so.

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
`search_index.json`, and optionally `cve_ids_index.json` and `kev_db.json`) and the year shards
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

The repo ships a project-scoped [`.mcp.json`](../../.mcp.json) that registers
the server as `tip-mcp`. Claude Code launches project servers from the project
root, so the relative `PYTHONPATH=src` resolves inside your clone and no
absolute path is needed:

```json
{
  "mcpServers": {
    "tip-mcp": {
      "type": "stdio",
      "command": "${TIP_PYTHON:-python3}",
      "args": ["-m", "tip_mcp.server"],
      "env": {
        "PYTHONPATH": "src"
      }
    }
  }
}
```

Open the clone in Claude Code from a shell where `python3` has
`requirements-mcp.txt` installed (an activated virtualenv works), or set
`TIP_PYTHON` to that interpreter. Approve the `tip-mcp` server when Claude
Code asks. For Claude Desktop, which has no project root, copy the entry into
its config and give an absolute `cwd`.

Optionally set `TIP_DATA_DIR` to override the default `docs/data/` location
and `TIP_SHARDS_DIR` to override the default `docs/database/` shard location,
which is useful if you share TIP data across multiple checkouts.

## Demo

Once configured, try a prompt like:

> I'm looking at CVE-2023-44487 (HTTP/2 Rapid Reset). Use the TIP tools to walk
> me through the attack chain and what defends against it, and tell me how
> urgent the patch is. Cite entity IDs.

[DEMO.md](DEMO.md) is the recorded tool sequence on this repo's data:

1. `lookup_entity("CVE-2023-44487")` returns the KEV record with `kev_detail` and 83 relationships
2. `pivot_from_entity("CVE-2023-44487", "technique")` returns 9 ATT&CK techniques, including T1499
3. `build_attack_chain("T1499")` returns the CVEs linked to T1499 ranked KEV first, each explained by its CWE and CAPEC path, the 3 CAPECs and the CWEs those CVEs go through (inherited links flagged and derived), and 11 D3FEND defenses
4. `get_defenses(technique_id="T1499")` returns 11 D3FEND defenses, MITRE D3FEND mappings at tier official
5. `get_defenses(cve_id="CVE-2023-44487")` returns 44 D3FEND defenses reached through its 9 techniques, each with its relationship verb and tier derived
6. `kev_status("CVE-2023-44487")` returns in KEV since 2023-10-10, due 2023-10-31

`scripts/mcp_demo.py` produced it: a real MCP client session over stdio (the
mcp SDK client, as the smoke test uses). Run it to regenerate the file, or
with `--check` to confirm the committed transcript still matches the data.
The demo anchor is T1499 (Endpoint Denial of Service), the technique
CVE-2023-44487 maps to; T1498 has no CAPEC link in TIP data.

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

Coverage on `src/tip_mcp` is above 90%, and CI enforces that floor (`tests.yml` runs
pytest-cov from `requirements-dev.txt`). To reproduce locally:

```bash
pytest tests/tip_mcp --cov=src/tip_mcp --cov-fail-under=90
```

## Design notes

- **MCPServer over the low-level Server.** Less boilerplate; tool schemas infer from Python type hints.
- **Package at `src/tip_mcp/`** so TIP's existing `PYTHONPATH=src` pattern works without reinstalling.
- **Split wrappers: `tools.py` vs `server.py`.** Impl functions in tools.py are testable with a fixture loader; server.py wraps them with the MCP decorators and a module-level loader. This is why tests pass without mcp installed.
- **One intel contract.** `src/tip_intel/cve_blocks.py` defines the CVE intelligence blocks for both the entity-index generator and this server; `tests/test_cve_intel_parity.py` drives the generator's real record builder to keep them in step.
