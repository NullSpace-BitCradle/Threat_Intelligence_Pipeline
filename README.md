# Threat Intelligence Pipeline (TIP)

> **A note from the author:** I'm not a developer by trade. I'm a hybrid IT and cybersecurity professional who enjoys tinkering, learning, and building useful things along the way. This project is under active development and may break from time to time as I experiment and improve it. Once I'm confident everything is working reliably, I'll remove this notice.

A search-first threat intelligence tool that correlates CVEs across 8 security frameworks. Search any CVE, technique, APT group, or weakness and instantly see its relationships: attack patterns, defensive countermeasures, threat actors, CISA KEV status, and more.

**Live demo:** [nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline](https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/)

![Landing Page](docs/images/landing.png)

![APT Group Result](docs/images/result-apt.png)

![CVE Result](docs/images/result-cve.png)

## Status snapshot

As of 2026-04-24:

- 345K raw CVEs ingested from NVD, 271K with CWE mappings, 2,766 indexed in the entity graph
- 5,303 total entities across 8 frameworks
- Auto-rebuilds via GitHub Actions: daily reference database refresh + weekly full CVE pipeline
- MCP Phase A live (3 of 6 tools), with shard fallback in both `lookup_entity` and `pivot_from_entity` for any CVE on disk
- 67 tests passing

The full roadmap with status of every item lives in [Plans/ROADMAP.md](Plans/ROADMAP.md). A summary is included in the [Roadmap](#roadmap) section below.

## How it works

Search for any entity and TIP shows you its complete threat intelligence picture:

- **CVEs**: weakness mappings, attack patterns, techniques, defensive measures, KEV status, SSVC risk, APT attribution, CVSS score and severity, disclosure dates, references
- **ATT&CK techniques**: associated CVEs, APT groups that use them, D3FEND countermeasures
- **APT groups**: aliases, descriptions, technique usage, linked CVEs and campaigns
- **CWEs**: parent chain, related attack patterns, OWASP categories
- **Campaigns**: attribution, timelines, technique usage

The pipeline builds the correlation chain automatically:

```
CVE -> CWE -> CAPEC -> ATT&CK Techniques -> D3FEND Countermeasures
                                          -> APT Groups (reverse lookup)
    -> OWASP Top 10 Category
    -> CISA KEV Status + Ransomware Use
    -> CISA SSVC Decision + CVSS Override
```

## Web interface

Search-first design with two views.

**Landing page**: one search bar across all entity types, database stats, and quick-access cards for recent KEV additions.

**Result page**: split layout with an intelligence brief on the left (entity header, badges, summary cards, tabbed framework detail) and a D3 force-directed relationship graph on the right showing how the entity connects across frameworks.

Features:
- Search by ID (`CVE-2024-37079`, `T1059`, `CWE-79`) or name (`APT29`, `Log4Shell`)
- CVE pages render full description, CVSS severity badge, disclosure dates, and reference count
- Overview tab with descriptions, aliases, KEV details, and data provenance
- Framework tabs: ATT&CK, D3FEND, APT Groups, OWASP, CWE, CAPEC, KEV detail
- Interactive relationship graph; click any node to navigate
- Investigation pinning with JSON export
- Dark and light theme
- Hash-based routing with shareable URLs and browser back / forward
- Static GitHub Pages deployment, zero install required

## Data sources

| Source | What it provides | Update frequency |
|--------|------------------|------------------|
| NVD API 2.0 | CVE records, CVSS scores, CWE assignments, descriptions, references | Weekly (Actions) |
| MITRE ATT&CK | Attack techniques (enterprise, mobile, ICS) | Weekly (Actions) |
| MITRE ATT&CK Groups | 160 threat groups with aliases and technique usage | Weekly (Actions) |
| MITRE ATT&CK Campaigns | 34 named campaigns with attribution and timelines | Weekly (Actions) |
| MITRE D3FEND | Defensive countermeasure mappings per technique | Weekly (Actions) |
| MITRE CWE | Weakness definitions and parent relationships | Weekly (Actions) |
| MITRE CAPEC | Attack pattern definitions and technique mappings | Weekly (Actions) |
| OWASP Top 10 | CWE to OWASP category mappings | Bundled |
| CISA KEV | Known exploited vulnerabilities, ransomware use, remediation deadlines | Daily (Actions) |
| CISA Vulnrichment | SSVC decisions (exploit status, automatable, impact), CISA CVSS overrides | Daily (Actions) |

## Quick start

### Use the hosted site (no install)

Visit [the GitHub Pages site](https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/). All data is pre-built and updated automatically by GitHub Actions.

### Run locally

```bash
git clone https://github.com/NullSpace-BitCradle/Threat_Intelligence_Pipeline.git
cd Threat_Intelligence_Pipeline
pip install -r requirements.txt
python setup.py

# Set NVD API key (recommended; get one free at https://nvd.nist.gov/developers/request-an-api-key)
export NVD_API_KEY="your-key-here"

# Run the full pipeline
PYTHONPATH=src python run_pipeline.py

# Start local web server
PYTHONPATH=src python run_pipeline.py --web-interface --web-port 8080
```

### CLI options

```bash
PYTHONPATH=src python run_pipeline.py              # Full pipeline
PYTHONPATH=src python run_pipeline.py --db-only    # Update reference databases only
PYTHONPATH=src python run_pipeline.py --cve-only   # Process CVEs only (with resume)
PYTHONPATH=src python run_pipeline.py --force      # Force full update
PYTHONPATH=src python run_pipeline.py --status     # Show pipeline status
PYTHONPATH=src python run_pipeline.py --health-check # System health check
```

## GitHub Actions

Two automated workflows keep data fresh:

| Workflow | Schedule | What it does |
|----------|----------|--------------|
| Update Reference Databases | Daily 06:00 UTC | Downloads KEV, Vulnrichment, ATT&CK, D3FEND, CWE, CAPEC, Groups |
| Run CVE Pipeline | Weekly Sunday 08:00 UTC | Fetches new CVEs from NVD, runs full enrichment chain |

Both auto-commit results back to the repo. Requires `NVD_API_KEY` as a repository secret.

## MCP server (optional)

Expose TIP's threat intelligence graph to Claude agents via the Model Context Protocol (MCP). Claude agents can ground threat reasoning in TIP's real data instead of hallucinating CVE IDs or MITRE relationships.

**Status:** Phase A (v1 MVP) shipped 2026-04-23. Three read-only tools, plus a JSONL shard fallback added 2026-04-24:

- `lookup_entity(entity_id)`: returns a single entity record and its relationships. Falls back to scanning the per-year CVE shard for any CVE not in the enriched entity graph, so any of the 345K ingested CVEs is queryable by ID.
- `pivot_from_entity(entity_id, target_type?)`: returns entities related by type. Same shard fallback as `lookup_entity`, so pivoting from any ingested CVE works even if it is not in the enriched graph.
- `search_threat_intel(query, limit?, types?)`: returns ranked hits from the inverted index

### Install

```bash
pip install -r requirements-mcp.txt
```

Requires TIP's pre-built indexes at `docs/data/entity_index.json` and `docs/data/search_index.json`. Run the pipeline first if they are missing.

### Run

```bash
PYTHONPATH=src python -m tip_mcp.server
```

The server speaks MCP over stdio. It loads both indexes into memory, then waits for a client to connect.

### Claude Code / Claude Desktop configuration

Add an entry to your `.mcp.json`:

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

Optionally set `TIP_DATA_DIR` in `env` to override the default `docs/data/` location. Set `TIP_SHARDS_DIR` to override the default `docs/database/` shard location used by the shard fallback.

### Demo prompt

Once the client is configured:

> Use the tip threat intel tools. Look up CVE-2023-44487 and walk me through the attack chain and defenses. Cite entity IDs.

See `src/tip_mcp/README.md` for full install and tool details, and `docs/superpowers/specs/mcp-server-scope.md` for the architecture rationale.

## Architecture

### Pipeline

```
src/tip/
  core/
    pipeline_orchestrator.py  # Pipeline execution and CLI
    cve_processor.py          # CVE enrichment chain (CWE, CAPEC, technique, D3FEND, OWASP, KEV, SSVC, APT)
    database_manager.py       # Downloads and manages all data sources
    entity_index_generator.py # Builds entity_index.json and search_index.json
    campaign_fetcher.py       # MITRE ATT&CK campaigns ingestion
    owasp_processor.py        # CWE to OWASP mapping
    kev_processor.py          # CISA KEV catalog
    vulnrichment_processor.py # CISA SSVC decisions and CVSS overrides
    apt_processor.py          # ATT&CK Groups with reverse technique index
  monitoring/                 # Health checks, metrics, web server
  utils/                      # Config, error handling, rate limiting
  database/                   # JSONL file manager
src/tip_mcp/
  loader.py                   # Loads entity / search indexes; CVE shard scanner
  tools.py                    # MCP tool implementations
  server.py                   # FastMCP stdio entry point
  schema.py                   # Response envelope + error codes
```

### Web interface

```
docs/
  index.html                  # Single-page app (landing + results)
  css/
    theme.css                 # Dark and light theme variables
    app.css                   # All layout and component styles
  js/
    app.js                    # Router, search, landing page, theme, investigation
    entity-system.js          # Entity index, search, data lookup helpers
    results.js                # Result page rendering (header, tabs, summary cards)
    graph.js                  # D3 force-directed relationship graph
  data/                       # Reference databases (auto-updated)
  database/                   # CVE database by year (auto-updated)
```

## Testing

```bash
PYTHONPATH=src python -m pytest tests/ -v
PYTHONPATH=src python -m pytest tests/ --cov=src/tip
```

Current suite: 67 tests across pipeline processors and the MCP layer.

## Requirements

- Python 3.9+ (3.12 used in CI)
- NVD API key (free; recommended for rate limit performance)

## Roadmap

The full roadmap with rationale, sizing, and source plans lives in [Plans/ROADMAP.md](Plans/ROADMAP.md). Summary below.

### Done (shipped, on disk)

| Item | When | Notes |
|------|------|-------|
| Pipeline foundation (NVD, CWE, CAPEC, ATT&CK, D3FEND, JSONL shards) | pre 2026-03 | `run_pipeline.py` orchestrator with `--db-only` / `--cve-only` / `--status` / `--force` |
| KEV + Vulnrichment + APT integration | 2026-03-14 | Processors plus 24 unit tests; KEV marks 1,569 CVEs, vulnrichment covers 1,262 |
| Provenance + Campaigns (entity_index v1.5) | 2026-03-18 | Per-entity and per-relationship provenance tiers; 34 MITRE campaigns ingested; KEV moved to top-level boolean |
| Search-first UI redesign | 2026-03-28 | Replaced 6-tab Bootstrap layout with single-search SPA; D3 graph replaces Sankey; investigation pinning; hash routing |
| GitHub Actions automation | 2026-03-29 | Daily reference DB updates + weekly CVE pipeline; both auto-commit |
| MCP Phase A | 2026-04-23 | `lookup_entity`, `pivot_from_entity`, `search_threat_intel` over stdio; 25 tests |
| CVE enrichment surgery | 2026-04-24 | Removed description and name truncations; added CVSS, dates, references extraction; widened entity_index filter (1,367 to 2,766 indexed); MCP `lookup_entity` shard fallback |
| MCP `pivot_from_entity` shard fallback | 2026-04-24 | Same JSONL shard fallback pattern mirrored into pivot; extracted `_shard_rels` helper; 8 new tests |

### Next (ready to pick up)

| Priority | Item | Size | Notes |
|----------|------|------|-------|
| N1 | Verify next scheduled pipeline run populates new NVD fields in shards | small | First run after 2026-04-24 fixes is Sunday 2026-04-26 08:00 UTC |
| N2 | MCP Phase B: `build_attack_chain`, `get_defenses`, `kev_status` | medium (1 day) | Headline portfolio piece; centerpiece of Partner Network demo |
| N3 | Capture CVE-2023-44487 demo for Partner Network README | small (half day) | Depends on N2 |

### Deferred (scoped, parked behind a decision)

| Item | Why parked |
|------|------------|
| All-CVE search architecture (tiered all-IDs index plus rich graph plus on-demand shard fetch) | Largest gap. Today's filter widening was incremental (2,766 vs full 271K). Full coverage needs a tiered design to avoid breaking browser load. |
| Multi-entity analysis mode (paste a list, see combined view) | Needs design session; UX questions unresolved |
| Visual polish (graph legend, zoom, landing page enhancements, responsive tweaks) | Functional today; promote when external demo polish matters |
| Live pipeline trigger from the search bar | Not blocking; static site is the primary deployment |
| Extended export formats (CSV, ATT&CK Navigator layer JSON) | JSON export shipped; promote on user request |
| MCP `pivot_from_entities(ids)` (multi-entity pivot) | Blocked on multi-entity analysis design |

### Followup (small leftovers)

- Update or remove the prior "300-char description truncation" memory note (now obsolete after the 2026-04-24 surgery)
- Rewrite stale comment in `src/tip/core/entity_index_generator.py` line 275 (filter description no longer matches the code)
- Vertical campaign timeline UI for APT entity panels (currently shows date range only)
- Campaign external link builder (`buildExternalLink` for `campaign` type)
- Playwright smoke test for the static site (no automated UI tests today)
- Merge vulnrichment `cisaCVSS` into shard CVE.CVSS at ingest so shards carry CVSS even if `vulnrichment_db.json` rotates

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Galeax](https://github.com/Galeax) for the original design that inspired this project
- [NVD](https://nvd.nist.gov/) for CVE data
- [MITRE](https://www.mitre.org/) for ATT&CK, D3FEND, CWE, and CAPEC frameworks
- [CISA](https://www.cisa.gov/) for KEV catalog and Vulnrichment data
- [OWASP](https://owasp.org/) for Top 10 security risk categories
