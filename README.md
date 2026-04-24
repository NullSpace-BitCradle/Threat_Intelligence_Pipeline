# Threat Intelligence Pipeline (TIP)

> **A note from the author:** I'm not a developer by trade -- I'm a hybrid IT and cybersecurity professional who enjoys tinkering, learning, and building useful things along the way. This project is under active development and may break from time to time as I experiment and improve it. Once I'm confident everything is working reliably, I'll remove this notice.

A search-first threat intelligence tool that correlates CVEs across 8 security frameworks. Search any CVE, technique, APT group, or weakness and instantly see its relationships -- attack patterns, defensive countermeasures, threat actors, CISA KEV status, and more.

**Live demo:** [nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline](https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/)

![Landing Page](docs/images/landing.png)

![APT Group Result](docs/images/result-apt.png)

![CVE Result](docs/images/result-cve.png)

## How It Works

Search for any entity and TIP shows you its complete threat intelligence picture:

- **CVEs** -- weakness mappings, attack patterns, techniques, defensive measures, KEV status, SSVC risk, APT attribution
- **ATT&CK Techniques** -- associated CVEs, APT groups that use them, D3FEND countermeasures
- **APT Groups** -- aliases, descriptions, technique usage, linked CVEs and campaigns
- **CWEs** -- parent chain, related attack patterns, OWASP categories
- **Campaigns** -- attribution, timelines, technique usage

The pipeline builds the correlation chain automatically:

```
CVE -> CWE -> CAPEC -> ATT&CK Techniques -> D3FEND Countermeasures
                                          -> APT Groups (reverse lookup)
    -> OWASP Top 10 Category
    -> CISA KEV Status + Ransomware Use
    -> CISA SSVC Decision + CVSS Override
```

## Web Interface

Search-first design with two views:

**Landing page** -- one search bar across all entity types, database stats, and quick-access cards for recent KEV additions.

**Result page** -- split layout with an intelligence brief on the left (entity header, badges, summary cards, tabbed framework detail) and a D3 force-directed relationship graph on the right showing how the entity connects across frameworks.

Features:
- Search by ID (`CVE-2024-37079`, `T1059`, `CWE-79`) or name (`APT29`, `Log4Shell`)
- Overview tab with descriptions, aliases, KEV details, and data provenance
- Framework tabs: ATT&CK, D3FEND, APT Groups, OWASP, CWE, CAPEC, KEV Detail
- Interactive relationship graph -- click any node to navigate
- Investigation pinning with JSON export
- Dark/light theme
- Hash-based routing with shareable URLs and browser back/forward
- Static GitHub Pages deployment -- zero install required

## Data Sources

| Source | What It Provides | Update Frequency |
|--------|-----------------|-----------------|
| NVD API 2.0 | CVE records, CVSS scores, CWE assignments | Weekly (Actions) |
| MITRE ATT&CK | Attack techniques (enterprise, mobile, ICS) | Weekly (Actions) |
| MITRE ATT&CK Groups | 176 threat groups with aliases and technique usage | Weekly (Actions) |
| MITRE ATT&CK Campaigns | 34 named campaigns with attribution and timelines | Weekly (Actions) |
| MITRE D3FEND | Defensive countermeasure mappings per technique | Weekly (Actions) |
| MITRE CWE | Weakness definitions and parent relationships | Weekly (Actions) |
| MITRE CAPEC | Attack pattern definitions and technique mappings | Weekly (Actions) |
| OWASP Top 10 | CWE-to-OWASP category mappings | Bundled |
| CISA KEV | Known exploited vulnerabilities, ransomware use, remediation deadlines | Daily (Actions) |
| CISA Vulnrichment | SSVC decisions (exploit status, automatable, impact), CISA CVSS overrides | Daily (Actions) |

## Quick Start

### Use the hosted site (no install)

Visit [the GitHub Pages site](https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/) -- all data is pre-built and updated automatically by GitHub Actions.

### Run locally

```bash
git clone https://github.com/NullSpace-BitCradle/Threat_Intelligence_Pipeline.git
cd Threat_Intelligence_Pipeline
pip install -r requirements.txt
python setup.py

# Set NVD API key (recommended, get one free at https://nvd.nist.gov/developers/request-an-api-key)
export NVD_API_KEY="your-key-here"

# Run the full pipeline
PYTHONPATH=src python run_pipeline.py

# Start local web server
PYTHONPATH=src python run_pipeline.py --web-interface --web-port 8080
```

### CLI Options

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

| Workflow | Schedule | What It Does |
|----------|----------|-------------|
| Update Reference Databases | Daily 06:00 UTC | Downloads KEV, Vulnrichment, ATT&CK, D3FEND, CWE, CAPEC, Groups |
| Run CVE Pipeline | Weekly Sunday 08:00 UTC | Fetches new CVEs from NVD, runs full enrichment chain |

Both auto-commit results back to the repo. Requires `NVD_API_KEY` as a repository secret.

## MCP Server (optional)

Expose TIP's threat intelligence graph to Claude agents via the Model Context Protocol (MCP). Claude agents can ground threat reasoning in TIP's real data instead of hallucinating CVE IDs or MITRE relationships.

**Status:** Phase A (v1 MVP) shipped. Three read-only tools:

- `lookup_entity(entity_id)` returns a single entity record and its relationships
- `pivot_from_entity(entity_id, target_type?)` returns entities related by type
- `search_threat_intel(query, limit?, types?)` returns ranked hits from the inverted index

### Install

```bash
pip install -r requirements-mcp.txt
```

Requires TIP's pre-built indexes at `docs/data/entity_index.json` and `docs/data/search_index.json`. Run the pipeline first if they are missing.

### Run

```bash
PYTHONPATH=src python -m tip_mcp.server
```

The server speaks MCP over stdio; it loads both indexes into memory, then waits for a client to connect.

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

Optionally set `TIP_DATA_DIR` in `env` to override the default `docs/data/` location.

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
    cve_processor.py          # 8-step CVE enrichment chain
    database_manager.py       # Downloads and manages all data sources
    owasp_processor.py        # CWE-to-OWASP mapping
    kev_processor.py          # CISA KEV catalog
    vulnrichment_processor.py # CISA SSVC decisions
    apt_processor.py          # ATT&CK Groups with reverse technique index
  monitoring/                 # Health checks, metrics, web server
  utils/                      # Config, error handling, rate limiting
  database/                   # JSONL file manager
```

### Web Interface

```
docs/
  index.html                  # Single-page app (landing + results)
  css/
    theme.css                 # Dark/light theme variables
    app.css                   # All layout and component styles
  js/
    app.js                    # Router, search, landing page, theme, investigation
    entity-system.js          # Entity index, search, data lookup helpers
    results.js                # Result page rendering (header, tabs, overview)
    graph.js                  # D3 force-directed relationship graph
  data/                       # Reference databases (auto-updated)
  database/                   # CVE database by year (auto-updated)
```

## Testing

```bash
PYTHONPATH=src python -m pytest tests/ -v
PYTHONPATH=src python -m pytest tests/ --cov=src/tip
```

## Requirements

- Python 3.9+
- NVD API key (free, recommended for rate limit performance)

## Roadmap

### TIP core

1. **All-CVE search architecture.** Currently indexes only the 1,351 CVEs with CWE mappings. Extend to cover all CVEs via a tiered approach (entity index for rich CVEs, search index for all IDs, on-demand JSONL lookup for detail).
2. **Multi-entity analysis mode.** Paste multiple CVEs or entity IDs, see a combined relationship view.
3. **Visual polish.** Graph legend, zoom, landing page enhancements, responsive tweaks.

### MCP server

Phase A shipped: `lookup_entity`, `pivot_from_entity`, `search_threat_intel`.

- **Phase B.** Add `build_attack_chain`, `get_defenses`, `kev_status`. Extend pytest coverage. Polish error handling and pagination.
- **Phase C.** JSONL shard fallback for non-indexed CVEs (depends on TIP roadmap #1). Multi-entity pivot tool (depends on TIP roadmap #2).

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Galeax](https://github.com/Galeax) for the original design that inspired this project
- [NVD](https://nvd.nist.gov/) for CVE data
- [MITRE](https://www.mitre.org/) for ATT&CK, D3FEND, CWE, and CAPEC frameworks
- [CISA](https://www.cisa.gov/) for KEV catalog and Vulnrichment data
- [OWASP](https://owasp.org/) for Top 10 security risk categories
