# Threat Intelligence Pipeline (TIP)

> **A note from the author:** I'm not a developer by trade -- I'm a hybrid IT and cybersecurity professional who enjoys tinkering, learning, and building useful things along the way. This project is under active development and may break from time to time as I experiment and improve it. Once I'm confident everything is working reliably, I'll remove this notice.

Correlates CVEs across 8 security frameworks in one automated pipeline. Enter a CVE and instantly see its weakness (CWE), attack patterns (CAPEC), attack techniques (ATT&CK), defensive measures (D3FEND), OWASP category, CISA KEV status, SSVC risk decision, and associated APT groups.

**Live demo:** [nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline](https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/)

## What It Does

Given a CVE, the pipeline builds the complete correlation chain:

```
CVE -> CWE -> CAPEC -> ATT&CK Techniques -> D3FEND Countermeasures
                                          -> APT Groups (reverse lookup)
    -> OWASP Top 10 Category
    -> CISA KEV Status + Ransomware Use
    -> CISA SSVC Decision + CVSS Override
```

![CVE Data Flow](docs/images/CVE_Data_Flow.png)

## Data Sources

| Source | What It Provides | Update |
|--------|-----------------|--------|
| NVD API 2.0 | CVE records, CVSS scores, CWE assignments | Weekly (Actions) |
| MITRE ATT&CK | Attack techniques, threat groups with aliases | Weekly (Actions) |
| MITRE D3FEND | Defensive countermeasures per technique | Weekly (Actions) |
| MITRE CWE/CAPEC | Weakness definitions, attack pattern mappings | Weekly (Actions) |
| OWASP Top 10 | CWE-to-OWASP category mappings | Bundled |
| CISA KEV | Known exploited vulnerabilities, ransomware use, remediation deadlines | Daily (Actions) |
| CISA Vulnrichment | SSVC decisions (exploit status, automatable, impact), CISA CVSS | Daily (Actions) |
| ATT&CK Groups | 176 threat groups with aliases and technique usage | Weekly (Actions) |

## Web Interface

Dark/light theme with 6 views:

- **Analysis** -- Enter CVEs, generate Sankey flow diagram, see summary cards (KEV status, APT groups, OWASP categories)
- **CISA KEV** -- Searchable table of all known exploited vulnerabilities with ransomware flags
- **APT Groups** -- Browsable card grid of 176 threat groups with aliases and technique counts
- **ATT&CK** -- Interactive MITRE ATT&CK Navigator matrix
- **D3FEND** -- Defensive technique mappings from analysis
- **OWASP** -- Top 10 category breakdown with CVE counts

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
PYTHONPATH=src python run_pipeline.py --force       # Force full update
PYTHONPATH=src python run_pipeline.py --status      # Show pipeline status
PYTHONPATH=src python run_pipeline.py --health-check # System health check
```

## GitHub Actions

Two automated workflows keep data fresh:

| Workflow | Schedule | What It Does |
|----------|----------|-------------|
| Update Reference Databases | Daily 06:00 UTC | Downloads KEV, Vulnrichment, ATT&CK, D3FEND, CWE, CAPEC, Groups |
| Run CVE Pipeline | Weekly Sunday 08:00 UTC | Fetches new CVEs from NVD, runs full enrichment chain |

Both auto-commit results back to the repo. Requires `NVD_API_KEY` as a repository secret.

## Requirements

- Python 3.9+
- NVD API key (free, recommended for performance)

## Architecture

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
docs/
  index.html                  # Web interface
  css/theme.css               # Dark/light theme system
  js/tip-views.js             # Navigation, KEV/APT views
  js/global.js                # CVE analysis, Sankey diagram
  data/                       # Reference databases (auto-updated)
  database/                   # CVE database by year (auto-updated)
  mitre/                      # ATT&CK Navigator (embedded)
```

## Testing

```bash
# Run all tests (24 tests)
PYTHONPATH=src python -m pytest tests/ -v

# With coverage
PYTHONPATH=src python -m pytest tests/ --cov=src/tip
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Galeax](https://github.com/Galeax) for the original design that inspired this project
- [NVD](https://nvd.nist.gov/) for CVE data
- [MITRE](https://www.mitre.org/) for ATT&CK, D3FEND, CWE, and CAPEC frameworks
- [CISA](https://www.cisa.gov/) for KEV catalog and Vulnrichment data
- [OWASP](https://owasp.org/) for Top 10 security risk categories
