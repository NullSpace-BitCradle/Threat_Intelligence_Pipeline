# TIP v2.0 Redesign Spec

## Problem

The Threat Intelligence Pipeline correlates CVEs across five security frameworks (CWE, CAPEC, OWASP, ATT&CK, D3FEND) but lacks integration with CISA's operational intelligence (KEV, Vulnrichment), has no APT attribution, requires local Python execution to use, and has a dated UI.

## Goals

1. Integrate CISA KEV and Vulnrichment data into the enrichment pipeline
2. Add APT group attribution via MITRE ATT&CK Groups dataset
3. Automate data freshness via GitHub Actions
4. Redesign the web interface with modern dark/light theming and top-nav tab layout
5. Deploy as a static GitHub Pages site (zero-install access) while preserving local server mode

## Non-Goals

- Real-time streaming threat feeds (Mandiant, VirusTotal, etc.)
- User accounts or authentication
- Custom vulnerability databases beyond NVD
- Mobile-native app

## Data Architecture

### Sources

| Source | URL / Method | Data Provided | Update Frequency |
|--------|-------------|---------------|-----------------|
| NVD API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0/` | CVE records, NVD CVSS, CWE assignments | Weekly (Actions) |
| MITRE ATT&CK | XLSX downloads from `attack.mitre.org` | Techniques (Enterprise, Mobile, ICS) | Weekly (Actions) |
| MITRE ATT&CK Groups | STIX bundle from `attack.mitre.org` | Threat groups, aliases, technique usage | Weekly (Actions) |
| MITRE D3FEND | `d3fend.mitre.org/api/` | Defensive technique mappings | Weekly (Actions) |
| CISA KEV | `raw.githubusercontent.com/cisagov/kev-data` | Known exploited vulns catalog | Daily (Actions) |
| CISA Vulnrichment | `github.com/cisagov/vulnrichment` (per-CVE JSONs) | SSVC decisions, CISA CVSS overrides | Daily (Actions) |
| MITRE CWE | `cwe.mitre.org/data/xml/cwec_latest.xml.zip` | Weakness definitions, parent relationships | Weekly (Actions) |
| MITRE CAPEC | `capec.mitre.org/data/csv/1000.csv.zip` | Attack patterns, technique mappings | Weekly (Actions) |
| OWASP Top 10 | CWE-1344 mappings (bundled) | CWE-to-OWASP category mappings | Static (bundled) |

### Enriched CVE Record Schema

Each processed CVE produces this structure, stored in `database/CVE-{year}.jsonl`:

```json
{
  "CVE-2024-XXXXX": {
    "CWE": ["CWE-22", "CWE-23"],
    "CAPEC": ["CAPEC-126"],
    "TECHNIQUES": ["T1083", "T1005"],
    "DEFEND": [
      {"id": "D3-FA", "name": "File Analysis", "relationship": "detect"}
    ],
    "OWASP": ["A01:2021"],
    "KEV": {
      "inKEV": true,
      "dateAdded": "2024-06-15",
      "dueDate": "2024-07-06",
      "knownRansomwareCampaignUse": "Known",
      "requiredAction": "Apply vendor patch",
      "vendorProject": "Apache",
      "product": "HTTP Server"
    },
    "VULNRICHMENT": {
      "ssvcExploitStatus": "active",
      "ssvcAutomatable": "yes",
      "ssvcTechnicalImpact": "total",
      "cisaCVSS": {
        "baseScore": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      }
    },
    "APT_GROUPS": [
      {
        "id": "G0016",
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM"],
        "techniques_overlap": ["T1083"]
      }
    ]
  }
}
```

**Schema consistency rules:**
- Existing fields (`CWE`, `CAPEC`, `TECHNIQUES`, `DEFEND`) always present, using empty lists `[]` when no data exists (matches current cve_processor.py behavior).
- New fields (`KEV`, `VULNRICHMENT`, `APT_GROUPS`) are omitted entirely when not applicable (no empty objects/arrays). This distinction is intentional: existing fields are always populated because the pipeline always attempts the lookup; new fields are only present when a match is found in the external dataset.
- The UI must handle both patterns: check for key existence before accessing new fields, and check for empty arrays on existing fields.

### Resource Files

Stored in `resources/`, committed to the repo:

| File | Content | Approximate Size |
|------|---------|-----------------|
| `capec_db.json` | CAPEC attack patterns with technique mappings | ~2 MB |
| `cwe_db.json` | CWE weaknesses with parent relationships | ~3 MB |
| `techniques_db.json` | ATT&CK techniques (enterprise, mobile, ICS) | ~1 MB |
| `defend_db.jsonl` | D3FEND defensive techniques | ~500 KB |
| `owasp_db.json` | CWE-to-OWASP Top 10 mappings | ~50 KB |
| `kev_db.json` | CISA KEV catalog | ~2 MB |
| `vulnrichment_db.json` | SSVC decisions and CISA CVSS indexed by CVE ID | ~20-50 MB |
| `groups_db.json` | ATT&CK groups with aliases and technique usage | ~500 KB |

### Database Files

Stored in `database/`, committed to the repo:

| Files | Content | Approximate Total Size |
|-------|---------|----------------------|
| `CVE-{1999..2025}.jsonl` | Processed CVE records (enriched) | ~130 MB |

## Pipeline Architecture

### New Processors

#### KEV Processor (`src/tip/core/kev_processor.py`)

- Downloads `known_exploited_vulnerabilities.json` from cisagov/kev-data
- Indexes by CVE ID for O(1) lookup during enrichment
- Stores processed data as `resources/kev_db.json`
- Enrichment: during CVE processing, looks up each CVE ID and attaches KEV metadata if present

#### Vulnrichment Processor (`src/tip/core/vulnrichment_processor.py`)

- **Primary method (incremental):** Uses the GitHub Git Trees API to list files changed since the last processed commit SHA. Fetches only new/modified CVE JSONs via the Contents API. Stores last-processed SHA in `resources/vulnrichment_state.json`.
- **Bootstrap method (first run):** If no state file exists, performs a shallow clone (`git clone --depth=1`) of cisagov/vulnrichment (~500 MB), processes all CVE JSONs, then deletes the clone. Records the HEAD SHA in state file for future incremental updates.
- Extracts SSVC decisions (exploit status, automatable, technical impact) and CISA CVSS from each per-CVE JSON file
- Stores indexed data as `resources/vulnrichment_db.json` (CVE ID -> SSVC + CVSS)
- Enrichment: during CVE processing, attaches SSVC decision and CISA CVSS if present
- **Size note:** If `vulnrichment_db.json` exceeds 50 MB, switch to Git LFS for that file. Validate actual size during implementation of sub-project #1.

#### APT Group Processor (`src/tip/core/apt_processor.py`)

- Downloads the ATT&CK STIX Groups bundle from `mitre-attack/attack-stix-data` on GitHub (~3-4 MB), not the full enterprise bundle (~90 MB)
- Extracts group names, aliases (from `x_mitre_aliases`), descriptions, and `uses` relationships linking groups to techniques
- Builds a reverse index: technique ID -> list of groups that use it
- Stores as `resources/groups_db.json`
- Enrichment: during CVE processing, reverse-lookups techniques to find groups that use them. A CVE that maps to T1083 will show APT groups known to use T1083.

### Modified Processor

#### CVE Processor (`src/tip/core/cve_processor.py`)

Extended `process_cve_pipeline` method adds three new enrichment steps after existing steps:

```
Step 1: CVE -> CWE (existing)
Step 2: CWE -> CAPEC (existing)
Step 3: CAPEC -> ATT&CK Techniques (existing)
Step 4: ATT&CK Techniques -> D3FEND (existing)
Step 5: CWE -> OWASP Top 10 (existing)
Step 6: CVE -> KEV lookup (NEW)
Step 7: CVE -> Vulnrichment SSVC + CVSS (NEW)
Step 8: Techniques -> APT Groups reverse lookup (NEW)
```

#### Database Manager (`src/tip/core/database_manager.py`)

Extended to download and manage three new data sources (KEV, Vulnrichment, Groups) alongside existing ones.

## GitHub Actions

### Workflow 1: `update-databases.yml` (daily, 06:00 UTC)

Downloads fresh reference databases. The `--db-only` flag triggers all database processors including the three new ones (KEV, Vulnrichment, Groups). Config.json will need new `database` entries for `kev`, `vulnrichment`, and `groups` following the existing pattern.

```yaml
name: Update Reference Databases
on:
  schedule:
    - cron: '0 6 * * *'
  workflow_dispatch:

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          persist-credentials: true

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - run: pip install -r requirements.txt

      - run: python run_pipeline.py --db-only

      - name: Commit and push if changed
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add resources/
          git diff --cached --quiet || git commit -m "chore: update reference databases [skip ci]" && git push
```

### Workflow 2: `run-pipeline.yml` (weekly, Sunday 08:00 UTC)

Runs incremental CVE pipeline (fetches CVEs modified since last update, not full re-fetch). The `--force` flag in Actions context uses `lastUpdate.txt` to determine the date range, ensuring only new/modified CVEs are fetched. A full re-fetch from 1999 only happens on first run or when `lastUpdate.txt` is absent.

```yaml
name: Run CVE Pipeline
on:
  schedule:
    - cron: '0 8 * * 0'
  workflow_dispatch:

jobs:
  pipeline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          persist-credentials: true

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - run: pip install -r requirements.txt

      - name: Run pipeline
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: python run_pipeline.py --force

      - name: Commit and push if changed
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add database/ resources/ lastUpdate.txt
          git diff --cached --quiet || git commit -m "chore: update CVE database [skip ci]" && git push
```

The NVD API key is stored as a GitHub repository secret named `NVD_API_KEY`.

### Cost

- Public repo: unlimited Actions minutes (free tier)
- Daily workflow: ~8-12 min/run (Vulnrichment incremental update is the heaviest part) = ~300 min/month
- Weekly workflow: ~15 min/run (incremental CVE fetch) = ~60 min/month
- First weekly run (bootstrap, no lastUpdate.txt): ~30-45 min (full CVE fetch from 1999)
- Total steady-state: ~360 min/month, well within free tier

## Web Interface

### Technology

- Vanilla HTML, CSS, JavaScript (no build step, no framework)
- CSS custom properties for dark/light theming
- ECharts for Sankey diagrams and charts
- Existing MITRE ATT&CK Navigator (in `docs/mitre/`) retained
- All data loaded from pre-built JSON files (static-capable)

### Theme System

CSS variables define all colors. A `data-theme` attribute on `<html>` switches between dark and light:

```css
[data-theme="dark"] {
  --bg-primary: #0d1117;
  --bg-secondary: #161b22;
  --text-primary: #c9d1d9;
  --border: #30363d;
  --accent: #58a6ff;
  /* severity colors, etc. */
}

[data-theme="light"] {
  --bg-primary: #ffffff;
  --bg-secondary: #f6f8fa;
  --text-primary: #1f2937;
  --border: #e5e7eb;
  --accent: #1e40af;
}
```

Default: dark. Toggle persisted to localStorage.

### Layout

Top navigation bar with 6 tabs. Theme toggle in the nav. CVE input area is part of the Analysis tab (not persistent across tabs).

### Views

#### 1. Analysis (Home)

- CVE input area (text input, paste list, "Try an example" button)
- Generate button with matrix type selector
- Results section (appears after generation):
  - Summary cards row: severity, KEV status, SSVC decision, APT groups, OWASP categories
  - Sankey diagram (CVE -> CWE -> CAPEC -> Technique -> D3FEND, with OWASP nodes)
  - Detailed results table (expandable per-CVE rows)

#### 2. CISA KEV

- Searchable/filterable table of all KEV entries
- Columns: CVE ID, Vendor, Product, Vulnerability Name, Date Added, Due Date, Ransomware Use
- Filters: vendor, date range, ransomware flag
- Click a CVE to see its full enrichment (links to Analysis view)
- Summary stats at top: total KEV count, % with ransomware use, overdue count

#### 3. APT Groups

- Browsable grid/list of all ATT&CK groups
- Each group card: name, aliases, description, technique count
- Click a group to see its techniques mapped on ATT&CK matrix
- Reverse lookup: search by CVE to see which groups are associated via technique overlap
- Search by group name or alias

#### 4. ATT&CK Matrix

- Existing MITRE ATT&CK Navigator (refined, themed to match)
- Loaded from analysis results or browsable standalone

#### 5. D3FEND

- Existing D3FEND visualization (refined, themed to match)
- Shows defensive techniques mapped from analysis

#### 6. OWASP Top 10

- Existing OWASP category cards (refined, themed to match)
- Shows category breakdown from analysis

### Static vs Local Server Mode

**Static (GitHub Pages):**
- All views work by loading pre-built JSON from `resources/` and `database/`
- CVE analysis queries against local JSON files (client-side search)
- No server required
- URL: `https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/`

**Local server (`python run_pipeline.py --web-interface`):**
- Same UI, but adds API endpoints for live pipeline execution
- Can trigger pipeline runs, fetch fresh CVEs, update databases on demand
- Serves same static files plus REST API

**Mode detection:** The UI defaults to static mode (all API-dependent features hidden). On page load, a single probe request to `/health` fires with a 500ms timeout and no retry. If it succeeds, the UI unlocks local server features (run pipeline button, fetch CVEs, update databases). If it fails or times out, the UI stays in static mode with no visual flicker.

**CORS is a non-issue:** In local server mode, the Python server serves the UI files directly (same origin). Users don't mix GitHub Pages URLs with local API calls. The static GitHub Pages site is fully self-contained with no API calls.

## Cleanup

Items to address during the redesign:

- Remove Google Analytics tag (`G-NCCFW6FDGQ`) from original author
- Change `lang="fr"` to `lang="en"` in HTML
- Add `.superpowers/` to `.gitignore`
- Update README to reflect v2.0 features and architecture

## Sub-Projects (Implementation Order)

| # | Sub-Project | Scope | Dependencies | Estimated Effort |
|---|------------|-------|-------------|-----------------|
| 1 | KEV + Vulnrichment pipeline integration | New processors, CVE processor extension, database manager extension | None | Medium |
| 2 | APT Groups pipeline integration | New processor, CVE processor extension, STIX parsing | None | Medium |
| 3 | GitHub Actions automation | Two workflow files, repo secrets setup | #1, #2 | Low |
| 4 | UI redesign | Dark/light theme, top nav, 6 views, all visualizations | #1, #2 (needs data) | High |
| 5 | GitHub Pages deployment | Pages config, static mode detection, deployment workflow | #4 | Low |

Sub-projects 1 and 2 can be built in parallel. Each sub-project gets its own implementation plan.

## Success Criteria

- Pipeline enriches CVEs with KEV status, SSVC decisions, and APT attribution
- GitHub Actions keeps all data sources fresh (daily/weekly)
- Web interface works as a static GitHub Pages site with zero installation
- Dark/light theme toggle works across all views
- Users can clone the repo and have fully current, pre-processed data
- Local server mode provides additional live pipeline execution features
