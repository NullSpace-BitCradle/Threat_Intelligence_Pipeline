---
slug: 2026-04-29_cve2capec-ctibutler-integration
status: proposed
priority: HIGH
origin: PAIUpgrade 2026-04-29 findings #8 (CRITICAL) and #18 (HIGH)
related_to: 2026-04-24 CVE enrichment surgery
---

# Integration Plan: CVE2CAPEC + ctibutler for TIP CVE Enrichment

## Why this exists

The 2026-04-24 enrichment surgery built TIP's own CVE-to-ATT&CK mapping logic by scraping NVD and joining against CWE and CAPEC tables. That work is now obsolete. Two upstream feeds, both Apache-2.0 and verified to exist as of 2026-04-29:

1. **CVE2CAPEC** (Galeax/CVE2CAPEC, 290 stars, GPL-3.0). Daily-updated database via GitHub Actions (00:05 UTC). Publishes `results/new_cves.jsonl` with the full chain CVE -> CWE -> CAPEC -> MITRE ATT&CK -> MITRE D3FEND. Each CVE row gains `attack_techniques[]` and `d3fend_techniques[]`.

2. **ctibutler** (muchdogesec/ctibutler, 20 stars, Apache-2.0). Self-hostable Django plus ArangoDB API serving STIX 2.1 datasets for MITRE ATT&CK Enterprise/ICS/Mobile, CAPEC, CWE, ATLAS, Locations, DISARM. HTTP plus Swagger surface, single endpoint to query all five frameworks.

Together these obsolete the manual surgery: CVE2CAPEC supplies the per-CVE chain, ctibutler supplies the technique metadata lookup. Total cost: zero scraping, zero NVD rate limiting, zero in-house mapping logic to maintain.

## Phase 1: Replace nightly enrichment with CVE2CAPEC pull

**Target:** TIP nightly enrichment job (currently in `run_pipeline.py` or a Plans-directory cron).

**New job:**

```python
import json
import requests
from pathlib import Path
from datetime import datetime, timedelta

CVE2CAPEC_RAW = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/master/results/new_cves.jsonl"

def fetch_today_cves(out_path: Path) -> list[dict]:
    """Pull yesterday-onwards CVEs from CVE2CAPEC nightly publish."""
    resp = requests.get(CVE2CAPEC_RAW, timeout=60)
    resp.raise_for_status()
    rows = []
    cutoff = datetime.utcnow() - timedelta(days=2)
    for line in resp.text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        published = datetime.fromisoformat(row.get("publishedDate", "1970-01-01"))
        if published >= cutoff:
            rows.append(row)
    out_path.write_text("\n".join(json.dumps(r) for r in rows))
    return rows
```

**Join into existing TIP enrichment:**

```python
# In existing enrichment loop, replace the manual ATT&CK lookup with:
def enrich_cve_with_chain(cve_row, cve2capec_index):
    chain = cve2capec_index.get(cve_row["id"], {})
    cve_row["attack_techniques"] = chain.get("attack_techniques", [])
    cve_row["d3fend_techniques"] = chain.get("d3fend_techniques", [])
    cve_row["capec_ids"] = chain.get("capec", [])
    cve_row["cwe_ids"] = chain.get("cwe", [])
    return cve_row
```

**Deliverable:** TIP rows now carry the four-framework chain without TIP code maintaining it.

**Validation:**
- Diff a representative day's enriched output against the 2026-04-24 surgery output. Coverage should match or exceed; mismatches are usually because CVE2CAPEC has more recent CWE-to-CAPEC links than the surgery captured.
- Spot-check 5 CVEs against MITRE's published mapping to confirm no fabricated techniques.

## Phase 2: Stand up ctibutler for technique-detail lookup

**Target:** Replace ad-hoc MITRE GitHub raw fetches in TIP report rendering.

**Setup:**

```bash
git clone https://github.com/muchdogesec/ctibutler ~/Projects/ctibutler
cd ~/Projects/ctibutler
docker compose up -d
# default port: 8000
curl http://localhost:8000/api/v1/attack/objects/ | head
```

**TIP integration:**

```python
CTIBUTLER_BASE = "http://localhost:8000/api/v1"

def get_technique_detail(technique_id: str) -> dict:
    """Fetch MITRE ATT&CK technique detail via ctibutler."""
    resp = requests.get(f"{CTIBUTLER_BASE}/attack/objects/{technique_id}/", timeout=30)
    resp.raise_for_status()
    return resp.json()

def get_d3fend_countermeasure(d3fend_id: str) -> dict:
    """Fetch D3FEND countermeasure detail via ctibutler."""
    resp = requests.get(f"{CTIBUTLER_BASE}/d3fend/objects/{d3fend_id}/", timeout=30)
    resp.raise_for_status()
    return resp.json()
```

**Deliverable:** TIP reports gain technique descriptions, kill-chain phases, and detection guidance without external HTTP-to-GitHub-raw on every render.

## Phase 3: Wrap as ctibutler-mcp for PAI consumption

**Target:** Expose ctibutler as a PAI MCP server alongside cve-mcp.

```python
# ~/Projects/ctibutler-mcp/server.py
from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("ctibutler")
BASE = "http://localhost:8000/api/v1"

@mcp.tool()
def search_attack_technique(technique_id: str) -> dict:
    """Look up a MITRE ATT&CK technique by ID (e.g., T1059)."""
    return requests.get(f"{BASE}/attack/objects/{technique_id}/").json()

@mcp.tool()
def search_capec(capec_id: str) -> dict:
    """Look up a CAPEC entry by ID."""
    return requests.get(f"{BASE}/capec/objects/{capec_id}/").json()

@mcp.tool()
def list_atlas_techniques() -> list:
    """List MITRE ATLAS techniques (AI/ML adversary tactics)."""
    return requests.get(f"{BASE}/atlas/objects/").json()
```

Register in `~/.claude/settings.json` mcpServers alongside cve-mcp:

```json
"ctibutler-mcp": {
  "command": "uv",
  "args": ["--directory", "/home/d1881b/Projects/ctibutler-mcp", "run", "python", "-m", "ctibutler_mcp.server"],
  "alwaysLoad": true
}
```

**Deliverable:** PAI's weekly cybersec LinkedIn workflow and triage skills gain a sovereign STIX query surface without depending on external API uptime.

## Out of scope for this plan

- Do NOT migrate the 2026-04-24 surgery code to call ctibutler. Delete it instead once Phase 1 is validated.
- Do NOT add CVE2CAPEC as a git submodule; pull the JSONL each run.
- Do NOT attempt to consume CVE2CAPEC's raw repo via clone (622MB). Stream the JSONL only.

## Risk and rollback

- CVE2CAPEC GitHub Actions could fail. Cache the last-good JSONL locally; alert when staleness exceeds 36 hours.
- ctibutler ArangoDB volume disk usage: monitor; budget 5GB.
- License interaction: CVE2CAPEC is GPL-3.0. PAI consumption is fine because we are not redistributing CVE2CAPEC code, only consuming its public output. ctibutler is Apache-2.0, no constraint.

## Cross-references

- 2026-04-24 enrichment surgery (this work obsoletes it; migration target).
- PAIUpgrade 2026-04-29 round1-findings.json indices #8 and #18.
- Anthropic-Cybersecurity-Skills (mukul975) integration sketch (separate doc): the 754-skill cross-walk uses the same ATT&CK technique IDs ctibutler would expose.

## Owner

the maintainer. Phased manually; not auto-scheduled. Recommended order: Phase 1 first (low-risk drop-in), validate against 7 days of TIP output, then Phase 2 (docker compose addition), then Phase 3 (MCP wrapper).
