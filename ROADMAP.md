# Roadmap

The development plan with rationale, sizing, and acceptance criteria lives in [Plans/MASTER_PLAN.md](Plans/MASTER_PLAN.md). Summary below.

## Shipped

| Item | When | Notes |
|------|------|-------|
| Pipeline foundation (NVD, CWE, CAPEC, ATT&CK, D3FEND, JSONL shards) | pre 2026-03 | `run_pipeline.py` orchestrator with resume support |
| KEV + Vulnrichment + APT integration | 2026-03-14 | Three processors plus unit tests |
| Provenance + Campaigns | 2026-03-18 | Per-entity and per-relationship provenance tiers; 34 MITRE campaigns |
| Search-first UI redesign | 2026-03-28 | Single-search SPA, D3 relationship graph, investigation pinning, hash routing |
| GitHub Actions automation | 2026-03-29 | Daily reference DB updates + weekly CVE pipeline; both auto-commit |
| MCP Phase A | 2026-04-23 | `lookup_entity`, `pivot_from_entity`, `search_threat_intel` over stdio |
| CVE enrichment surgery | 2026-04-24 | Full descriptions, CVSS, dates, references in shards; MCP shard fallback |
| All-CVE tiered search | 2026-04-24 | Every ingested CVE searchable by ID and openable as a detail page |
| P9 stabilization | 2026-06-09 | Pipeline verified healthy, Playwright smoke suite + CI gating, master plan landed |
| CVSS long-tail backfill | 2026-06-11 | 75,945 historical CVEs gained CVSS via one-time NVD pass; processor fallback chain extended v4.0 through v2 |
| Always-latest MITRE sources | 2026-06-11 | ATT&CK STIX de-pinned (was frozen at v16.1); techniques refreshed to v19.1; dead XLSX config removed; CodeQL alerts at zero |
| Enrichment direction decided | 2026-06-11 | CVE2CAPEC adoption rejected (P11 closed); enrichment stays in-house; CWE-gap closure tracked as I21 |
| P9.5 surface-gap closure | 2026-06-20 | MCP now passes full KEV/SSVC/CVSS/D3FEND detail (I22); schema-driven shared contract `tip_intel.cve_blocks` with cross-seam parity test (I24); web triage badges + clickable references (I23); worklist/triage mode (I28); graph node-label and `/health` 404 fixes (I25/I26) |
| P9.6 review remediation | 2026-09-26 | Fail-closed writes, honest exit codes, atomic writes, zero dangling rels, MCP on `mcp` 2.x, frontend hardening, pinned CI, dead code removed; PR #1 |
| P10 MCP Phase B | 2026-09-26 | `build_attack_chain`, `get_defenses`, `kev_status` complete the six-tool Phase B surface; project `.mcp.json`; recorded CVE-2023-44487 demo in `src/tip_mcp/DEMO.md`; PR #4 |
| I29 assigned vs inherited CWEs | 2026-09-27 | NVD-assigned CWEs kept apart from one level of inherited parents across shards, index, site, and MCP; CWE-1000 pillars never inherited; PR #5 |
| I1 EPSS | 2026-09-27 | Fail-closed bulk processor; daily curated-tier file, weekly shard enrichment with score date and model; site badge and worklist column; MCP `epss` block; the full daily set is never committed; PR #8 |
| I16 failure alerting and freshness | 2026-09-27 | `docs/data/freshness.json` advances per source only on a fresh success; "Data as of" on every page with a stale banner; `pipeline-failure` and `pipeline-stale` issues that close on recovery; PR #10 |
| I21 technique coverage | 2026-09-27 | MITRE CTID KEV mappings (official) and one technique inferred from the CVSS vector (inferred), each link labeled by source and tier; PR #11 |
| I7, I8 watchlists and what changed | 2026-09-27 | 30-day change event log (`docs/data/changes.json.gz`), watch toggles, `#/watching`, `#/changes`, and MCP `recent_changes`; PR #12 |
| T15.1 change log slack | 2026-09-27 | Addition slack lowered from 500 to 250 records, so a recovery from a suppressed shrink no longer reads as hundreds of new KEV entries; PR #14 |
| T10.7 MCP demo recapture | 2026-09-27 | `src/tip_mcp/DEMO.md` recaptured on the first weekly data with I29 and EPSS shards (PR #15), then again on the attributed data after I32; `mcp_demo.py --check` matches today's data |
| I30, I32 APT links by ATT&CK citation | 2026-09-27 | A CVE links to a group only where the enterprise ATT&CK bundle cites it, each link official with its citing object; technique-overlap linking removed; first run: 199 pairs, 118 CVEs, 74 groups, curated 1,728 to 1,734; PR #16 |
| T16.1 refused attributions write fails the run | 2026-09-27 | A `groups_db.json` write refused by the attribution collapse guard is a failed step: the run exits non-zero, publishes nothing, and opens the `pipeline-failure` issue; PR #18 |
| I31 remove vendored ATT&CK Navigator | 2026-09-27 | The unused Navigator 5.1.0 copy (16 MB, 139 files) under `docs/` deleted; it was served outside the site CSP and shared the watchlist's `localStorage`; PR #19 |

## Next

| ID | Item | Notes |
|-------|------|-------|
| T10.8 | Cross-vendor (Forge/GPT) audit of P10 and I29 | Required before any Partner Network demo; blocked until 2026-09-29 by the free Codex quota |

## Later

| Phase | Item | Notes |
|-------|------|-------|
| P13 | UI, exports, and worklist follow-ups | CSV export from pinning (T13.3), ATT&CK Navigator layer export (T13.4), visual polish: graph legend, zoom and pan, narrow viewports (T13.2), worklist filters, CSV export, and a summary view past 25 ids (T13.1), MCP `pivot_from_entities` (T13.5) |
| P14 | Pipeline observability and hardening | Move shards off git history (I17 / T14.3; the repo is about 2.9 GB against GitHub's 5 GB guidance), pipeline health JSON (I5 / T14.1), NVD 429 and retry counts (I19 / T14.5), a coverage floor for `src/tip/` (I20 / T14.4), `mypy --strict` (I9 / T14.6), content-hash cache busting on Pages (I18), an investigation into splitting `IndexLoader`, `DatabaseManager`, and `cve_processor.py` (T17.1) |
| P15 | Improvements grab-bag | One at a time, each with its own acceptance criteria: software two-hop APT attribution as a lower tier (T16.2), STIX 2.1 export (I15), MITRE ATLAS (I2), CWE Top 25 (I3), Sigma rules pivot (I4), private notes (I14), DISARM (I11), NIST CSF mapping (I12) |

Parked until a trigger fires: embedding similarity (I10), RSS or webhook outputs (I13), and a live pipeline trigger from the search bar (T13.6), which need product validation or a server-mode deployment.

Dropped by decision: P11 (CVE2CAPEC parity check) on 2026-06-11, since enrichment stays in-house; P12 (ctibutler) on 2026-06-11, since its conditional can no longer fire; I33 (required status checks on `main`) on 2026-09-27, since the bot token it needs would be the larger risk for a solo repo. The no-force-push, no-deletion ruleset stays.
