# TIP Development Roadmap

Last updated: 2026-04-24
Owner: the maintainer (Strategic Rogue / NullSpace-BitCradle)

## How to read this doc

One source of truth for "what is done, what is next, what is parked". Pulled from three plan docs (Mar 14, Mar 18, Mar 28), one MCP scope doc (Apr 23), today's PRD (Apr 24), and direct verification against code on disk.

Status legend:
- DONE: shipped, in main, verifiable on disk
- ACTIVE: started, partially complete
- NEXT: ready to pick up next; no blockers
- DEFERRED: scoped but intentionally parked behind something else
- FOLLOWUP: small leftover from a recently completed body of work

---

## 1. What TIP is today (state of the world, 2026-04-24)

A search-first SPA at nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline that correlates CVEs across 8 frameworks (CWE, CAPEC, ATT&CK, D3FEND, OWASP, KEV, SSVC, Campaigns). Static GitHub Pages site, weekly auto-rebuild. Plus a local MCP server (Phase A complete, Apr 23) that exposes the same graph to Claude agents.

Numbers as of today's regen:
- 345,198 raw CVEs in shards (`docs/database/CVE-YYYY.jsonl.gz`, 35 MB compressed)
- 271,941 enriched with CWE
- 2,766 indexed in `entity_index.json` (was 1,367 before today's filter widening)
- 5,303 total entities (CVEs + CWE + technique + CAPEC + APT + D3FEND + campaign + OWASP)
- 7.9 MB entity_index.json, 0.7 MB search_index.json
- 59 tests passing

---

## 2. Phase history (what shipped, in order)

### Phase 0: Pipeline foundation (pre 2026-03)
DONE. CVE ingestion from NVD API, CWE/CAPEC/ATT&CK/D3FEND processors, JSONL year-shard storage, `run_pipeline.py` orchestrator with --db-only / --cve-only / --status / --force flags.

### Phase 1: KEV + Vulnrichment + APT integration (2026-03-14 to 2026-03-18)
DONE. Spec: `docs/superpowers/specs/2026-03-14-tip-v2-redesign-design.md`. Plan: `docs/superpowers/plans/2026-03-14-kev-vulnrichment-integration.md`.
- `src/tip/core/kev_processor.py` (CISA KEV catalog, 1,569 CVEs marked)
- `src/tip/core/vulnrichment_processor.py` (CISA SSVC + CVSS overrides, 1,262 entries)
- `src/tip/core/apt_processor.py` (MITRE ATT&CK Groups, 160 groups, technique reverse lookup)
- All wired into `cve_processor.process_cve_pipeline()` as steps 6 to 8
- 24 unit tests in `tests/test_kev_processor.py`, `tests/test_vulnrichment_processor.py`, `tests/test_apt_processor.py`

### Phase 2: Provenance + Campaigns (2026-03-18)
DONE (with two cosmetic followups). Spec: `docs/superpowers/specs/2026-03-18-provenance-campaigns-design.md`. Plan: `docs/superpowers/plans/2026-03-18-provenance-campaigns-plan.md`.
- `src/tip/core/campaign_fetcher.py` (MITRE STIX 2.1 ingestion, 34 campaigns)
- `entity_index.json` v1.5 schema: per-entity `prov: {source, tier}` and per-rel `{ids, source, tier}`
- KEV moved to top-level `entity['kev']` boolean (1,376 marked)
- `docs/data/campaigns_db.json` (48 KB)
- Bidirectional Campaign to APT and Campaign to Technique links
- UI: provenance section + tier badges (OFFICIAL green, AUTHORITATIVE blue, DERIVED amber) in `docs/js/results.js`

Cosmetic followups (low priority, see section 6):
- Vertical campaign timeline UI for APT entity panels (currently shows date range only)
- Campaign card section inside APT cards (planned `tip-views.js` was never created; cards module was removed in the Mar 28 refactor)

### Phase 3: Search-first UI redesign (2026-03-28)
DONE (with five explicit deferrals). Spec: `docs/superpowers/specs/2026-03-28-tip-ui-redesign-search-first-design.md`. Plan: `docs/superpowers/plans/2026-03-28-tip-ui-search-first-redesign.md`.
- Replaced 6-tab Bootstrap layout with single search bar SPA
- `docs/index.html` rewritten (landing + results + search-results containers)
- `docs/js/app.js` (hash router, debounced search, theme toggle, investigation pinning with localStorage)
- `docs/js/entity-system.js` (pure data layer, getEntity, getRelatedEntities helpers)
- `docs/js/graph.js` (D3 force-directed relationship graph, replaced Sankey)
- `docs/js/results.js` (entity header, summary cards, tabbed framework detail, graph panel)
- Bootstrap, ECharts, SweetAlert2 removed
- Same-day pipeline fixes: CWE XML parser fix grew CAPEC coverage 418 to 1,003; D3FEND transitive resolution; D3FEND canonical IDs

Deferred (see section 5):
- Multi-entity batch search (paste a list of CVEs, see combined view)
- Quick-access rotation on landing (currently only KEV recents)
- Live pipeline trigger from the search bar (server-mode only)
- CSV and ATT&CK Navigator export formats (JSON export is shipped)

### Phase 4: GitHub Actions automation (2026-03-29)
DONE.
- `.github/workflows/update-databases.yml` (daily 06:00 UTC, runs `--db-only`)
- `.github/workflows/run-pipeline.yml` (weekly Sunday 08:00 UTC, runs full pipeline with --force)
- Both auto-commit to main with `[skip ci]` markers
- Last successful run: 2026-04-23 08:03 UTC (`lastUpdate.txt`)

### Phase 5: MCP server Phase A (2026-04-23)
DONE. Scope: `docs/superpowers/specs/mcp-server-scope.md`. Commit: 45c648d.
- `src/tip_mcp/loader.py` (loads entity_index.json + search_index.json into memory)
- `src/tip_mcp/tools.py` (3 of 6 tools: lookup_entity, pivot_from_entity, search_threat_intel)
- `src/tip_mcp/server.py` (FastMCP stdio entry point)
- `src/tip_mcp/schema.py` (envelope + ErrorCode enum)
- 25 tests in `tests/tip_mcp/`

### Phase 6: CVE enrichment surgery (2026-04-24, today)
DONE. PRD: `MEMORY/WORK/20260424-160123_flesh-out-cve-enrichment/PRD.md`.
- Fixed description-loss bug in `process_cve_pipeline` (was building fresh dict, dropping DESCRIPTION every time)
- Added CVSS v3.1 / publishedDate / lastModifiedDate / references extraction in `process_nvd_cves`
- Removed `[:300]` description and `[:200]` name truncations
- Widened entity_index "interesting" filter from `KEV OR APT` to `KEV OR APT OR vulnrichment OR CVSS>=7.0`
- Wired previously-loaded `vulnrichment_db.json` into entity enrichment so 404 indexed CVEs gained CVSS today
- MCP `lookup_entity` shard fallback (effectively shipped MCP v1.1's shard fallback ahead of schedule)
- UI: severity badge (color coded), full description, disclosure dates, reference count on CVE pages
- 10 new tests in `tests/tip_mcp/test_shard_fallback.py`

---

## 3. Where the project is right now

Functional and live. Auto-updating weekly. Public site reflects pipeline output. MCP server runs locally with stdio transport. Code is in a healthy state; the only active known incompleteness is that the JSONL shards do not yet have NVD descriptions / CVSS / dates / references because the fix landed today and a fresh pipeline run has not happened. The next scheduled `run-pipeline.yml` execution is Sunday 2026-04-26 at 08:00 UTC, which will populate them.

---

## 4. NEXT (ready to pick up)

### N1. Verify the next scheduled pipeline run populates new fields
SIZE: small (1 to 2 hours of attention spread over a day).
WHY: Today's CVE enrichment fixes only take effect when the pipeline ingests CVEs from NVD with the new code. The first run will rewrite shards with full descriptions, CVSS, dates, and references.
WHAT TO DO: After Sunday's auto-run completes, sample five recent CVEs from `docs/database/CVE-2026.jsonl.gz` and confirm `DESCRIPTION`, `CVSS`, `PUBLISHED`, `LAST_MODIFIED`, `REFERENCES` are populated. If yes, regenerate `entity_index.json` and confirm UI renders the new fields. If no, debug whichever processor step is dropping them.
DEPENDS ON: nothing (just time).

### N2. MCP Phase B: implement remaining three tools
SIZE: medium (1 day).
WHY: Phase A shipped only `lookup_entity`, `pivot_from_entity`, `search_threat_intel`. The original scope (`mcp-server-scope.md`) lists three more tools needed for the Partner Network demo and Strategic Rogue portfolio.
WHAT TO DO:
- `build_attack_chain(technique_id)`: returns ordered chain of CAPECs, CWEs, CVEs (with KEV flag), and D3FEND defenses
- `get_defenses(technique_id?, cve_id?)`: returns D3FEND defenses applicable to either an ATT&CK technique or a CVE
- `kev_status(cve_id)`: returns `{in_kev, date_added, known_campaigns, ssvc_decision}`
- Extend pytest coverage; aim for 90% on tip_mcp package
- README update with full tool list and demo prompts
DEPENDS ON: Phase A (done).

### N3. Pivot shard fallback
SIZE: small (2 to 3 hours).
WHY: Today's enrichment session added shard fallback to `lookup_entity` only. `pivot_from_entity` still returns NOT_FOUND for non-indexed CVEs, which is inconsistent.
WHAT TO DO: Mirror the shard fallback pattern from `lookup_entity_impl` into `pivot_from_entity_impl`. When a CVE is found via shard, project its CWE, CAPEC, TECHNIQUE, OWASP fields as relationships of the appropriate types.
DEPENDS ON: Phase 6 (done).

### N4. Demo content for Partner Network application
SIZE: small (half day).
WHY: Per `mcp-server-scope.md` section 9, the headline demo is "CVE-2023-44487 (HTTP/2 Rapid Reset) attack chain via MCP". The plan says reviewers should be able to run this prompt and see grounded reasoning.
WHAT TO DO: Run the demo prompt end to end via Claude Code with `.mcp.json` pointed at `tip-mcp`. Capture the transcript. If the answer is grounded and clean, write a short README section in `src/tip_mcp/README.md` with the prompt and expected behavior. If anything in the chain hallucinates or fails, fix the underlying tool first.
DEPENDS ON: N2 (build_attack_chain is the centerpiece of this demo).

---

## 5. DEFERRED (scoped, parked behind a decision or external dependency)

### D1. All-CVE search architecture (the big one)
ORIGIN: Original roadmap item #1 from project memory; still the single largest gap.
STATE: Today's work made an incremental dent (1,367 to 2,766 CVEs indexed). Full coverage of all 271K enriched CVEs would push entity_index.json well past 100 MB and break browser load.
DESIGN PARKED: tiered architecture, three layers:
- Layer 1: thin "all-IDs" search index (just CVE-YYYY-NNNN strings + year, ~5 MB) so the UI search bar can find any CVE ID
- Layer 2: rich entity_index.json for the "interesting" subset (currently 2,766; could grow to 10K to 30K with broader filter)
- Layer 3: on-demand fetch from JSONL shards for full detail (already shipped today as MCP shard fallback; needs UI-side equivalent)
TRIGGER TO UNDEFER: when the maintainer decides the current 2,766 coverage feels too thin during real investigation work, or when a user explicitly hits a "CVE not found" wall in the UI for a CVE they expected.

### D2. Multi-entity analysis mode
ORIGIN: 2026-03-28 UI redesign spec, explicitly deferred at the time. Project memory roadmap item #2.
STATE: Not started. Needs design session before implementation.
DESIGN QUESTIONS: paste-a-list UX (textarea? CSV upload? URL params?), output rendering (combined graph? side-by-side cards? Venn-style intersection of techniques/CWEs?), how it interacts with investigation pinning.
TRIGGER TO UNDEFER: when the maintainer wants to use TIP for an actual multi-CVE investigation (e.g., "what do these 12 advisories from this week have in common?").

### D3. Visual polish (graph + landing)
ORIGIN: 2026-03-28 UI redesign plan, project memory roadmap item #3.
STATE: Functional but minimal. Specifically deferred:
- Graph legend (no current way for users to learn the color coding)
- Graph zoom and pan controls
- Landing page enhancements beyond "recent KEV" cards
- Quick-access rotation (KEV / high-profile CVEs / active APT groups cycling)
- Responsive tweaks for narrow viewports
TRIGGER TO UNDEFER: visible user friction or before any external Strategic Rogue demo where polish matters.

### D4. Live pipeline trigger from UI
ORIGIN: 2026-03-28 UI redesign plan.
STATE: Health probe in `app.js` detects whether TIP is running in server mode vs static mode, but the "search a CVE not in the database to fetch it live" path is not wired.
DESIGN QUESTIONS: confirm UX (modal? inline progress?), permission model (just NVD_API_KEY env var?), error handling for NVD rate limits.
TRIGGER TO UNDEFER: not blocking any current use case (the static site is the primary deployment).

### D5. Extended export formats
ORIGIN: 2026-03-28 UI redesign plan.
STATE: Investigation pinning exports JSON only. Spec also listed CSV and ATT&CK Navigator layer JSON.
SIZE: small (1 to 2 hours per format).
TRIGGER TO UNDEFER: any user request, or before a Navigator-using audience demo.

### D6. MCP v1.1 additive items
ORIGIN: `mcp-server-scope.md` section 8 Phase C.
STATE: One of the two v1.1 items (shard fallback in `lookup_entity`) shipped today. Remaining:
- `pivot_from_entities(ids: list)` (multi-entity pivot) blocked on D2's multi-entity work
TRIGGER TO UNDEFER: D2.

---

## 6. FOLLOWUP (small leftovers)

### F1. Description-storage memory note
SIZE: tiny (5 minutes).
The user-level memory `~/.claude/MEMORY/AUTO/project_tip_v15_status.md` contains the line "CVE description storage added to processor (truncated to 300 chars currently)". That truncation was removed today. When this roadmap is reviewed, also update or rewrite that memory entry so future sessions start from accurate state.

### F2. Stale comment in entity_index_generator
SIZE: tiny (2 minutes).
Line 275 of `src/tip/core/entity_index_generator.py` reads `# Only index "interesting" CVEs: KEV-listed, APT-linked, or 3+ relationship types`. The "3+ relationship types" criterion has never been implemented (the actual filter has always been simpler). Today's filter is even broader. Comment should be rewritten to match current code.

### F3. Provenance plan cosmetic gaps (from Phase 2)
SIZE: small (afternoon).
- Vertical campaign timeline UI for APT entity panels (currently shows only date range)
- Campaign external link builder (`buildExternalLink` for `campaign` type)
TRIGGER TO PICK UP: visible during real APT investigation, otherwise stays cosmetic.

### F4. UI test coverage
SIZE: medium (1 day).
There are no automated UI tests. Today's `results.js` changes (severity badge, description block, disclosure dates) were only manually inspected. Worth adding a Playwright smoke test that loads the static site, searches for a known CVE, asserts the expected DOM exists.

### F5. Vulnrichment CVSS for all CVEs (not just indexed)
SIZE: tiny (15 minutes after next pipeline run).
`vulnrichment_db.json` has 1,262 CVEs with `cisaCVSS` data. Today's `cve_processor` change does not back-fill that into shard records. Consider adding a "merge vulnrichment cisaCVSS into CVE.CVSS at ingest" step so the shard records carry the data even if vulnrichment_db.json is later removed or rotated.

---

## 7. Strategic anchors (the why behind the what)

These shape what to prioritize among the items above.

### S1. Strategic Rogue portfolio piece
The MCP server is the maintainer's headline portfolio piece for Strategic Rogue (cybersec + Claude integration consulting), CCA Foundations cert, and the Partner Network application. This pulls N2 (Phase B tools) and N4 (demo) up the priority list.

### S2. Partner Network reply
Application submitted; reviewer engagement is on the runway. Demo-readiness should not wait on broader TIP roadmap items. The mcp-server-scope decision was explicit: "MCP v1 ships independently of TIP roadmap work."

### S3. CCA Foundations cert
Exam-ready at 88% / 90% cold (per project memory). The MCP work doubles as evidence for six CCA domains (agentic architecture, tool design, MCP protocol, Claude Code config, prompt engineering, context/reliability). Already reinforces N2.

### S4. "Cover all CVEs" instinct (D1)
the maintainer feels strongly that a thorough threat intel tool should cover all CVEs. This is a real product belief, not a vanity metric. Stays parked because the right answer is the tiered architecture in D1, not just lifting the filter further. Build out N2 and N4 before this becomes the active focus.

---

## 8. Suggested order of operations from here

1. Wait for the Sunday 2026-04-26 pipeline run, verify N1.
2. While waiting, ship N3 (pivot shard fallback, half day) since it is small and consistent with what just shipped.
3. Pick up N2 (MCP Phase B tools) as the primary work block. The three tools are independent and can ship in any order.
4. Once Phase B is in, do N4 (demo capture) and update the README so Partner Network reviewers can run it.
5. Take a short break from MCP. Review F1, F2, F5 in one batch (under an hour).
6. Re-evaluate D1 once N2 + N4 land. If real-use friction has surfaced, start the All-CVE tiered architecture spec. If not, consider D2 (multi-entity) instead, since it has clearer use cases for the Strategic Rogue audience.

---

## 9. Source documents

For deeper context on any item, the source plans live at:

- `docs/superpowers/specs/2026-03-14-tip-v2-redesign-design.md`
- `docs/superpowers/plans/2026-03-14-kev-vulnrichment-integration.md`
- `docs/superpowers/specs/2026-03-18-provenance-campaigns-design.md`
- `docs/superpowers/plans/2026-03-18-provenance-campaigns-plan.md`
- `docs/superpowers/specs/2026-03-28-tip-ui-redesign-search-first-design.md`
- `docs/superpowers/plans/2026-03-28-tip-ui-search-first-redesign.md`
- `docs/superpowers/specs/mcp-server-scope.md`
- `MEMORY/WORK/20260424-160123_flesh-out-cve-enrichment/PRD.md`
