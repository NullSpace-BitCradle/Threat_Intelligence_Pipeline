---
slug: tip-master-plan
status: active
version: 1.0
authored: 2026-05-08
authored_by: maintainer (PAI Algorithm v6.3.0, E3)
supersedes: Plans/ROADMAP.md (kept as historical reference)
review_cadence: monthly + after each phase ships
---

# TIP Master Plan

> **Single source of truth for what TIP is, what is shipping next, and what is parked.**
> Replaces the layered Plans/ROADMAP.md + Plans/2026-04-29_cve2capec-ctibutler-integration.md split. ROADMAP.md remains as historical record but is no longer authoritative.

## How to read this doc

Every item has a stable ID (P1..Pn for phases, T1..Tn for tasks within a phase, I1..In for improvement candidates). IDs never re-number on edit; dropped items become tombstones (`[DROPPED — see Decisions]`). When something ships, change its `status:` and add a Verification entry — do not delete it.

Status legend:
- **DONE** — shipped, in main, verifiable on disk
- **ACTIVE** — in flight
- **NEXT** — ready to pick up; no blockers
- **DEFERRED** — scoped but parked behind a decision or trigger
- **PROPOSED** — improvement candidate, not yet committed
- **DROPPED** — explicitly removed; tombstone retained

---

## 1. Executive summary

TIP is functional, live, and auto-updating. The 2026-04-24 work block closed nine substantive items (Phases 1-8 plus all-CVE tiered search). Since then there has been a two-week stall in active development; only the auto-pipeline chore commits land. The headline next deliverables are MCP Phase B (three remaining tools) and the CVE-2023-44487 demo capture for Strategic Rogue / Partner Network. A separate proposal (2026-04-29 CVE2CAPEC + ctibutler integration) would obsolete some of the 2026-04-24 manual mapping work; this plan reconciles that tension by gating Phase B on a CVE2CAPEC parity check first, so MCP Phase B is not built twice.

The plan is grouped into seven phases (P9-P15), running roughly two weeks of focused work plus an open-ended improvements grab-bag. Phase ordering optimizes for portfolio impact (Strategic Rogue + Partner Network demo) before broader feature breadth.

## 2. Current state (verifiable, 2026-05-08)

### 2.1 Code on disk

- 27 Python modules in `src/tip/` (core processors, monitoring, utils, database)
- 5 Python modules in `src/tip_mcp/` (loader, schema, server, tools)
- 67 tests passing (unit tests for processors + MCP layer)
- Static SPA in `docs/` (HTML + 4 JS modules + 2 CSS files)
- 2 GitHub Actions workflows (daily reference DB + weekly CVE pipeline)

### 2.2 Data on disk

| Asset | Size | Last touched |
|-------|------|--------------|
| `docs/database/CVE-2026.jsonl.gz` | 6.0 MB | 2026-04-24 |
| `docs/data/entity_index.json` | 16.4 MB | 2026-04-24 |
| `docs/data/cve_ids_index.json` | 1.8 MB (345K CVE IDs) | 2026-04-24 |
| `docs/data/defend_db.jsonl` | 676 KB | 2026-04-23 |
| `docs/data/cwe_db.json` | 382 KB | 2026-03-29 |
| `docs/data/groups_db.json` | 340 KB | 2026-03-14 |

### 2.3 Critical observability finding

**The local working tree last received a real commit on 2026-04-24.** No new commits visible on `origin/main` since then in the local-cached refs. Either:

- the daily and weekly auto-pipelines have not run successfully for two weeks (i.e., the GitHub Actions workflows are broken or quota-blocked), OR
- they have run but the local checkout has not been fetched in two weeks.

This must be resolved as the very first action of P9 (see T9.1).

### 2.4 Untracked working-tree state

- `Plans/2026-04-29_cve2capec-ctibutler-integration.md` (the proposal that this master plan absorbs)
- `d1-after-pipeline-layer2-with-desc.png` (Layer 2 architecture screenshot)

Decision required: commit, gitignore, or delete. Default proposal: commit both as part of the master-plan landing commit.

### 2.5 Roadmap hygiene finding

`Plans/ROADMAP.md` has duplicate entries for F4 and F5 (lines 213-228) — two slightly different versions of each were left in during the 2026-04-24 consolidation. This master plan replaces it cleanly; the ROADMAP file gets a pointer at top and is otherwise frozen.

---

## 3. Outstanding items inherited from prior plans

Renumbered into the new ID space. Originals in parentheses for traceability.

### From the previous ROADMAP

| New ID | Old | Item | Status |
|--------|-----|------|--------|
| T9.2 | N1 | Verify auto-pipeline runs populate the new NVD fields | NEXT |
| T10.1 | N2 | MCP Phase B: `build_attack_chain` | NEXT |
| T10.2 | N2 | MCP Phase B: `get_defenses` | NEXT |
| T10.3 | N2 | MCP Phase B: `kev_status` | NEXT |
| T10.4 | N3 | CVE-2023-44487 demo capture for Partner Network | NEXT (deps T10.1) |
| T13.1 | D2 | Multi-entity analysis mode (paste list, combined view) | DEFERRED → P13 |
| T13.2 | D3 | Visual polish (graph legend, zoom, landing, responsive) | DEFERRED → P13 |
| T13.3 | D4 | Live pipeline trigger from search bar | DEFERRED → P15 |
| T13.4 | D5 | Extended export formats (CSV, ATT&CK Navigator JSON) | DEFERRED → P13 |
| T13.5 | D6 | MCP `pivot_from_entities(ids: list)` | DEFERRED → P13 (deps T13.1) |
| T9.3 | F4 | Playwright smoke test for static site | NEXT |

### From the 2026-04-29 CVE2CAPEC + ctibutler proposal

| New ID | Old | Item | Status |
|--------|-----|------|--------|
| T11.1 | Phase 1 | Validate CVE2CAPEC parity vs. current TIP enrichment (dry-run, no replace) | NEXT |
| T11.2 | Phase 1 | Replace nightly enrichment with CVE2CAPEC pull (only if T11.1 passes) | NEXT (deps T11.1) |
| T12.1 | Phase 2 | Stand up ctibutler locally (docker compose) for technique-detail lookup | DEFERRED → P12 |
| T12.2 | Phase 3 | Wrap ctibutler as `ctibutler-mcp` for PAI consumption | DEFERRED → P12 |

---

## 4. New work — improvements, additions, new functionality

Proposed during this 2026-05-08 review. Not yet committed; ranked by impact-to-effort. Each carries an `I` ID for stable reference.

### 4.1 High value, low-medium effort (promote into P15 candidates)

- **I1: EPSS scoring integration.** `cve-mcp` already exposes EPSS via `get_epss_score`. Pull EPSS into the CVE entity and surface as a fourth severity axis alongside CVSS, KEV, and SSVC. ~2-4 hours.
- **I2: MITRE ATLAS framework.** AI/ML adversary tactics. Aligns with the maintainer's interest in AI security and Anthropic Partner Network positioning. CTIButler exposes ATLAS for free. Add as ninth framework. ~1 day.
- **I3: CWE Top 25 alongside OWASP Top 10.** CWE Top 25 is the more cited industry list; small dataset, additive UI. ~2-4 hours.
- **I4: Sigma rules pivot from CVE/technique.** Sigma is the open detection rule format; a "show detection content" tab on each CVE/technique would be unique vs. competitors. Source: SigmaHQ/sigma. ~1-2 days.
- **I5: Pipeline observability dashboard.** Existing `monitoring/` and `utils/` code is partially wired but underused. Build a `/health` route and a JSON metrics export so a Pulse module can read it. ~1 day.
- **I6: Schema-versioned entity_index with migration doc.** Entity_index.json is at v1.5; the schema is implicit in `entity_index_generator.py`. Promote to a versioned formal schema (jsonschema) and write a one-page migration doc. ~half day.
- **I7: Saved searches / watchlists (localStorage).** Investigation pinning exists; extend to "watch this APT group / CWE / technique." Per-device, no server. ~half day.
- **I8: Diff view between pipeline runs.** "What changed in this week's pipeline?" is a real analyst question and free with the auto-pipeline cadence. ~1 day.
- **I9: Type-strict mypy pass.** Project uses Python 3.9+; add `mypy --strict` to CI and address findings. ~1 day on first pass.
- **I21: CWE-assignment gap closure (added 2026-06-11).** The chain-coverage ceiling: TECHNIQUES coverage caps at ~75% in modern years (near zero pre-2010) because many NVD records carry no usable CWE to join from — the joins themselves are fine. Close it in-house, in provenance-tagged tiers: (a) CNA-provided CWEs from the NVD record's CNA/ADP containers, (b) CISA vulnrichment CWE assignments (already ingested, currently only used for SSVC/CVSS), (c) description-based CWE inference as an explicitly-labeled lowest tier. This is the "better than CVE2CAPEC" successor work from the P11 decision. ~2-3 days for (a)+(b); (c) scoped separately if (a)+(b) leave a gap worth chasing.

### 4.2 Higher effort, conditional value

- **I10: Embedding-based similarity ("CVEs like this one").** Adds semantic search on top of the inverted index. ~3-5 days, depends on embedding model choice and corpus index size.
- **I11: DISARM framework (disinformation TTPs).** Aligns with the maintainer's mis/disinformation OSINT interest. Out of band for typical CVE workflows. ~1-2 days. CTIButler exposes it.
- **I12: NIST CSF subcategory mapping.** For compliance audiences. ~1-2 days. Adds compliance-flavored entity type.
- **I13: RSS / webhook outputs.** Watch + alert. Requires server mode. Defer until D4 (live pipeline trigger) lands.
- **I14: Annotation / private notes layer.** Per-CVE local notes + JSON export/import. ~1 day.
- **I15: STIX 2.1 export.** Investigation pinning → STIX bundle. Industry-standard interchange. ~1-2 days.

### 4.3 Operational / hardening (high importance, often invisible)

- **I16: Auto-pipeline failure alerting.** GH Actions can succeed-with-no-changes silently; add a notification channel (email / GitHub issue / RSS) when a run fails or skips for >36h. ~half day.
- **I17: Shard-size budget monitoring.** 35 MB compressed today; track YoY growth and define a "when do we shard differently or move off Pages" trigger. ~half day for the monitoring code, ongoing for the policy.
- **I18: GitHub Pages content-hash cache busting.** Ensure clients always pull fresh entity_index.json after pipeline runs. ~1-2 hours.
- **I19: Pipeline rate-limit observability.** NVD has tight rate limits; capture per-run rate-limit hits and 429 responses for tuning. ~half day.
- **I20: Test coverage gates in CI.** Today: 67 tests, no coverage threshold. Add `pytest-cov --cov-fail-under=80` for `src/tip_mcp/` and `--cov-fail-under=60` for `src/tip/` (lower bar reflecting integration-heavy code). ~2-3 hours.

### 4.4 Drop or hold

- DROPPED: nothing intentional this round. Anything from the original ROADMAP that did not survive triage is explicitly retained as DEFERRED above; no items are lost.

---

## 5. Master execution sequence

Seven phases, sequenced to maximize Strategic Rogue + Partner Network impact while resolving the CVE2CAPEC tension before duplicate work occurs.

### P9 — Stabilize current state (1 day)

**Why first:** before adding any feature, confirm the foundation has not silently broken during the two-week stall.

| Task | Description | Depends on |
|------|-------------|------------|
| T9.1 | `git fetch` + investigate auto-pipeline status (GitHub Actions runs since 2026-04-24). Decide pull or rebase locally. | nothing |
| T9.2 | Verify the most recent auto-pipeline run populated DESCRIPTION / CVSS / PUBLISHED / LAST_MODIFIED / REFERENCES on at least 5 sampled CVEs from `docs/database/CVE-2026.jsonl.gz`. If not, debug processor step. | T9.1 |
| T9.3 | Playwright smoke test: load static site, search for `CVE-2023-44487`, assert expected DOM nodes (severity badge, description, KEV badge, graph). Fails build on regression. Add to CI. | nothing |
| T9.4 | Commit the untracked working-tree state: this master plan, the 2026-04-29 CVE2CAPEC plan, the layer-2 architecture PNG. Update `Plans/ROADMAP.md` with a pointer to this file. Update `lastUpdate.txt`. | T9.1 |
| T9.5 | Update `~/.claude/PAI/USER/PROJECTS/PROJECTS.md` TIP entry to reflect "P9-P10 active, master plan landed 2026-05-08." | T9.4 |

**Acceptance criteria (ISCs for P9):**
- ISC-9.1: `git status` shows clean working tree, master plan committed and pushed.
- ISC-9.2: `git log -1 origin/main` returns a hash newer than `a505989` (or a documented decision in `## Decisions` if no auto-pipeline activity is expected).
- ISC-9.3: Sampled 2026-CVE record from `CVE-2026.jsonl.gz` contains all five new fields with non-null values, OR a P9.2 followup is filed citing the missing field.
- ISC-9.4: `bun test` (or pytest equivalent) Playwright smoke run exits 0 on the deployed `nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/` URL.
- ISC-9.5: `grep -c "MASTER_PLAN" Plans/ROADMAP.md` returns ≥1.
- ISC-9.6: Anti — no production code changes land in P9 except the Playwright test scaffold and a release commit. Behavior is unchanged.

### P10 — MCP Phase B + Partner Network demo (2 days)

**Why next:** highest-leverage portfolio work. Partner Network reviewers can run the demo end-to-end. CCA Foundations evidence builds.

| Task | Description | Depends on |
|------|-------------|------------|
| T10.1 | Implement `build_attack_chain(technique_id)` per scope doc §5.4. Returns ordered chain of CAPECs, CWEs, CVEs (with KEV flag), D3FEND defenses. | P9 |
| T10.2 | Implement `get_defenses(technique_id?, cve_id?)` per scope doc §5.5. Exactly-one-of validation, returns D3FEND list with mapping_source. | P9 |
| T10.3 | Implement `kev_status(cve_id)` per scope doc §5.6. Returns `{in_kev, date_added, known_campaigns, ssvc_decision}`. | P9 |
| T10.4 | Extend pytest coverage for the three new tools to ≥90% on `tip_mcp/`. | T10.1, T10.2, T10.3 |
| T10.5 | CVE-2023-44487 end-to-end demo via Claude Code with `.mcp.json` pointed at local `tip-mcp`. Capture transcript. | T10.1, T10.2, T10.3 |
| T10.6 | README update: full six-tool list with example prompts, plus the captured demo transcript. | T10.5 |

**Acceptance criteria (ISCs for P10):**
- ISC-10.1: `lookup_entity("CVE-2023-44487")` → real CVE record with KEV true, CVSS, description, references — verified by direct MCP call.
- ISC-10.2: `pivot_from_entity("CVE-2023-44487", "technique")` → at least one ATT&CK technique (T1498 Network Denial of Service expected) — verified by direct MCP call.
- ISC-10.3: `build_attack_chain("T1498")` returns `{capecs, cwes, cves, defenses}` with each list ≥1 element — verified by direct MCP call.
- ISC-10.4: `kev_status("CVE-2023-44487")` returns `{in_kev: true, date_added: "2023-10-10", ...}` — verified by direct MCP call.
- ISC-10.5: `get_defenses(technique_id="T1498")` returns ≥1 D3FEND entity — verified by direct MCP call.
- ISC-10.6: `pytest tests/tip_mcp/ --cov=src/tip_mcp --cov-fail-under=90` passes.
- ISC-10.7: README contains an "MCP demo" section with a verbatim demo prompt and the actual Claude Code transcript.
- ISC-10.8: Anti — no breaking change to Phase A tools' response envelopes; existing 25 Phase A tests still pass.
- ISC-10.9: Anti — no MCP tool returns a hardcoded mapping; all data comes from `entity_index.json` or a documented shard fallback.

### P11 — CVE2CAPEC parity check + decision (1 day)

> **RESOLVED 2026-06-11 — decision by principal, parity check moot.** the maintainer: TIP was originally built off CVE2CAPEC's approach; whatever it does, TIP's in-house pipeline can do better. CVE2CAPEC will not be adopted in any posture (no REPLACE, no AUGMENT). Enrichment stays in-house. Supporting evidence from 2026-06-11 session: the in-house chain is local joins over static MITRE datasets (CAPEC CSV, ATT&CK XLSX, CWE XML) with no rate-limited dependency, and the NVD-cost argument collapsed — a full-corpus keyless NVD pass took ~20 minutes (CVSS backfill, commit 0f3a748). T11.1-T11.4 are superseded. The "do it better" successor work is closing the CWE-assignment gap that caps TECHNIQUES coverage (~75% modern years) — tracked as **I21** in §4.1 and slotted #2 in the P15 promotion order. Per the P12 conditional below, P12 (ctibutler) is deferred indefinitely.

**Original phase content retained for historical context:**

**Why before P12:** the 2026-04-29 plan claims CVE2CAPEC obsoletes the 2026-04-24 enrichment surgery. Before investing in P12 (ctibutler) or letting the next pipeline run rewrite shards, confirm the parity claim on real data.

| Task | Description | Depends on |
|------|-------------|------------|
| T11.1 | Pull CVE2CAPEC's `new_cves.jsonl` once. Compute coverage diff vs. current TIP enriched set on 100 sampled CVEs from the last 30 days. Document gaps and surpluses. | P10 |
| T11.2 | Decide: REPLACE (drop manual mapping, use CVE2CAPEC + ctibutler), AUGMENT (keep TIP processors, supplement gaps via CVE2CAPEC), or HOLD (keep current, revisit in 6 months). Record decision in `## Decisions` with rationale. | T11.1 |
| T11.3 | If REPLACE: branch `feat/cve2capec-replace`, implement Phase 1 of the 2026-04-29 plan, validate against 7 days of TIP output, then merge or abandon. | T11.2 (if REPLACE) |
| T11.4 | If AUGMENT: implement a thin enrichment layer that fills only the documented gaps from T11.1. | T11.2 (if AUGMENT) |

**Acceptance criteria (ISCs for P11):**
- ISC-11.1: A `parity-report.md` artifact exists in `Plans/` with per-CVE coverage diff over the 100-sample set.
- ISC-11.2: Decision (REPLACE / AUGMENT / HOLD) is recorded in `## Decisions` with at least one quoted parity datapoint as evidence.
- ISC-11.3: If REPLACE chosen — `pytest tests/` still passes against the new pipeline; ≥3 spot-checked CVEs against MITRE's published mapping show no fabricated techniques.
- ISC-11.4: Anti — no decision is recorded without parity data; "feels right" is not acceptance evidence.

### P12 — ctibutler local + ctibutler-mcp wrapper (2 days)

**Why this phase:** strategic STIX query surface independent of GitHub uptime; doubles as PAI MCP that informs cve-mcp + tip-mcp workflows.

**Conditional:** only if P11.2 lands as REPLACE or AUGMENT. If HOLD, P12 is deferred indefinitely.

| Task | Description | Depends on |
|------|-------------|------------|
| T12.1 | Stand up ctibutler via docker compose at `~/Projects/ctibutler`. Verify `/api/v1/attack/objects/` returns ATT&CK data. | P11 (REPLACE or AUGMENT) |
| T12.2 | Replace ad-hoc MITRE GitHub raw fetches in `tip` report rendering with ctibutler calls. Add 30s timeout + circuit breaker for ctibutler downtime. | T12.1 |
| T12.3 | Scaffold `~/Projects/ctibutler-mcp` as a sibling to `cve-mcp`. Implement three tools: `search_attack_technique`, `search_capec`, `list_atlas_techniques`. | T12.1 |
| T12.4 | Register `ctibutler-mcp` in `~/.claude/settings.json` mcpServers. | T12.3 |

**Acceptance criteria (ISCs for P12):**
- ISC-12.1: `curl http://localhost:8000/api/v1/attack/objects/T1190/` returns 200 + valid STIX object.
- ISC-12.2: TIP report rendering for an ATT&CK technique uses ctibutler when available; falls back to the in-repo data when not.
- ISC-12.3: `ctibutler-mcp` tool calls return structured STIX from the local API; verified end-to-end via Claude Code.
- ISC-12.4: ctibutler's ArangoDB volume disk usage measured; budget set to ≤5 GB and recorded in `## Decisions`.
- ISC-12.5: Anti — no raw `requests.get("https://raw.githubusercontent.com/...")` calls remain in the report path.

### P13 — Multi-entity + UI polish + exports (3-4 days)

| Task | Description | Depends on |
|------|-------------|------------|
| T13.1 | Multi-entity analysis design pass: pick UX (textarea paste vs. URL params vs. file upload), output rendering (combined graph vs. side-by-side cards vs. Venn intersection). Half-day design doc, then implementation. | P10 |
| T13.2 | Visual polish: graph legend, graph zoom + pan, landing-page quick-access rotation, responsive viewport tweaks. | nothing |
| T13.3 | CSV export from investigation pinning. | nothing |
| T13.4 | ATT&CK Navigator layer JSON export. | nothing |
| T13.5 | MCP `pivot_from_entities(ids: list)` tool. Returns intersection or union of relationships. | T13.1 |

**Acceptance criteria (ISCs for P13):**
- ISC-13.1: Pasting a list of 5+ CVE IDs in the new multi-entity input renders a combined view that loads in <2 s for an indexed sample.
- ISC-13.2: Graph legend visibly explains the 8 framework colors; legend toggleable.
- ISC-13.3: Graph supports mouse-wheel zoom + click-drag pan with reset button.
- ISC-13.4: Investigation export menu offers JSON, CSV, and ATT&CK Navigator JSON; each downloads a file with the expected schema.
- ISC-13.5: MCP `pivot_from_entities` round-trips through Claude Code and returns intersection results for a multi-CVE input.
- ISC-13.6: Static site renders without horizontal scroll at 360 px viewport width.
- ISC-13.7: Anti — multi-entity mode does not break single-entity routes; existing hash URLs still resolve.

### P14 — Pipeline observability + hardening (1-2 days)

| Task | Description | Depends on |
|------|-------------|------------|
| T14.1 | I5: `/health` JSON endpoint surfacing pipeline last-run, success/failure, durations per processor. | nothing |
| T14.2 | I16: Auto-pipeline failure alerting — GitHub Actions notify on failure; weekly "no commit in 36h" canary. | nothing |
| T14.3 | I17: Shard-size budget monitoring. Track entity_index.json + shard total size per run; warn at 80% of a configured budget. | nothing |
| T14.4 | I20: pytest-cov coverage gates in CI. | T9.3 |
| T14.5 | I19: NVD rate-limit observability. Per-run 429 + retry counts logged + surfaced in `/health`. | T14.1 |
| T14.6 | I9: `mypy --strict` pass on `src/tip_mcp/` first; gradual on `src/tip/`. | nothing |

**Acceptance criteria (ISCs for P14):**
- ISC-14.1: `curl https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/health.json` (or chosen path) returns last-run timestamp, status, processor durations.
- ISC-14.2: A failed GH Actions run produces a visible notification within 1 hour of failure.
- ISC-14.3: CI fails when `pytest --cov-fail-under` thresholds drop below the configured floor.
- ISC-14.4: `mypy --strict src/tip_mcp/` returns zero errors.
- ISC-14.5: Anti — no observability addition introduces a runtime dependency the pipeline does not already carry.

### P15 — Improvements grab-bag (open-ended, 5+ days when promoted)

Take items from §4 in order of analyst-leverage. Each item gets its own design + ship cycle. Promote one at a time; do not fan out in parallel within a single session.

Initial promotion order (revisable):

1. **I1 (EPSS scoring)** — highest signal-to-effort; cve-mcp already has the data.
2. **I21 (CWE-assignment gap closure)** — raises the chain-coverage ceiling itself; the in-house "better than CVE2CAPEC" successor work per the P11 decision.
3. **I3 (CWE Top 25)** — 2-4 hours, additive UI.
4. **I7 (saved searches / watchlists)** — half day, real workflow value.
5. **I6 (schema versioning doc)** — half day, pays back the next time entity_index changes.
6. **I8 (diff view between runs)** — answers a real analyst question.
7. **I2 (MITRE ATLAS framework)** — strategic positioning for AI-security work.
8. **I4 (Sigma rules pivot)** — differentiator vs. competitors.
9. **I14 (annotation layer)** — extends investigation pinning.
10. **I11 (DISARM framework)** — the maintainer's OSINT interest.
11. **I15 (STIX 2.1 export)** — interchange format.
12. **I12 (NIST CSF subcategory mapping)** — compliance audiences.
13. **I10 (embedding-based similarity)** — heavier lift; requires real product validation first.

T13.3 (live pipeline trigger from UI) and I13 (RSS/webhook) require a server-mode deployment; both are deferred until there is a use case that justifies leaving the static-site model.

Acceptance criteria for P15: each promoted item produces its own ISC list at the time it is promoted; nothing is shipped from P15 without ≥3 ISCs of its own.

---

## 6. Cross-cutting risks and rollback

| Risk | Probability | Mitigation |
|------|-------------|------------|
| CVE2CAPEC GH Actions stops publishing | Medium | T11.3/T11.4 cache the last-good JSONL locally; alert if stale >36h. |
| ctibutler ArangoDB disk runaway | Low-Medium | T12.4 enforces 5 GB budget. |
| GitHub Pages outgrowing 35 MB compressed corpus | Low today, rising YoY | I17 monitors and triggers a Cloudflare Pages or R2 migration discussion at 80% of budget. |
| Phase B tests break after CVE2CAPEC swap | Medium if REPLACE chosen | P11 is gated on parity report; if mappings shift, T11.3 includes test backfill. |
| Auto-pipeline silently broken (current state, possibly) | Unknown until T9.1 | T9.1 first action; P14 builds proper observability so this is not the second time we discover it weeks late. |
| Phase B builds against soon-to-be-retired manual mappings | Low if P11 runs before P12; impossible if P11 chooses HOLD | Sequence is exactly P10 → P11 → P12 to bound this risk. |
| Multi-entity mode produces unmanageable graph for >50 entities | Medium | T13.1 design must pick a hard cap (default proposal: 25 entities) and a "summary view" fallback for larger inputs. |
| Improvements list (§4) derails focus | High if items are intaken in parallel | P15 explicitly serial; one at a time, with its own ISCs. |

Rollback: each phase commits to its own branch. P11 REPLACE in particular branches as `feat/cve2capec-replace` and only merges after T11.3 passes.

---

## 7. Strategic anchors (the why behind the what)

These shape phase priority. Carried forward verbatim from the 2026-04-24 ROADMAP §7.

- **S1 — Strategic Rogue portfolio piece.** MCP server is the headline portfolio item. Pulls P10 (MCP Phase B) up the priority list.
- **S2 — Partner Network reply.** Demo readiness must not wait on broader TIP roadmap. P10 ships before P11.
- **S3 — CCA Foundations cert.** MCP work is evidence for six CCA domains. Reinforces P10.
- **S4 — "Cover all CVEs" instinct.** Resolved by D1 (Phase 8) tiered architecture. No longer a forcing function; current focus is correctness, not coverage.
- **S5 (NEW) — Reduce in-house mapping debt.** Every line of CVE-to-ATT&CK glue code we do not maintain is a line that does not break when MITRE renames a technique. P11 is the test of whether the upstream feeds carry their weight.

---

## 8. Open decisions (await the maintainer)

1. **Auto-pipeline status:** if T9.1 finds the pipeline has not run in two weeks, decide whether to repair (re-trigger workflow, fix Actions config) or accept manual `--db-only` runs as the new operating mode.
2. **CVE2CAPEC posture (P11):** ~~REPLACE / AUGMENT / HOLD. Decision evidence: the parity report from T11.1.~~ **DECIDED 2026-06-11: none of the above — CVE2CAPEC rejected outright; enrichment stays in-house** (TIP was built off CVE2CAPEC's approach and can do it better). See the resolution note at P11. P12 deferred indefinitely per its conditional.
3. **Multi-entity entity cap (T13.1):** propose 25; confirm.
4. **GitHub Pages migration trigger (I17):** propose 80% of a 100 MB total corpus budget; confirm.
5. **mypy strictness scope (I9):** propose `src/tip_mcp/` first, gradual on `src/tip/`; confirm.
6. **Improvement promotion order (P15):** the proposed order is revisable; the maintainer's call.

---

## 9. Source documents (carry forward)

- `Plans/ROADMAP.md` — historical, frozen with pointer to this file
- `Plans/2026-04-29_cve2capec-ctibutler-integration.md` — absorbed into P11/P12 above
- `docs/superpowers/specs/mcp-server-scope.md` — canonical for MCP scope; P10 follows §5.4-§5.6 verbatim
- `docs/superpowers/specs/2026-03-14-tip-v2-redesign-design.md`
- `docs/superpowers/plans/2026-03-14-kev-vulnrichment-integration.md`
- `docs/superpowers/specs/2026-03-18-provenance-campaigns-design.md`
- `docs/superpowers/plans/2026-03-18-provenance-campaigns-plan.md`
- `docs/superpowers/specs/2026-03-28-tip-ui-redesign-search-first-design.md`
- `docs/superpowers/plans/2026-03-28-tip-ui-search-first-redesign.md`
- `MEMORY/WORK/20260424-160123_flesh-out-cve-enrichment/PRD.md`
- `MEMORY/WORK/20260424-204159_pivot-shard-fallback/PRD.md`
- `MEMORY/WORK/20260424-205652_all-cve-search-tiered/PRD.md`
- `MEMORY/WORK/20260424-162249_consolidate-roadmap/PRD.md`

---

## Decisions

(append-only log; new entries on top)

- 2026-06-09 — P9 executed. T9.1 resolution: fast-forward pull (local ahead 0 / behind 52; every remote commit was auto-pipeline `[skip ci]` data maintenance — pipeline ran healthy through the entire 2026-05-08 → 2026-06-09 stall; daily + weekly Actions runs all green).
- 2026-06-09 — T9.2 finding: 5 sampled 2026 CVEs all carry DESCRIPTION/PUBLISHED/LAST_MODIFIED/REFERENCES. CVSS null on 2/5 (CVE-2026-46395, CVE-2026-8714) — verified against live NVD: both unscored upstream (status `Deferred` / `Awaiting Analysis`). Pipeline is faithful; CVSS is expected-null for unanalyzed NVD records. No P9.2 followup needed.
- 2026-06-09 — T9.4 refinement: lastUpdate.txt NOT manually edited. It is auto-pipeline-owned (written each run; current as of today's 06:00 UTC run). A manual timestamp would misrepresent data freshness.
- 2026-06-09 — T9.3 implementation: pytest + playwright chosen over bun test (repo is Python/pytest; MASTER_PLAN blessed either). CI job is schedule-based (07:00 UTC daily, after the 06:00 db update deploys) + workflow_dispatch — push-triggered runs would race the Pages deploy.
- 2026-05-08 — Created MASTER_PLAN.md as new single source of truth. Roadmap becomes pointer file. Reason: 2026-04-29 CVE2CAPEC plan + 2026-04-24 ROADMAP + ad-hoc memory notes had drifted out of sync; one canonical doc is required for the next two weeks of work.
- 2026-05-08 — Sequence locked as P9 → P10 → P11 → P12 → P13 → P14 → P15. Reason: portfolio impact (S1, S2, S3) gates pre-CVE2CAPEC migration; parity check (P11) gates P12 to avoid building ctibutler against a HOLD outcome.
- 2026-05-08 — P11 added as a hard gate ahead of P12 because the 2026-04-29 proposal claims CVE2CAPEC obsoletes 2026-04-24 surgery; we will not act on that claim without evidence.

## Changelog

(append on each shipped phase)

- 2026-06-09 (P9 — stabilize): synced to origin (52 data commits), auto-pipeline verified healthy, NVD field population verified on sampled CVEs, Playwright smoke suite added (5 tests, green against live site) + daily CI job, plan documents landed. No production code changes. P10 (MCP Phase B) unblocked.
- 2026-05-08 (P0 — meta): initial master plan landed.

## Verification

(append per ISC as it passes)

(none yet)
