---
slug: tip-master-plan
status: active
version: 2.0
authored: 2026-05-08
updated: 2026-09-27
authored_by: maintainer (PAI Algorithm v6.3.0, E3)
supersedes: Plans/ROADMAP.md (removed 2026-06-20; git history retains it)
review_cadence: monthly + after each phase ships
---

# TIP Master Plan

> The single plan of record for TIP: where it stands, what ships next, what is parked, and what was decided. Git log is the changelog.

## 1. How to read this doc

Status legend:

- **NOW**: in flight or starting now.
- **NEXT**: ready to pick up after NOW; no blockers.
- **LATER**: scoped and wanted, not yet scheduled.
- **PARKED**: waits on a trigger (server mode, product validation) that has not happened.
- **DONE**: shipped to `main`, verifiable on disk or in git.
- **DROPPED**: removed on purpose; the tombstone stays with its reason.

ID rules:

- IDs never renumber. A dropped item keeps its ID and a tombstone in §6.
- **P** is a phase (P0 to P15). **T** is a task inside a phase (T13.4 belongs to P13). **I** is an improvement candidate.
- One item may carry two IDs when a phase task tracks an improvement (T14.2 is I16). The roadmap lists it once, with both.
- IDs inherited from older plans map as follows: ROADMAP N1 is T9.2, N2 is T10.1 to T10.3, N3 is T10.4, F4 is T9.3, D2 to D6 are T13.1, T13.2, T13.6, T13.4, T13.5; the 2026-04-29 proposal's Phase 1 to 3 are T11.1, T11.2, T12.1, T12.2.
- One collision fixed on 2026-09-27: the old inheritance table used T13.3 for the live pipeline trigger (D4) while the P13 table used T13.3 for CSV export. T13.3 stays CSV export; the live trigger is T13.6.

## 2. Executive summary

On 2026-09-27 TIP is live, auto-updating, and fails closed. The September review remediation (PR #1), MCP Phase B with its six-tool surface and scripted demo (P10, PR #4), and the inherited-CWE fix (I29, PR #5) are all merged to `main`. The next job is to re-capture the MCP demo once the first weekly run writes I29 shards (T10.7) and to start EPSS scoring (I1). After that come failure alerting, the cross-vendor audit before any Partner Network demo, the APT linkage fix and decision, and the CWE-assignment gap.

## 3. Current state, measured

Measured on `main` at `8848172` on 2026-09-27.

**Entity index** (`docs/data/entity_index.json`, v1.5): 4,342 entities, 7.81 MB, generated 2026-09-27T02:57Z.

| Type | Count |
|------|------:|
| cve | 1,728 |
| cwe | 969 |
| technique | 697 |
| capec | 559 |
| apt_group | 176 |
| defend | 147 |
| campaign | 56 |
| owasp | 10 |

- The curated CVE tier (Layer 2) is KEV, or APT-linked, or SSVC exploitation `active`.
- The index has 0 dangling relationship targets by construction.
- The published index predates the first weekly run with the I29 shard format. Inherited markers arrive with the next weekly run.

**All-CVE tier.** `docs/data/cve_ids_index.json` holds 398,446 CVE ids. Every one opens through 28 per-year shards (`docs/database/CVE-1999.jsonl.gz` to `CVE-2026.jsonl.gz`), 114.7 MB in total. `docs/` is 176.8 MB.

**Reference data.** KEV: 1,726 entries. Vulnrichment: 188,261 entries, after a full resync on 2026-09-27 that followed the truncated-compare fix (it held 2,567 before).

**Tests.** 396 unit tests and 33 Playwright smoke tests. `mypy` is clean on 27 source files. CI gates `src/tip_mcp` coverage at 90% (measured 96.8%).

**CI and repo.**

- `tests.yml`: unit tests, mypy, and the MCP coverage gate on every push to `main` and every PR.
- `smoke-test.yml`: local gate on pushes and PRs touching the site, plus a daily 07:00 UTC canary against the live site.
- `run-pipeline.yml`: weekly CVE pipeline, Sunday 08:00 UTC.
- `update-databases.yml`: daily reference databases, 06:00 UTC.
- CodeQL runs as GitHub's default setup. Dependabot covers pip and GitHub Actions.
- Actions are pinned to commit SHAs. Three hash-locked lockfiles carry a 7-day cooldown and install with `--require-hashes`.
- Data runs fail closed, share one concurrency group, build on the latest `main`, and never force push.
- The repo is about 2.6 GB on GitHub, mostly history growth (see I17).
- A ruleset on `main` blocks force push and deletion. It requires no checks yet (see I33).

**MCP.** Six tools on `mcp` 2.2.0: `lookup_entity`, `pivot_from_entity`, `search_threat_intel`, `build_attack_chain`, `get_defenses`, `kev_status`. The repo root carries `.mcp.json`. `scripts/mcp_demo.py` records the CVE-2023-44487 walkthrough to `src/tip_mcp/DEMO.md`.

## 4. Roadmap

Format: `ID · title · status · why · effort`. Phase labels P13 (UI and exports), P14 (observability and hardening), and P15 (improvement grab-bag) still name the old groupings; the status decides order. P15 items ship one at a time, each with at least 3 acceptance criteria of its own.

### 4.1 NOW

- **T10.7** · Re-capture `src/tip_mcp/DEMO.md` after the first weekly run with I29 shards · NOW · the committed demo predates the new shard format, and `scripts/mcp_demo.py --check` will flag the drift · minutes, after the Sunday run
- **I1** · EPSS scoring (P15) · NOW · adds a fourth severity axis beside CVSS, KEV, and SSVC; next feature · ~2 to 4 hours

### 4.2 NEXT

- **I16 / T14.2** · Failure alerting and freshness banner · NEXT · runs now fail red, so the risk is silent staleness; nothing notifies on a failure or a skip over 36 hours, and the site shows no data age · ~half day
- **T10.8** · Cross-vendor (Forge/GPT) audit of P10 and I29 · NEXT · required before any Partner Network demo; blocked until 2026-09-29 by the free Codex quota · ~half day
- **I30** · APT lookup id mismatch · NEXT, pair with I32 · the processor passes bare technique ids (`1134`) to `lookup_by_techniques`, whose keys are `T1134`, so shard `APT_GROUPS` is always empty · small
- **I32** · Decide APT linkage · NEXT, maintainer decision · technique-overlap links would tag roughly 60% of CVEs; replace with explicit attribution (ATT&CK campaign or intrusion-set references that cite CVEs) or keep and label it derived · decision first
- **I21** · CWE-assignment gap closure (P15) · NEXT · technique coverage caps near 75% in modern years because many NVD records carry no usable CWE; close it in provenance-tagged tiers: (a) CNA/ADP CWEs from the NVD record, (b) Vulnrichment CWE assignments, now complete at 188,261 entries, (c) description inference as a labeled lowest tier · ~2 to 3 days for (a) and (b)

### 4.3 LATER

- **I7** · Saved searches and watchlists in localStorage (P15) · LATER · extends pinning to "watch this APT group, CWE, or technique"; per device, no server · ~half day
- **I8** · Diff view between pipeline runs (P15) · LATER · "what changed this week" is a real analyst question · ~1 day
- **T13.3** · CSV export from investigation pinning (P13) · LATER · analysts leave the tool with spreadsheets · ~hours
- **T13.4** · ATT&CK Navigator layer JSON export (P13) · LATER · the standard way to share technique coverage; also the replacement path in I31 · ~hours
- **I15** · STIX 2.1 export (P15) · LATER · industry interchange format from pinned investigations · ~1 to 2 days
- **I17 / T14.3** · Move shards off git history · LATER · every weekly shard rewrite adds to history; the repo is about 2.6 GB against GitHub's 5 GB guidance; move shards to release assets or object storage and track size per run · ~half day for monitoring, more for the move
- **I2** · MITRE ATLAS framework (P15) · LATER · AI and ML adversary tactics; fits the AI-security positioning · ~1 day
- **I3** · CWE Top 25 beside OWASP Top 10 (P15) · LATER · the more cited industry list; small dataset · ~2 to 4 hours
- **I4** · Sigma rules pivot from CVE or technique (P15) · LATER · detection content per CVE is a differentiator · ~1 to 2 days
- **I14** · Annotation and private notes layer (P15) · LATER · per-CVE local notes with JSON export and import · ~1 day
- **I11** · DISARM framework (P15) · LATER · disinformation TTPs; outside typical CVE workflows · ~1 to 2 days
- **I12** · NIST CSF subcategory mapping (P15) · LATER · compliance audiences · ~1 to 2 days
- **I18** · Content-hash cache busting on Pages · LATER · clients must pull a fresh `entity_index.json` after each run · ~1 to 2 hours
- **I5 / T14.1** · Pipeline health JSON and metrics export · LATER · the `monitoring/` package it once meant to wire up was removed as dead code on 2026-09-26, so this starts from zero · ~1 day
- **I19 / T14.5** · NVD rate-limit observability, remainder · LATER · pacing shipped; per-run 429 and retry counts are still not captured · ~half day
- **I20 / T14.4** · Coverage floor for `src/tip/` · LATER · `src/tip_mcp` has a 90% floor; the pipeline core has none · ~2 to 3 hours
- **I9 / T14.6** · `mypy --strict`, `src/tip_mcp/` first, then gradual on `src/tip/` · LATER · non-strict mypy is clean in CI; strict is the next step · ~half day for the MCP package
- **T13.2** · Visual polish (P13) · LATER · graph legend, zoom and pan, landing rotation, narrow viewports · ~1 day
- **T13.1** · Worklist follow-ups (P13) · LATER · the MVP shipped as I28; open: column filters beyond KEV-only, CSV export of the worklist, a summary view for inputs over the 25-id cap · ~1 day
- **T13.5** · MCP `pivot_from_entities(ids)` (P13, after T13.1) · LATER · intersection or union across several entities · ~half day
- **I31** · Decide `docs/mitre/` · LATER, maintainer decision · a vendored ATT&CK Navigator 5.1.0 on end-of-life Angular 17, unused, served on the site origin outside the CSP; delete it or replace it with a Navigator layer export (T13.4) · decision, then ~1 hour
- **I33** · Branch protection with required checks · LATER, maintainer decision · GitHub Actions cannot be a ruleset bypass actor, so requiring checks would block the bot's data pushes; option: a small GitHub App token for the data workflows plus a bypass for that App · decision first, then ~half day

### 4.4 PARKED

- **I10** · Embedding similarity, "CVEs like this one" (P15) · PARKED · needs product validation first · ~3 to 5 days
- **I13** · RSS or webhook outputs · PARKED · needs server mode; waits on T13.6 · unsized
- **T13.6** · Live pipeline trigger from the search bar (was D4) · PARKED · needs a server-mode deployment and a use case that justifies leaving the static site · unsized

### 4.5 Acceptance criteria carried for open phases

- ISC-13.1: pasting 5 or more CVE ids renders a combined view in under 2 s for an indexed sample.
- ISC-13.2: a toggleable graph legend explains the 8 framework colors.
- ISC-13.3: the graph supports wheel zoom, drag pan, and a reset button.
- ISC-13.4: the export menu offers JSON, CSV, and Navigator JSON, each with the expected schema.
- ISC-13.5: `pivot_from_entities` returns intersection results for a multi-CVE input.
- ISC-13.6: the site renders without horizontal scroll at 360 px.
- ISC-13.7 (anti): multi-entity mode breaks no single-entity route; old hash URLs still resolve.
- ISC-14.1: a health JSON path returns last-run time, status, and per-processor durations.
- ISC-14.2: a failed Actions run produces a visible notification within 1 hour.
- ISC-14.3: CI fails when coverage drops below the configured floor.
- ISC-14.4: `mypy --strict src/tip_mcp/` returns zero errors.
- ISC-14.5 (anti): no observability addition adds a runtime dependency the pipeline does not already carry.

## 5. Shipped

| ID | What | Date | Evidence |
|----|------|------|----------|
| P0 | Initial master plan landed | 2026-05-08 | Decisions log |
| P9 (T9.1, T9.2, T9.3, T9.4) | Stabilized: stall was a stale local checkout, NVD fields verified on sampled CVEs, Playwright smoke suite and CI, master plan landed | 2026-06-09 | `855b506`, `9ca439d`, `c7c440f` |
| (no ID) | CVSS backfill for 75,945 historical CVEs; fallback v4.0 to v2 | 2026-06-11 | `cdc9d59` |
| (no ID) | MITRE ATT&CK sources de-pinned; techniques at v19.1 | 2026-06-11 | `001a034` |
| I22 (T9.5.1, T9.5.2) | MCP passes full KEV, SSVC, CISA CVSS, CVSS source, D3FEND semantics | 2026-06-20 | `685eedb` |
| I23, I25, I26, I27 (T9.5.3, T9.5.4, T9.5.5) | Triage badges and clickable references; graph label fix; `/health` 404 removed; sanitization audit, no vuln found | 2026-06-20 | `d719eb9` |
| I24 (absorbs I6) | One schema-driven CVE intel contract (`tip_intel.cve_blocks`) with a cross-seam parity test | 2026-06-20 | `8ae0c27` |
| I28 (T13.1 MVP) | Worklist and triage mode, `#/list`, capped at 25 ids | 2026-06-20 | `dfec5cb` |
| P9.5 | Surface-gap closure (the five rows above) | 2026-06-20 | rows above |
| (no ID) | NVD brownout: deeper retry and backoff, then fail loud on outage | 2026-06-21, 2026-07-09 | `e6f6078`, `94c5c62`, `c12bbee` |
| (no ID) | Vulnrichment DB restored after the 2026-09-25 wipe | 2026-09-26 | `169c6ef` |
| P9.6 | Review remediation: fail-closed writes, honest exit codes, atomic writes, zero dangling rels, MCP on `mcp` 2.x, frontend hardening, pinned CI, dead code removed; 66 of 66 ISCs closed | 2026-09-26 | PR #1 |
| I9 (partial) | Non-strict mypy in CI, clean on 27 files; `--strict` stays open | 2026-09-26 | PR #1 |
| I16 (partial) | Degraded, partial, or failed runs exit non-zero and show red; alerting stays open | 2026-09-26 | PR #1 |
| I19 (partial) | NVD pacing honors documented limits (6 s keyless, 0.6 s keyed); 429 capture stays open | 2026-09-26 | PR #1 |
| I20 (partial) | Unit tests in CI (PR #1); 90% coverage floor on `src/tip_mcp` (PR #4); `src/tip/` floor stays open | 2026-09-26 | PR #1, PR #4 |
| P10 (T10.1, T10.2, T10.3, T10.4, T10.5, T10.6) | `build_attack_chain`, `get_defenses`, `kev_status`; `.mcp.json`; scripted CVE-2023-44487 demo; six-tool READMEs | 2026-09-26 | PR #4 |
| (no ID) | Dependabot: `actions/checkout` 7.0.1, `actions/setup-python` 7.0.0 | 2026-09-26 | PR #2, PR #3 |
| (no ID) | Data runs build on the latest `main` (stale-base conflict) | 2026-09-26 | PR #6 |
| I29 | NVD-assigned CWEs kept apart from inherited parents across shards, index, site, and MCP; pillars skipped | 2026-09-26 | PR #5 |

## 6. Dropped

| ID | Item | Date | Reason |
|----|------|------|--------|
| P11 (T11.1, T11.2, T11.3, T11.4) | CVE2CAPEC parity check and REPLACE/AUGMENT paths | 2026-06-11 | CVE2CAPEC rejected in every posture; enrichment stays in-house; the successor work is I21 |
| P12 (T12.1, T12.2, T12.3, T12.4) | Local ctibutler and a `ctibutler-mcp` wrapper | 2026-06-11 | Its own conditional required P11 to pick REPLACE or AUGMENT; P11 picked neither, so it can never fire |
| T9.5 | Update the maintainer's private project list | 2026-09-27 | Outside this repo; not tracked here |

## 7. Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Repo reaches GitHub's 5 GB guidance around early 2027 at the current weekly rewrites (about 2.6 GB today) | High | I17: move shards off git history before then |
| Silent staleness: upstream outages now fail red, but nobody is told and the site shows no data age | Medium | I16 alerting and freshness banner |
| Single maintainer; knowledge and review live in one head | High | This plan, ISC-backed PRs, CI gates; I33 would enforce checks |
| Cross-vendor audits depend on a free Codex quota | Medium | T10.8 waits for the reset; no demo before it runs |
| Wrong or noisy mappings ship with authoritative labels | Medium | I29 labels inherited links; I30 and I32 fix APT linkage; I21 raises coverage with provenance tiers |
| Unused third-party code served on the site origin outside the CSP (`docs/mitre/`) | Low to Medium | I31 |
| Site size on Pages: `docs/` is 176.8 MB and grows with every run | Low | Watch with I17 monitoring |
| Worklist graph unmanageable for large inputs | Low | Capped at 25 ids; a summary view is T13.1 follow-up work |
| The roadmap derails focus | High if items run in parallel | P15 stays serial, one item at a time with its own criteria |

Rollback: every change lands on its own branch through a PR; data runs never force push.

## 8. Strategic anchors

- **S1: Strategic Rogue portfolio piece.** The MCP server is the headline item. It keeps MCP quality (T10.7, T10.8) ahead of breadth.
- **S2: Partner Network demo.** The demo must be honest and reproducible. T10.8 gates it.
- **S3: CCA Foundations evidence.** MCP work maps to the exam domains.
- **S4 and S5 retired.** "Cover all CVEs" was settled by the tiered all-CVE index. "Reduce in-house mapping debt" was settled the other way by the P11 decision: mapping stays in-house and gets better (I21, I29, I32).

## 9. Open decisions

Still open:

1. **I31:** delete `docs/mitre/` or replace it with a Navigator layer export.
2. **I32:** explicit APT attribution, or keep technique-overlap links labeled derived.
3. **I33:** required checks through a GitHub App token and bypass, or no required checks.
4. **I17 migration trigger:** when to move shards off git history, and to where.
5. **P15 order:** the order in §4 is a proposal; the maintainer may reorder.

Resolved:

- Auto-pipeline status: healthy, no stall (2026-06-09).
- CVE2CAPEC posture: rejected outright (2026-06-11).
- Worklist entity cap: 25 ids (2026-09-26).
- mypy scope: non-strict mypy in CI on all 27 files (2026-09-26); the `--strict` step and its order are tracked as I9.
- Pages size budget: replaced by the repo-size framing in I17 (2026-09-27).

## 10. Source documents

- `README.md`: user-facing overview and live status snapshot.
- `CLAUDE.md`: project rules for agents.
- `ISA.md`: the 2026-09-26 remediation record, claim by claim.
- `src/tip_mcp/README.md` and `src/tip_mcp/DEMO.md`: MCP install, tools, and the recorded demo.
- `.mcp.json`: project MCP registration.

Task ISAs for P10, I29, and later work live in the maintainer's private workspace and are not in the repo. The design specs this plan once cited under `docs/superpowers/` are not in the repo either; git history is the record.

## 11. Decisions log

Append-only, newest first. Older entries are kept verbatim.

- 2026-09-27: Plan restructured to v2.0. Status set reduced to NOW, NEXT, LATER, PARKED, DONE, DROPPED. The Changelog and Verification sections were folded into the Shipped table; git log is the changelog. P12 marked DROPPED because its conditional can no longer fire. T13.3 collision resolved: the live pipeline trigger became T13.6. New items T10.7, T10.8, and I30 to I33 moved here from private task notes.
- 2026-09-27: Manual early runs of both data workflows ahead of the weekly schedule. Vulnrichment did a full resync to 188,261 entries (from 2,567) after the truncated-compare fix. The runs exposed a stale-base conflict: a run queued behind the other data run checked out its trigger SHA, so its final rebase conflicted on `lastUpdate.txt`. PR #6 makes both data workflows fast-forward to the latest `main` right after checkout.
- 2026-09-26: I29 policy is "skip pillars and label". The ten CWE-1000 pillar parents are never added; other one-level parents are kept, tagged inherited, and published apart from NVD-assigned CWEs. Measured on CVE-2024 (36,772 records with CWEs), re-derived with the assigned set approximated by dropping any CWE that is a ChildOf parent of another listed CWE: technique coverage 78.3% to 76.6%, techniques per CVE 7.91 to 5.43, CVEs linked to T1134 2,254 to 1,519. The earlier count on the shards then published read 79.2%, 8.08, and 2,424 as the baseline; direct links only give 26.7%, 1.89, and 511. CVE-2023-44487 had mapped to T1134, T1539, and T1606 only through CWE-664, a parent NVD never assigned; it re-derives to CWE-400 assigned, nothing inherited, and T1499 only. Merged as PR #5.
- 2026-09-26: P10 merged as PR #4 with the demo anchor on T1499 (entry below). The fresh-context review changed three things before merge: chains now hold only the technique's own CVE rels (60 of 697 techniques had differed; 0 after), every element carries its weakest-hop tier, and the review found the parent-CWE problem that became I29.
- 2026-09-26: Review remediation merged as PR #1. All 66 ISCs closed, including ISC-59 to ISC-66 from the Forge cross-vendor audit. The weekly CVE pipeline was re-enabled after merge.
- 2026-09-26: P10 demo anchor moved from T1498 to T1499. Probe on the regenerated index: T1498 (Network Denial of Service) has 0 CAPEC links, so `build_attack_chain("T1498")` can only return an empty chain; T1499 (Endpoint Denial of Service) has 3 CAPECs and 11 D3FEND defenses, and CVE-2023-44487 maps to T1499, not T1498. (Corrected 2026-09-26 after the fresh-context review: the first probe also reported 52 CWEs and 19 CVEs, counts from a walk that followed CWEs inheriting the CAPECs up the ChildOf chain. With the chain restricted to the technique's own CVE rels, the regenerated index gives 17 CVEs, all KEV, explained through 5 CWEs, 3 of them flagged inherited.) ISC-10.2, ISC-10.3, and ISC-10.5 are read with T1499. T1498 stays in the test story as the honest empty-chain case: ok, empty lists, a `meta.note`, and its 11 defenses.
- 2026-09-26: the P10 scope doc this plan cites as canonical (`docs/superpowers/specs/mcp-server-scope.md`, §5.4 to §5.6) does not exist in the repo. P10 contracts were taken from T10.1 to T10.6 and ISC-10.1 to ISC-10.9 in this plan. `kev_status` returns `known_ransomware_campaign_use` (the KEV catalog field) in place of the `known_campaigns` named in T10.3, plus the other KEV catalog fields, and `ssvc` in place of `ssvc_decision`.
- 2026-09-26: P10 builds reverse adjacency (target to incoming edges) on the MCP loader, once and lazily, instead of changing the entity-index generator. The graph stores capec to technique and cwe to capec but not the reverse, so a forward walk from a technique finds nothing.
- 2026-09-26: pytest-cov added to `requirements-dev.txt` with the principal's approval (same 7-day cooldown, hash-locked). `tests.yml` now enforces `--cov-fail-under=90` on `src/tip_mcp`; the pipeline core still has no coverage floor.
- 2026-09-26: P9.6 review remediation decisions (full detail in `ISA.md` Decisions). Restore vulnrichment_db.json on `main` (`169c6ef`) and pause the weekly `Run CVE Pipeline` until this branch merges; deliver via branch `fix/review-2026-09-26` + PR, principal merges, no history rewrite for the existing repo growth. Layer 2 (curated CVE) redefined as KEV, APT-linked, or SSVC exploitation `active`: curated CVEs drop from 2,971 to 1,726 (every KEV CVE) on the next pipeline run, all others stay reachable via shard fallback. Reference-DB write floor set at 50% of the existing record count, plus a stricter refusal of a zero-record write even when no file exists yet. The APT-linked clause is inert (APT_GROUPS never populates from technique overlap) and stays that way rather than tagging 60% of all CVEs as noise. Async/aiohttp port rejected outright (NVD pacing makes the fetch serial by nature, the policy text is corrected instead of the code). Three requirements files hash-locked via `uv pip compile --generate-hashes` with a 7-day cooldown, installed with `pip --require-hashes`.
- 2026-06-20 — Removed `Plans/ROADMAP.md`. MASTER_PLAN is the sole plan of record; the superseded ROADMAP added no value in-tree. Git history retains it. Updated the `supersedes` frontmatter, the intro line, and the §9 source-doc list; earlier P9 ISC/narrative mentions of ROADMAP are left as historical record.
- 2026-06-20 — Removed two obsolete files: `Plans/2026-04-29_cve2capec-ctibutler-integration.md` (superseded — CVE2CAPEC rejected at P11; content absorbed into P11/P12) and the unreferenced root-level `d1-after-pipeline-layer2-with-desc.png` screenshot. `Plans/ROADMAP.md` retained as frozen historical record; `CLAUDE.md` retained as active project rules. Git history preserves the removed files. Source-doc list (§9) updated.
- 2026-06-20 — Deployed-state review (technical + usability, live-probed). Root finding: `entity_index_generator.py` is a lossy manual re-projection with a 3-place hand-maintained field allowlist; ingested intelligence (SSVC, full KEV, CVSS source/version, D3FEND semantics) is stripped before reaching the website OR MCP, and the MCP surface is strictly weaker than the website. Logged as I22–I28; I6 absorbed into I24.
- 2026-06-20 — Sequencing decision (Advisor-backed): insert P9.5 ahead of P10. I22 (MCP shard-passthrough) is a Phase B prerequisite — `kev_status`/`get_defenses`/`build_attack_chain` consume exactly the stripped fields. Scope the pre-MCP fix to MCP-only; defer the schema-driven generator rewrite (I24) to post-demo to avoid SPA regression before the Partner Network demo. Quick wins I23/I25/I26 run alongside in P9.5.
- 2026-06-09 — P9 executed. T9.1 resolution: fast-forward pull (local ahead 0 / behind 52; every remote commit was auto-pipeline `[skip ci]` data maintenance — pipeline ran healthy through the entire 2026-05-08 → 2026-06-09 stall; daily + weekly Actions runs all green).
- 2026-06-09 — T9.2 finding: 5 sampled 2026 CVEs all carry DESCRIPTION/PUBLISHED/LAST_MODIFIED/REFERENCES. CVSS null on 2/5 (CVE-2026-46395, CVE-2026-8714) — verified against live NVD: both unscored upstream (status `Deferred` / `Awaiting Analysis`). Pipeline is faithful; CVSS is expected-null for unanalyzed NVD records. No P9.2 followup needed.
- 2026-06-09 — T9.4 refinement: lastUpdate.txt NOT manually edited. It is auto-pipeline-owned (written each run; current as of today's 06:00 UTC run). A manual timestamp would misrepresent data freshness.
- 2026-06-09 — T9.3 implementation: pytest + playwright chosen over bun test (repo is Python/pytest; MASTER_PLAN blessed either). CI job is schedule-based (07:00 UTC daily, after the 06:00 db update deploys) + workflow_dispatch — push-triggered runs would race the Pages deploy.
- 2026-05-08 — Created MASTER_PLAN.md as new single source of truth. Roadmap becomes pointer file. Reason: 2026-04-29 CVE2CAPEC plan + 2026-04-24 ROADMAP + ad-hoc memory notes had drifted out of sync; one canonical doc is required for the next two weeks of work.
- 2026-05-08 — Sequence locked as P9 → P10 → P11 → P12 → P13 → P14 → P15. Reason: portfolio impact (S1, S2, S3) gates pre-CVE2CAPEC migration; parity check (P11) gates P12 to avoid building ctibutler against a HOLD outcome.
- 2026-05-08 — P11 added as a hard gate ahead of P12 because the 2026-04-29 proposal claims CVE2CAPEC obsoletes 2026-04-24 surgery; we will not act on that claim without evidence.
