---
task: "Fix every 2026-09-26 review finding and ship recommended improvements"
slug: 20260926-112500_tip-review-remediation
project: Threat_Intelligence_Pipeline
phase: climbing
progress: 54/66
started: 2026-09-26T18:25:00Z
updated: 2026-09-26T18:25:00Z
principal_stated_goal: "Write up the ISA for fixing all the found issues and implementing recommended improvements then execute."
principal_stated_goal_source: prompt
principal_stated_goal_signal: 2
principal_stated_goal_locked: 2026-09-26T18:09:00Z
context_sufficient: true
interview_invoked: true
---

## Problem

A four-reviewer code review on 2026-09-26 found that TIP reports success when it fails. Reference DB downloads that fail write empty files and commit them (vulnrichment_db.json went 2333 to 0 on 2026-09-25, the 21st wipe in history). `run_pipeline.py` exits 0 on degraded runs, so the July fail-loud fix never reached CI. Shard writes are not atomic. 2,864 of 2,971 curated CVEs carry parent-CWE links that resolve to nothing, and 3,514 technique links dangle. The MCP server does not import on the mcp SDK a fresh install resolves. The search route is unreachable. No CI job runs the 83 unit tests or mypy. The repo grows ~135 MB per week because every shard is rewritten weekly. About 3,300 lines of utils/monitoring code do nothing useful, and two of them (`web_interface.py`) are an exposure when run.

## Vision

The pipeline tells the truth about itself. A bad upstream day produces a red CI run and leaves yesterday's good data on Pages, never a green run and an empty file. Every link on the site and every MCP answer resolves to a real entity. A pull request cannot merge while the unit suite or mypy is red. The maintainer opens the repo after three months away and finds it smaller, honest, and ready for P10, not a pile of half-wired modules to re-learn.

## Out of Scope

- MCP Phase B tools (`build_attack_chain`, `get_defenses`, `kev_status`). This run clears their blockers (P10 readiness); building them is P10.
- Rewriting git history to reclaim the existing 2.4 GB. Principal decision 2026-09-26: stop the growth only.
- Porting the pipeline to async aiohttp. NVD pacing makes the fetch serial by nature; the policy text is corrected instead.
- Deleting or upgrading the vendored ATT&CK Navigator under `docs/mitre/`. It is served at a public URL that may be linked externally; that is the maintainer's call (Remaining Work).
- New entity types, new frameworks, EPSS, or any P15 improvement.
- Merging to main. The principal merges the PR.

## Principles

- Last-good data beats fresh-but-wrong data. When in doubt, keep what shipped yesterday and fail loudly.
- A green check means something was verified. A CI step that cannot fail is not a check.
- Every dependency is attack surface; code nothing calls is attack surface too.
- A link that resolves to nothing is a bug, not a styling issue.

## Constraints

- Python 3.13, pip + `requirements.txt` (repo CLAUDE.md). No new third-party runtime dependency without the principal's say.
- Static GitHub Pages hosting stays. No server-mode anything.
- Published data formats (`entity_index.json` v1.5 shape, shard JSONL-gz per year, `cve_ids_index.json`) stay backward compatible for the SPA and MCP; changes are additive.
- Work lands on branch `fix/review-2026-09-26` and a PR. Nothing else is pushed to main in this run beyond the 169c6ef restore.
- `Run CVE Pipeline` stays disabled until the PR merges.
- No network calls to NVD from tests. Tests use fixtures.
- No co-author trailer on commits.

## Goal

"Write up the ISA for fixing all the found issues and implementing recommended improvements then execute." Done means every finding in the 2026-09-26 review is fixed and verified or explicitly dispositioned in Decisions, the recommended improvements (fail-closed writes, CI test and type gates, pinned and trimmed dependencies, dead-code removal, growth stop) are in the PR, and the full unit suite plus mypy pass in CI on the branch.

## Features

### F0 · Cross-cutting
Why: the whole PR is only worth merging if the gates that prove it keep proving it after merge.

- [x] ISC-1: `pytest -q --ignore=tests/smoke` passes on the branch with at least 83 tests plus the new regression tests.
- [x] ISC-2: `mypy` (as configured in pyproject, run the way CI runs it) exits 0 on the branch.
- [ ] ISC-3: A PR from `fix/review-2026-09-26` to main exists and its CI checks are green.
- [ ] ISC-4: Anti: no file under `docs/data/` or `docs/database/` is modified by this PR except through a regenerated, verified pipeline output described in Decisions.
- [ ] ISC-5: Anti: no commit on the branch contains an em dash, en dash, or double hyphen in its message.

### F1 · Fail-closed reference data
Why: a failed upstream fetch must leave the last good file in place and turn the run red.

- [x] ISC-6: `_update_vulnrichment_database` returns failure (not the empty dict) when `VulnrichmentProcessor.update()` returns False; a unit test simulating a GitHub API error asserts the on-disk DB is unchanged.
- [x] ISC-7: Vulnrichment incremental update detects a truncated compare (300-file cap or missing commits) and falls back to a full resync instead of advancing state past unprocessed files; unit test with a 300-file compare fixture.
- [x] ISC-8: Vulnrichment per-file fetch failures during incremental update prevent advancing `last_commit_sha`; unit test.
- [x] ISC-9: Every reference DB writer (CWE, CAPEC, techniques, D3FEND, KEV, vulnrichment, groups, OWASP, campaigns) refuses to overwrite when the new record count is below a floor relative to the existing file; one parametrized test covers all writers.
- [x] ISC-10: The CWE archive is fetched over https.
- [x] ISC-11: The CWE zip is extracted to a temp directory, not the repo root, and only the expected XML member is read.

### F2 · Honest exit codes
Why: CI is the only watcher, so the process exit code is the alarm.

- [x] ISC-12: `run_pipeline.py --force` exits non-zero when any step is `degraded`; test drives `run_pipeline.main()` with a stubbed orchestrator returning `degraded_steps: 1`.
- [x] ISC-13: `run_pipeline.py --db-only` exits non-zero when any reference DB update is `partial` or failed; test.
- [x] ISC-14: Entity index generation failure is a failed step (non-zero exit), not a warning; test raises inside the generator and asserts exit 1.
- [x] ISC-15: `lastUpdate.txt` advances only on a fully successful run; test.

### F3 · Atomic, lossless shard and index writes
Why: a kill or exception mid-write must never leave a truncated or partial published file.

- [x] ISC-16: Every writer of a published file (shards, entity/search/cve_ids index, all reference DBs) writes to a temp file in the same directory and `os.replace`s it; `rg` shows no direct `open(... 'w')`/`gzip.open(... 'wt')` on a published path.
- [x] ISC-17: An exception raised mid-write leaves the previous file byte-identical; test.
- [x] ISC-18: A malformed line in an existing shard fails the save loudly instead of being silently dropped on rewrite; test.
- [x] ISC-19: A truncated gzip shard produces a clear error naming the file, not an unhandled EOFError deep in a later step; test.
- [x] ISC-20: The three index files are written so a failure cannot publish a mix of old and new (all temp files written first, then replaced); test.

### F4 · Correlation correctness
Why: every relationship the site or MCP shows must point at an entity that exists.

- [x] ISC-21: CVE CWE lists (including parent expansion) are normalized to `CWE-<n>` at ingestion; unit test on the mixed `['74','CWE-79']` shape.
- [x] ISC-22: The generator normalizes CWE and technique ids when linking, so existing shards also produce resolvable rels; unit test.
- [x] ISC-23: Parent-CWE expansion uses one definition shared by the processor and generator (full ChildOf chain or one level, decided and recorded in Decisions); test.
- [x] ISC-24: The generator drops (and counts in meta) any rel whose target entity does not exist; a test asserts zero dangling targets in a generated fixture index.
- [x] ISC-25: Regenerating the entity index from the current on-disk shards and DBs yields zero dangling rel targets (probe script over the output).
- [x] ISC-26: Layer 2 (curated CVE) inclusion no longer depends on vulnrichment_db membership alone, so a vulnrichment wipe or full resync cannot shrink or explode the index; regenerated `entity_index.json` includes every KEV CVE and stays at or under 20 MB.
- [x] ISC-27: The NVD crawl uses `totalResults` to decide completion; a short page before `totalResults` is reached is retried or fails, never treated as end of corpus; test.
- [x] ISC-28: NVD request pacing honors the documented limits (6 s between requests keyless, 0.6 s keyed) via one small helper; test asserts the computed delay per mode.
- [x] ISC-29: A resumed NVD fetch does not report a full refresh for a partial one: the resumed run keeps previously fetched items or is marked partial; test.

### F5 · MCP server works on the resolved SDK
Why: the headline portfolio piece must start and answer correctly from a fresh install.

- [x] ISC-30: `requirements-mcp.txt` pins an mcp version the server imports cleanly, and `python -c "from tip_mcp import server"` succeeds in a fresh venv from the pinned file.
- [x] ISC-31: A stdio smoke test starts the server, lists tools, and calls `lookup_entity` successfully.
- [x] ISC-32: `pivot_from_entity` and `search_threat_intel` accept the graph's type names (`defend`, `apt_group`) and map the legacy aliases (`d3fend`, `apt`); `pivot_from_entity("T1499","d3fend")` returns more than zero hits on real data.
- [x] ISC-33: The shard path emits the same rel type vocabulary as the entity path; test.
- [x] ISC-34: Entity ids are normalized (strip, uppercase for CVE/CWE/CAPEC/T-ids) before lookup, so `" cve-2023-44487 "` returns the same record as `"CVE-2023-44487"`; test.
- [x] ISC-35: The entity path returns `kev_detail`, `ssvc`, `cisa_cvss` from `entity_index.json` when shards are absent; test with a missing shards dir.
- [x] ISC-36: Shard lookups are cached per year and a miss is short-circuited via `cve_ids_index.json`; a repeat lookup of a CVE in the 2026 shard completes in under 0.2 s after first load (timed probe on real data).
- [x] ISC-37: Truncated gzip, bad UTF-8, and wrong-shaped index files return the documented `{ok:false}` envelope instead of raising; tests.
- [x] ISC-38: The parity test calls the real generator code path for the producer side, so deleting the generator's `cve_blocks.enrich` call makes it fail (verified by a temporary mutation).
- [x] ISC-39: `src/tip_mcp/README.md` matches the current tool vocabulary, counts, and shard fallback; the demo step 3 command returns results.

### F6 · Frontend correctness and hardening
Why: the site is a security tool's public face and must not dead-end or run unpinned third-party code.

- [x] ISC-40: `#/search/<query>` renders the multi-result search page (route ordering fixed); smoke test covers it.
- [x] ISC-41: d3 is vendored at a pinned version under `docs/` and loaded from the same origin, and `.gitignore` does not swallow it.
- [x] ISC-42: `docs/index.html` carries a CSP meta tag with `script-src 'self'`; the live-local page loads with zero CSP console errors.
- [x] ISC-43: Malformed percent-encoding in the hash and corrupt `localStorage` values do not break routing or init; tests.
- [x] ISC-44: A stale async render cannot overwrite a newer page (generation token); code probe plus manual repro in the browser.
- [x] ISC-45: The worklist caps input at 25 ids and says so in the UI.
- [x] ISC-46: Index and shard fetches check `res.ok` and show an error state instead of "0 entities" or "not found"; test.

### F7 · CI and supply chain
Why: nothing merges unverified, and nothing the bot runs can be swapped under it.

- [x] ISC-47: A CI workflow runs the unit suite and mypy on push and pull_request.
- [x] ISC-48: Every workflow pins actions to full commit SHAs and declares least-privilege `permissions:`.
- [x] ISC-49: Data workflows share a `concurrency:` group, set `timeout-minutes`, and never force-push: a rebase conflict fails the run.
- [x] ISC-50: Runtime requirements are pinned `==` from a tested resolution, with dev/test deps split into a separate file that the data workflows do not install.
- [x] ISC-51: `requirements.txt` lists no package that nothing imports (probe: rg per package).
- [x] ISC-52: A `.github/dependabot.yml` proposes updates for pip and github-actions.

### F8 · Dead code removal
Why: code that nothing calls still costs reading time, mypy errors, and exposure.

- [x] ISC-53: `web_interface.py`, `rate_limiter.py`, `error_recovery.py`, `config_validator.py` schema, `request_tracker.py`, `metrics.py`, `health_check.py` and the dead half of `performance_optimizer.py` are removed or reduced, with every call site updated; `rg` shows no importer left.
- [x] ISC-54: `run_pipeline.py --help` and `--db-only` still work after removal (the CLI surface drops only the removed flags, documented in README).
- [x] ISC-55: Logging writes each line once (single file handler); test.

### F9 · Stop repo growth
Why: an unchanged shard must not add a new blob to history every week.

- [x] ISC-56: Shards are written with deterministic gzip (fixed mtime, no filename header) and sorted record order, so re-writing identical content yields byte-identical files; test.
- [x] ISC-57: The daily run commits nothing when no data changed (`lastUpdate.txt` alone does not produce a commit); workflow logic probe.

### F10 · Docs match disk
Why: the maintainer's next return starts from docs that are true.

- [ ] ISC-58: README and `Plans/MASTER_PLAN.md` current-state numbers, test counts, CI description, and the July/September incidents match disk on the branch; repo CLAUDE.md async rule corrected to the serial-paced reality.

### F11 · Audit closures
Why: the cross-vendor audit found fail-open paths inside records, not whole files, that the diff never touched; done means those are closed too.

- [ ] ISC-59: A CVE whose enrichment throws is not written; its prior shard record stays byte-identical, and the step fails above 1% or 50 failures.
- [ ] ISC-60: Any non-404 D3FEND per-technique error fails the D3FEND update and keeps the previous defend_db.
- [ ] ISC-61: Anti: a data workflow dispatched from any ref other than main does not run its job.
- [ ] ISC-62: Any per-file error during a vulnrichment resync aborts it with no DB write and no state advance.
- [ ] ISC-63: A failure on the second replace in atomic_replace_many leaves all targets byte-identical to before.
- [ ] ISC-64: A malformed JSONL line in a shard yields the data_corrupt envelope instead of not_found.
- [ ] ISC-65: The MCP shard cache enforces a byte budget, not only a year count.
- [ ] ISC-66: search_threat_intel with a non-list types value returns an error envelope.

## Test Strategy

| isc | type | check | threshold | tool | anchors_to |
|---|---|---|---|---|---|
| ISC-1 | unit | pytest unit suite | 0 failures | pytest | Goal |
| ISC-2 | static | mypy as CI runs it | 0 errors | mypy | Goal |
| ISC-3 | ci | PR checks | all green | gh pr checks | Goal |
| ISC-4 | anti | git diff main --stat on docs/data, docs/database | only documented regenerations | git | Constraints |
| ISC-5 | anti | commit messages scanned for dashes | 0 hits | git log + rg | Constraints |
| ISC-6..9 | unit | simulated upstream failures | DB unchanged on disk | pytest | F1 |
| ISC-10..11 | code | rg config and extract path | https, tempdir | rg | F1 |
| ISC-12..15 | unit | run_pipeline.main exit codes | non-zero on degraded/partial | pytest | F2 |
| ISC-16 | code | rg for direct writes on published paths | 0 hits | rg | F3 |
| ISC-17..20 | unit | fault injection mid-write | previous bytes intact | pytest | F3 |
| ISC-21..24 | unit | normalization and dangling-rel tests | 0 dangling | pytest | F4 |
| ISC-25..26 | probe | regenerate index from disk, count dangling and size | 0 dangling, <=20 MB, all KEV present | python script | F4 |
| ISC-27..29 | unit | NVD client with fixture pages | per claim | pytest | F4 |
| ISC-30..31 | smoke | fresh venv import + stdio session | tool list + lookup ok | python | F5 |
| ISC-32..35,37 | unit | tool impl calls | per claim | pytest | F5 |
| ISC-36 | probe | timed repeat lookup on real data | < 0.2 s | python | F5 |
| ISC-38 | mutation | remove enrich call, run parity test | test fails | pytest | F5 |
| ISC-39 | doc | README demo command run | > 0 results | python | F5 |
| ISC-40..46 | browser | local serve + Interceptor + smoke suite | per claim | Interceptor, pytest-playwright | F6 |
| ISC-47..49 | ci | workflow read-back + a run | per claim | gh, rg | F7 |
| ISC-50..52 | code | requirements read-back, rg per package | 0 unused, all == | rg | F7 |
| ISC-53..55 | code+unit | rg importers, CLI run, log line count | 0 importers, CLI ok, 1 line | rg, python | F8 |
| ISC-56 | unit | write twice, compare bytes | identical | pytest | F9 |
| ISC-57 | workflow | commit step guarded on data diff | no-op run makes no commit | rg + local git probe | F9 |
| ISC-59..60,62..66 | unit | fault-injection tests red before fix | per claim | pytest | F11 |
| ISC-61 | ci | job-level ref guard read-back + actionlint | guard present | rg, actionlint | F11 |
| ISC-58 | doc | numbers in docs vs disk | match | python + rg | F10 |

## Decisions

- 2026-09-26 11:20: urgent restore landed on main as 169c6ef before this ISA: vulnrichment_db.json restored from 27edc17 and merged with the 299 entries rebuilt 09-26 (2567 total); `Run CVE Pipeline` disabled until this PR merges. Principal chose restore + pause.
- 2026-09-26 11:20: delivery via branch `fix/review-2026-09-26` + PR; principal merges. Growth fix limited to stopping growth, no history rewrite.
- 2026-09-26 11:25: the daily `Update Reference Databases` workflow stays enabled. Its wipe path can empty vulnrichment_db.json again before merge, but the shards are only rebuilt by the paused weekly run, so a daily wipe is recoverable by re-restore. Re-check the file before re-enabling the weekly run.
- 2026-09-26 11:40: ISA gate: 0 hard, 2 advisory. Bundled-claim advisory on ISC-21/23/27/46/47 accepted: each is one change with one probe.
- 2026-09-26 11:40: Layer 2 (curated CVE) rule becomes KEV or APT-linked or SSVC exploitation `active` (from the shard VULNRICHMENT block or vulnrichment_db). Plain vulnrichment membership no longer qualifies, because a full resync restores ~136k entries and would balloon the index. ISC-26 threshold (<=20 MB, all KEV present) is the falsifier.
- 2026-09-26 11:40: parent-CWE semantics (ISC-23): a CVE's CWE list gains one level of ChildOf parents (current behavior, kept); CAPEC inheritance walks the full chain (current generator behavior, kept). Different on purpose; both go through one shared id normalizer so neither emits bare numbers.
- 2026-09-26 11:40: reference DB write floor (ISC-9): refuse to replace an existing non-empty DB when the new count is under 50% of the existing count. Growth is always allowed, so a vulnrichment full resync passes.
- 2026-09-26 11:40: regenerated data is a probe, never a commit. Agents regenerate to scratch paths; nothing under docs/data or docs/database is staged. The pipeline republishes on its next run.
- 2026-09-26 11:40: execution waves by file ownership. Wave 1 parallel: F8 dead code, F5 MCP, F6 frontend. Wave 2 after F8 merges: F1+F2+F3+F4+F9 core as one agent (shared files), F7 CI. Wave 3: F10 docs, full suite, Forge audit, PR. `lastUpdate.txt` has no SPA consumer (rg over docs/js), so ISC-57 is safe.
- 2026-09-26 12:00: F8 escalation accepted: removing `@with_recovery` lets `_update_databases` raise instead of continuing with status failed. Both exit 1; fail loud matches Principles.
- 2026-09-26 12:00: F5 accepted: `search_threat_intel` with an unknown type now returns `invalid_type` (consistent with pivot); mcp pinned 2.2.0 on the 2.x MCPServer API; shard cache stores zlib-compressed lines, LRU 3 years, about 300 MB worst case.
- 2026-09-26 12:00: lockfiles compiled by uv with generate-hashes and an exclude-newer cooldown of 7 days; CI installs with pip require-hashes. The three lockfiles share no conflicting pins (checked).
- 2026-09-26 12:15: F6 merged (7a369f3). Playwright Chromium smoke suite 25/25 locally, including CSP-violation listener, stale-render repro with mutation check, and worklist cap. Interceptor real-Chrome pass is [DEFERRED-VERIFY]: Chrome was not running and launching it was denied by the permission classifier; Interceptor pass ran 12:05 after the principal enabled manual approval: search, CVE, worklist, malformed-hash routes verified in real Chrome; ISC-40..46 closed. Accepted F6 extras: worklist URL via history.pushState (removes the double build), form-action 'none' in CSP, Google Fonts left remote.
- 2026-09-26 12:40: core merged (3e11ab4). Consequence of the Layer 2 rule, surfaced to the principal: curated CVEs drop from 2,971 to 1,726 (every KEV CVE; SSVC active adds none beyond KEV today). The ~1,245 CVEs that qualified only by vulnrichment membership stay reachable through the all-CVE shard fallback on the site and in the MCP.
- 2026-09-26 12:40: APT_GROUPS is never populated (processor passes technique ids without the T prefix). Not fixed: repairing the lookup would mark 235,807 of 395,617 CVEs APT-linked through technique overlap, which is noise and would breach the 20 MB budget. The APT clause in Layer 2 is inert. Moved to Remaining Work.
- 2026-09-26 12:40: write floor also refuses a 0-record write when no file exists yet (stricter than recorded). Accepted: there is no legitimate empty reference DB; D3FEND-disabled skips the write instead.
- 2026-09-26 12:40: the first weekly run after merge rewrites every shard once (normalized ids, deterministic gzip), adding one last ~135 MB to history; unchanged shards are byte-identical after that.
- 2026-09-26 12:45: Forge (GPT) cross-vendor audit returned fail with 3 critical, 1 high, 3 medium, 1 low. All 8 adopted as ISC-59..66 and dispatched to one fix worker. Blind spot it named, recorded as a learning: the fail-closed work guarded whole-file writes but left per-record and per-technique swallows in untouched code, and a 50% count floor stops wipes but does not prove completeness.
- 2026-09-26 11:25: `docs/mitre/` Navigator bundle left untouched (public URL, principal's call); recorded in Remaining Work.

## Learning

- conjectured: guarding whole-file writes (atomic replace, count floor, honest exit code) makes the pipeline fail closed.
  refuted by: Forge audit 2026-09-26: per-record and per-technique exception handlers inside untouched code still published partial data under an exit 0.
  learned: fail-closed has to be traced from every exception handler to the publish step, not from the writers backward; a diff-only review cannot see handlers the diff never touched.
  criterion now: ISC-59, ISC-60, ISC-62 (every swallow on the path to publish either fails the step or preserves prior data).

## Verification

- ISC-1: 236 passed at 3e11ab4
- ISC-2: mypy: no issues in 27 source files at 3e11ab4
- ISC-6: 536b805 test: API error leaves DB and state byte-identical
- ISC-7: 536b805 compare >=300 files falls back to resync (mocked)
- ISC-8: 536b805 per-file failure keeps last_commit_sha
- ISC-9: 536b805 write_reference_db parametrized 12 writers x 4 sizes
- ISC-10: 536b805 config.json:29 https
- ISC-11: 536b805 zips read in memory, rg no extractall
- ISC-12: 536b805 exit_code_for shared; degraded exits 1
- ISC-13: 536b805 db-only partial exits 1
- ISC-14: 536b805 generator failure is a failed step
- ISC-15: 536b805 lastUpdate only on clean run
- ISC-16: 536b805 rg residue only non-published paths
- ISC-17: 536b805 fsync failure leaves old bytes
- ISC-18: 536b805 ShardCorruptError on malformed line
- ISC-19: 536b805 truncated gzip names file
- ISC-20: 536b805 all temps before any replace
- ISC-21: da74e5c id_normalize test on mixed CWE list
- ISC-22: da74e5c generator normalizes ids
- ISC-23: da74e5c processor output == expand_cwe_list
- ISC-24: da74e5c meta.dropped_dangling_rels
- ISC-25: regen probe at 3e11ab4: 0 dangling
- ISC-26: regen probe at 3e11ab4: 7.55 MB, 0 of 1726 KEV missing
- ISC-27: da74e5c totalResults completion tests
- ISC-28: da74e5c nvd_request_delay 6.0 / 0.6
- ISC-29: da74e5c resumed fetch recorded partial
- ISC-56: 536b805 deterministic gzip, identical bytes across clocks
- ISC-30: d229e96 fresh venv import; test_stdio_smoke
- ISC-31: tests/tip_mcp/test_stdio_smoke.py
- ISC-32: probe pivot T1499 d3fend=11
- ISC-33: test_shard_path_uses_graph_vocabulary
- ISC-34: probe normalized equal True
- ISC-35: parity test entity path no shards
- ISC-36: probe repeat 0.0000s after 2.30s cold
- ISC-37: tests/tip_mcp corrupt input tests
- ISC-38: mutation: 4 failed with enrich removed
- ISC-39: d229e96 README demo step 3 = 11
- ISC-40: Interceptor read #/search/apache: Results for "apache"; smoke test_search_route_renders_results_page
- ISC-41: docs/vendor/d3-7.9.0.min.js; Interceptor pixel capture shows full relationship map
- ISC-42: Interceptor: page CSP blocks eval; 0 violations in smoke CSP test
- ISC-43: Interceptor #/cve/%E0%A4%A renders Entity not found; smoke malformed hash + storage tests
- ISC-44: smoke test_stale_shard_render_does_not_overwrite_newer_page + mutation
- ISC-45: smoke test_worklist_caps_at_25_and_says_so; Interceptor worklist table 2 rows
- ISC-46: smoke index and shard failure tests
- ISC-47: .github/workflows/tests.yml 1491320
- ISC-48: 1491320 actionlint clean
- ISC-49: 1491320 concurrency tip-data, rebase fails run
- ISC-50: f045d30 797dc3d hashed lockfiles, ci-sim install ok
- ISC-51: f045d30 only requests remains
- ISC-52: 1491320 .github/dependabot.yml
- ISC-53: ee172a2 monitoring removed, rg no importers
- ISC-54: tests/test_cli_surface.py
- ISC-55: tests/test_logging_single_handler.py
- ISC-57: 1491320 commit step diffs docs/data docs/database only

## Remaining Work

- [ ] Re-enable `Run CVE Pipeline` after the PR merges and vulnrichment_db.json is confirmed non-empty. Waits on principal merge.
- [ ] Decide the fate of `docs/mitre/` (Navigator 5.1.0 on Angular 17, EOL). Principal's call.
- [ ] Decide APT linkage: technique-overlap APT_GROUPS would tag 60% of all CVEs. Needs a tighter signal (campaign or explicit attribution) before it means anything.
- [ ] Branch protection on main requiring the new CI checks. Repo settings change, principal's call.
