---
task: "Harden data workflows after the 2026-09-30 Vulnrichment 403"
slug: 20260930-102000_tip-workflow-hardening
project: Threat_Intelligence_Pipeline
phase: building
progress: 0/22
started: 2026-09-30T17:20:00Z
updated: 2026-09-30T17:20:00Z
principal_stated_goal: "yes, push and merge, and add the always-clone change and fix the other issues as well"
principal_stated_goal_source: prompt
principal_stated_goal_signal: 2
principal_stated_goal_locked: 2026-09-30T17:15:00Z
context_sufficient: true
interview_invoked: false
---

## Problem

The daily Update Reference Databases run failed on 2026-09-30 (run 36712483756) because Vulnrichment called api.github.com without auth and hit the shared runner's per-IP limit. PR #28 authenticated the two API calls. A follow-up sweep found the same class of failure still open: the Vulnrichment delta loop makes up to 299 anonymous github.com raw fetches a day with no retry, five other reference fetches share raw.githubusercontent.com with no retry, the ATT&CK STIX bundle is downloaded two or three times per run, reference downloads borrow `api.nvd.timeout` (30s) instead of their own timeout, the whole `error_handling` block in config.json is read by nothing, and every cron fires on the top of the hour. Because the pipeline fails closed, any one of these blocks the whole day's publish.

## Vision

A transient upstream hiccup costs a few seconds of backoff, not a red run and an issue. The daily run makes one authenticated API call and one git clone for Vulnrichment instead of hundreds of anonymous fetches, downloads the STIX bundle once, and config.json only says things the code actually does.

## Out of Scope

- Fail-closed publish semantics. One failed source still blocks publishing; that is deliberate.
- Sunday queue cancellation in the `tip-data` concurrency group. The 36h staleness canary is the backstop.
- Running smoke-local on data commits.
- EPSS retry behavior. It has its own retry loop with its own tests; moving it is a semantic change nobody asked for.
- The D3FEND per-technique retry and the NVD retry. Both already retry correctly.
- New third-party dependencies (repo CLAUDE.md dependency policy).

## Constraints

- No new packages. The retry helper uses `requests` and the standard library only.
- The helper calls `requests.get` internally so every existing test stub on `requests.get` keeps intercepting.
- Tokens stay in headers, only to api.github.com, never in a URL or a log line.
- Fail-closed stays intact: a failed fetch or clone leaves the on-disk DB and state byte-identical and reports failure.
- Sequential PRs to main, each with green CI and a non-builder review PASS before merge.

## Goal

"yes, push and merge, and add the always-clone change and fix the other issues as well". Vulnrichment refreshes by shallow clone whenever upstream moved, every reference-data fetch retries 429 and 5xx with capped backoff, the STIX bundle downloads once per process, reference downloads use their own timeout, dead config is gone, and crons run off the hour. All of it merged to main with CI green.

## Features

### F1 · Vulnrichment always clones
Why: the anonymous per-file loop is the remaining way today's failure recurs, and the clone path already exists and is proven.

- [ ] ISC-1: When HEAD differs from the stored sha, `update()` refreshes through `_bootstrap_clone()` and makes no compare or raw_url request.
- [ ] ISC-2: When HEAD equals the stored sha, `update()` returns True, makes no clone, and leaves the DB byte-identical.
- [ ] ISC-3: The HEAD check still sends `Authorization: Bearer <GITHUB_TOKEN>` when the token is set.
- [ ] ISC-4: A failed HEAD check returns False with DB and state byte-identical and no clone.
- [ ] ISC-5: A failed clone returns False with DB and state byte-identical.
- [ ] ISC-6: The compare code, `_compare_is_truncated`, and both `COMPARE_*_CAP` constants are removed.
- [ ] ISC-7: Anti: no request to any host other than api.github.com leaves `vulnrichment_processor.py`.

### F2 · Shared retrying fetch
Why: one throttle event on a shared host should cost backoff, not a failed run.

- [ ] ISC-8: `tip.utils.http.get_with_retry` retries on 429, 500, 502, 503, 504 and on connection errors or timeouts, up to 3 attempts, with exponential backoff.
- [ ] ISC-9: A numeric `Retry-After` header sets the wait, capped at 60 seconds.
- [ ] ISC-10: A 4xx other than 429 returns immediately with no retry.
- [ ] ISC-11: Retry log lines carry URL and status only, never headers.
- [ ] ISC-12: KEV, CTID (tree and mapping), CAPEC/CWE zips, the D3FEND ontology, APT groups, techniques, and campaigns all fetch through `get_with_retry`.
- [ ] ISC-13: Anti: no new entry in any requirements `.in` file.

### F3 · STIX bundle once per run
Why: the same 40 MB bundle was downloaded two or three times per run from a throttled host.

- [ ] ISC-14: Techniques, APT groups, and campaigns share one cached STIX download per process, keyed by URL.
- [ ] ISC-15: A failed STIX download is not cached; the next caller retries.

### F4 · Reference download timeout
Why: a 40 MB bundle on a 30s NVD timeout is borrowing a budget meant for something else.

- [ ] ISC-16: config.json has `database.download_timeout`, and every reference-data fetch reads it.
- [ ] ISC-17: Anti: `api.nvd.timeout` is read only by the NVD fetch.

### F5 · Dead config removed
Why: config that looks active but isn't misleads whoever reads it next.

- [ ] ISC-18: The `error_handling` block is gone from config.json, and the full test suite passes.

### F6 · Crons off the hour
Why: GitHub delays top-of-hour schedules the most; the smoke-test comment also overclaims ordering.

- [ ] ISC-19: No workflow cron has minute `0`.
- [ ] ISC-20: The smoke-test cron comment no longer claims it runs after the database deploy.

### F0 · Cross-cutting
Why: the changes only count if they ship through the same gates as everything else.

- [ ] ISC-21: Each PR merges with CI (tests, CodeQL) green and a non-builder review PASS.
- [ ] ISC-22: Anti: the full local suite has no new failures versus main (the two MCP stdio smoke tests fail on main in the full local run).

## Test Strategy

| isc | type | check | threshold | tool | anchors_to |
|-----|------|-------|-----------|------|------------|
| ISC-1 | unit | moved HEAD calls clone, no compare/raw URL requested | pass | pytest | Goal |
| ISC-2 | unit | same HEAD returns True, no clone, DB bytes equal | pass | pytest | Goal |
| ISC-3 | unit | HEAD request carries Bearer header | pass | pytest | Constraints |
| ISC-4 | unit | HEAD ConnectionError returns False, bytes equal, clone not called | pass | pytest | Constraints |
| ISC-5 | unit | clone failure returns False, bytes equal | pass | pytest | Constraints |
| ISC-6 | static | rg finds no compare/truncation symbols | 0 hits | rg | Goal |
| ISC-7 | unit | only api.github.com requested across moved and unchanged paths | pass | pytest | Constraints |
| ISC-8 | unit | 503 then 200 returns 200 after 2 calls; ConnectionError x3 raises | pass | pytest | Goal |
| ISC-9 | unit | Retry-After 5 sleeps 5; Retry-After 999 sleeps 60 | pass | pytest | Goal |
| ISC-10 | unit | 404 returns after 1 call | pass | pytest | Goal |
| ISC-11 | unit | caplog on retry holds no header value | pass | pytest | Constraints |
| ISC-12 | static | rg for bare requests.get in listed processors | 0 hits | rg | Goal |
| ISC-13 | diff | git diff on *.in files | empty | git | Constraints |
| ISC-14 | unit | three callers, one requests.get | 1 call | pytest | Goal |
| ISC-15 | unit | fail then succeed makes 2 downloads | pass | pytest | Goal |
| ISC-16 | static | key present; rg download_timeout at each site | present | rg | Goal |
| ISC-17 | static | rg api.nvd.timeout outside cve_processor | 0 hits | rg | Goal |
| ISC-18 | suite | config.json lacks key; pytest | pass | pytest | Goal |
| ISC-19 | static | rg "cron: '0 " in workflows | 0 hits | rg | Goal |
| ISC-20 | static | smoke-test.yml comment | no ordering claim | rg | Goal |
| ISC-21 | ci | gh pr checks all pass; review verdict PASS | pass | gh | Constraints |
| ISC-22 | suite | full pytest vs main | same 2 known failures | pytest | Constraints |

## Decisions

- 2026-09-30: The retry helper wraps `requests.get` instead of mounting urllib3 `Retry` on a Session. About 15 test files stub `requests.get`, and a Session bypasses every stub.
- 2026-09-30: A failed Vulnrichment HEAD check returns False rather than falling back to a clone. It keeps the closed root ISA's ISC-6 test meaningful, and the check is now authenticated.
- 2026-09-30: Ship as three sequential PRs (F1, then F2 to F5, then F6), each reviewed and merged before the next.
- 2026-09-30: The whole `error_handling` block goes, not just the two sub-keys; nothing reads `enable_*` or `alert_thresholds` either (error_handler.py hardcodes its thresholds).

## Verification
