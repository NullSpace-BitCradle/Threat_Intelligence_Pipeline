# Threat Intelligence Pipeline — Project Rules

Python 3.13 · aiohttp · pandas · mypy. Pip + `requirements.txt` (not uv).

## Dependency policy (supply-chain hardening)

This is a security tool. Its dependency surface is part of its threat model.

- **Every dependency earns its place.** Do not add a new third-party package without asking first. Prefer the standard library, or rebuilding a small function inline, over importing a whole library for one helper. Each new package is new attack surface (slop-squatting, typosquatting, post-install hooks, maintainer compromise).
- **Pin with intent.** `requirements.txt` currently uses loose `>=` lower bounds on every package — meaning a fresh `pip install -U` can resolve to a *just-published* (and potentially compromised) release with no cooldown. When you touch deps, move toward pinned exact versions (`==`) for the runtime set, and regenerate from a tested environment. Do not repin blindly — pin from a known-good resolved set and run the test suite before committing.
- **Hash-verify in CI.** Aspire to `pip install --require-hashes` against a hashed lockfile so a tampered artifact fails the build. If/when this migrates to `uv`, use `[tool.uv] add-bounds = "exact"` + `exclude-newer` (cooldown window) + `uv sync --locked` in CI.
- **No new transitive trust without review.** When a PR adds or bumps a dependency, state *why* in the PR and what it replaced.

## Stack conventions

- Type-check with mypy (config in `pyproject.toml`); tests via pytest (`testpaths = ["tests"]`).
- Async I/O via aiohttp — no blocking `requests` in hot paths.

<!-- Provenance: added 2026-06-05. Source: Dave Ebbelaar, "Your Pip Install Is a Backdoor" (bw1ZLzdXJn4). Scoped to pip reality; uv-specific config noted as future migration only. -->
