# Threat Intelligence Pipeline - Project Rules

Python 3.13 · requests · mypy. Lockfiles are compiled with `uv`; installation and CI still use pip (`pip install --require-hashes -r requirements.txt`, etc).

## Dependency policy (supply-chain hardening)

This is a security tool. Its dependency surface is part of its threat model.

- **Every dependency earns its place.** Do not add a new third-party package without asking first. Prefer the standard library, or rebuilding a small function inline, over importing a whole library for one helper. Each new package is new attack surface (slop-squatting, typosquatting, post-install hooks, maintainer compromise).
- **Pin with intent.** Three lockfiles carry exact, hash-locked pins: `requirements.txt` (runtime, only `requests` and its transitives), `requirements-dev.txt` (pytest, playwright, pytest-playwright, mypy), and `requirements-mcp.txt` (`mcp==2.2.0` and its transitives). Each is compiled from its own `*.in` source via `uv pip compile <name>.in -o <name>.txt --generate-hashes -p 3.13 --exclude-newer <7 days ago>` (the exact command lives in a header comment in each `.in` file), so a fresh compile never resolves to a package published in the last week. To bump a version, edit the `.in` file and recompile; do not hand-edit the `.txt` lockfiles. Run the test suite before committing a recompiled lockfile.
- **Hash-verify in CI.** CI installs with `pip install --require-hashes -r <file>` against the hashed lockfiles above, so a tampered artifact fails the build. `uv` compiles the lockfiles; pip still does the install, in CI and locally alike. This is the built setup, not a future migration.
- **No new transitive trust without review.** When a PR adds or bumps a dependency, state *why* in the PR and what it replaced.

## Stack conventions

- Type-check with mypy (config in `pyproject.toml`); tests via pytest (`testpaths = ["tests"]`).
- NVD fetches are serial, over `requests`, paced to the documented rate limit (6 seconds between requests keyless, 0.6 seconds with an API key). This is a hard constraint, not an oversight: the limit is a budget per requester (per IP without a key, per key with one), so parallel workers would share that one budget rather than adding throughput. Neither `aiohttp` nor `pandas` is used anywhere on the run path; both are removed from the requirements.

<!-- Provenance: added 2026-06-05. Source: Dave Ebbelaar, "Your Pip Install Is a Backdoor" (bw1ZLzdXJn4). Scoped to pip reality; uv-specific config noted as future migration only. -->
