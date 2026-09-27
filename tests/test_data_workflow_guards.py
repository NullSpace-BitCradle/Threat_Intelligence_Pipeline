"""The data workflows can only publish from main.

A workflow_dispatch from any other ref must not run the job, and the commit
step pushes only when the local branch is exactly one new data commit on top
of origin/main. Parsed as text (no YAML dependency); actionlint validates the
syntax separately.
"""
import json
import re
from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
DATA_WORKFLOWS = ["run-pipeline.yml", "update-databases.yml"]


def _job_header(text):
    """Lines of the single job, from its name to its first step."""
    jobs = text.split("\njobs:\n", 1)[1]
    return jobs.split("    steps:", 1)[0]


@pytest.mark.parametrize("name", DATA_WORKFLOWS)
def test_job_runs_only_on_main(name):
    text = (WORKFLOWS / name).read_text()
    assert "workflow_dispatch:" in text  # manual trigger stays
    header = _job_header(text)
    assert re.search(r"^    if: github\.ref == 'refs/heads/main'\s*$", header, re.M), header


@pytest.mark.parametrize("name", DATA_WORKFLOWS)
def test_push_guarded_by_single_commit_on_origin_main(name):
    text = (WORKFLOWS / name).read_text()
    step = text.split("- name: Commit and push if data changed", 1)[1]
    guard = step.index('"$(git rev-parse HEAD~1)" != "$(git rev-parse origin/main)"')
    push = step.index("git push origin HEAD:main")
    rebase = step.index("git rebase origin/main")
    assert rebase < guard < push
    assert "--force" not in step


@pytest.mark.parametrize("name", DATA_WORKFLOWS)
def test_syncs_to_latest_main_before_running(name):
    """A run queued behind another data run is checked out at its trigger SHA.
    It must fast-forward to the latest main before the pipeline runs, or its
    final rebase conflicts on lastUpdate.txt (2026-09-27 run 36288431648)."""
    text = (WORKFLOWS / name).read_text()
    sync = text.find("git pull --ff-only origin main")
    run = text.find("python run_pipeline.py")
    assert sync != -1, "no sync-to-latest-main step"
    assert sync < run, "sync must happen before the pipeline runs"


# I16 alerting guards.

ALL_WORKFLOWS = sorted(p.name for p in WORKFLOWS.glob("*.yml"))
ALERTING_JOBS = {
    "update-databases.yml": {"update"},
    "run-pipeline.yml": {"pipeline"},
    "smoke-test.yml": {"smoke-live"},
}


def _run_blocks(text):
    """Every run: script, as (line number, body): the run: line itself plus
    every following line indented deeper than the run: key."""
    lines = text.splitlines()
    blocks = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(?:- )?run:(.*)$", line)
        if not m:
            continue
        indent = len(m.group(1))
        body = [m.group(2)]
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            body.append(nxt)
        blocks.append((i + 1, "\n".join(body)))
    return blocks


def _jobs(text):
    """Map job id to its text (top-level jobs are indented two spaces)."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\s*$", body, flags=re.M)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


def _step(job_text, name):
    step = job_text.split(f"- name: {name}\n", 1)[1]
    return step.split("\n      - ", 1)[0]


def test_run_block_parser_sees_expressions():
    """The parser would catch a violation (guards the guard)."""
    bad = "      - name: x\n        run: |\n          echo ${{ github.ref }}\n"
    assert any("${{" in body for _, body in _run_blocks(bad))


@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_no_expressions_inside_run_blocks(name):
    text = (WORKFLOWS / name).read_text()
    blocks = _run_blocks(text)
    assert blocks, "no run blocks found; parser broken?"
    for lineno, body in blocks:
        assert "${{" not in body, f"{name}:{lineno} interpolates an expression in run:"


def _unquote(value):
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def _strip_comment(line):
    """Drop a trailing # comment that is outside quotes."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i].rstrip()
    return line.rstrip()


_KEY = re.compile(r"""^(["']?)([A-Za-z0-9_.-]+)\1\s*:(?:\s+(.*))?$""")


def _entries(text):
    """Every mapping entry in a workflow as (path, key, value).

    A small indentation-aware reader for the YAML subset workflows use (no
    PyYAML dependency): path is the tuple of parent keys, list markers are
    transparent, keys may be quoted and spaced before the colon, and a block
    scalar (| or >) value is its joined body.
    """
    lines = text.splitlines()
    stack = []  # (indent, key)
    out = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\s*)((?:-\s+)*)(.*)$", raw)
        indent = len(m.group(1)) + len(m.group(2))
        km = _KEY.match(_strip_comment(m.group(3)))
        if not km:
            continue
        key, value = km.group(2), (km.group(3) or "")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if re.fullmatch(r"[|>][-+0-9]*", value.strip()):
            body = []
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                body.append(lines[i])
                i += 1
            value = "\n".join(body)
        out.append((tuple(k for _, k in stack), key, value))
        stack.append((indent, key))
    return out


def _flow_pairs(value):
    """key: value pairs of a flow mapping such as { issues: write }."""
    v = value.strip()
    if not (v.startswith("{") and v.endswith("}")):
        return []
    pairs = []
    for part in v[1:-1].split(","):
        if ":" in part:
            k, _, val = part.partition(":")
            pairs.append((_unquote(k), _unquote(val)))
    return pairs


def _permission_grants(text):
    """(scope, permission, level) for every permission in a workflow; scope is
    the job id, or "" for the workflow level."""
    grants = []
    for path, key, value in _entries(text):
        full = path + (key,)
        if "permissions" not in full:
            continue
        where = full.index("permissions")
        scope = full[1] if full[0] == "jobs" and where >= 2 else ""
        if key == "permissions":
            pairs = _flow_pairs(value)
            if pairs:
                grants.extend((scope, k, v) for k, v in pairs)
            elif _unquote(value):
                grants.append((scope, "*", _unquote(value)))  # read-all, write-all
        elif path and path[-1] == "permissions":
            grants.append((scope, key, _unquote(value)))
    return grants


def _expression_sinks(text):
    """Values a shell or script interpreter parses: run: blocks and with:
    script: inputs (actions/github-script style)."""
    return [
        (key, value) for path, key, value in _entries(text)
        if key == "run" or (key == "script" and path and path[-1] == "with")
    ]


PERMISSION_TRAPS = [
    ("jobs:\n  other:\n    permissions:\n      issues: write\n", {("other", "issues", "write")}),
    ("jobs:\n  other:\n    permissions:\n      'issues' : \"write\"  # sneaky\n",
     {("other", "issues", "write")}),
    ("jobs:\n  other:\n    permissions: { contents: read, issues: write }\n",
     {("other", "contents", "read"), ("other", "issues", "write")}),
    ("permissions: write-all\njobs:\n  a:\n    runs-on: x\n", {("", "*", "write-all")}),
    ("permissions:\n  issues: write\njobs:\n  a:\n    runs-on: x\n", {("", "issues", "write")}),
]


@pytest.mark.parametrize("text, expected", PERMISSION_TRAPS)
def test_permission_parser_sees_every_spelling(text, expected):
    """The guard would catch each spelling (guards the guard)."""
    assert set(_permission_grants(text)) == expected


def test_script_input_parser_sees_expressions():
    bad = ("      - uses: actions/github-script@0123456789012345678901234567890123456789\n"
           "        with:\n          script: |\n            core.info('${{ github.ref }}')\n")
    assert any("${{" in v for _, v in _expression_sinks(bad))


@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_no_write_all_anywhere(name):
    text = (WORKFLOWS / name).read_text()
    assert not [v for _, _, v in _entries(text) if "write-all" in v]
    assert not [g for g in _permission_grants(text) if g[2] == "write-all"]


@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_issues_write_only_on_alerting_jobs(name):
    grants = _permission_grants((WORKFLOWS / name).read_text())
    with_issues = {scope for scope, perm, level in grants if perm == "issues" and level == "write"}
    assert "" not in with_issues, "issues permission must be job-level only"
    assert with_issues == ALERTING_JOBS.get(name, set())


@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_no_expressions_in_script_inputs(name):
    for key, value in _expression_sinks((WORKFLOWS / name).read_text()):
        assert "${{" not in value, f"{name}: expression inside {key}:"


@pytest.mark.parametrize("name", DATA_WORKFLOWS)
def test_data_job_keeps_contents_write(name):
    """Job-level permissions replace the workflow block, so contents: write
    must be restated next to issues: write or the push step breaks."""
    header = _job_header((WORKFLOWS / name).read_text())
    assert re.search(r"^    permissions:\n      contents: write\n      issues: write$", header, re.M)


@pytest.mark.parametrize("name", DATA_WORKFLOWS)
def test_data_workflow_alerts_on_failure_and_closes_on_success(name):
    text = (WORKFLOWS / name).read_text()
    commit = text.index("- name: Commit and push if data changed")
    fail_at = text.index("- name: Alert on failure")
    ok_at = text.index("- name: Close failure alert on success")
    assert commit < fail_at and commit < ok_at, "alerts must run after the publish step"

    fail = _step(text, "Alert on failure")
    assert "if: failure() || cancelled()" in fail
    assert "RUN_OUTCOME: ${{ job.status }}" in fail
    assert "REPO_OWNER: ${{ github.repository_owner }}" in fail
    ok = _step(text, "Close failure alert on success")
    assert "if: success()" in ok
    assert "RUN_OUTCOME: success" in ok
    for step in (fail, ok):
        assert "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in step
        assert "run: python3 scripts/pipeline_alert.py run" in step


def test_live_canary_checks_freshness_even_after_smoke_failure():
    text = (WORKFLOWS / "smoke-test.yml").read_text()
    job = _jobs(text)["smoke-live"]
    step = _step(job, "Check published data freshness")
    assert "if: always() && github.ref == 'refs/heads/main'" in step
    assert "REPO_OWNER: ${{ github.repository_owner }}" in step
    assert "FRESHNESS_URL: https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/data/freshness.json" in step
    assert "run: python3 scripts/pipeline_alert.py stale" in step
    assert "pipeline_alert" not in _jobs(text)["smoke-local"]


@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_actions_stay_sha_pinned(name):
    for line in (WORKFLOWS / name).read_text().splitlines():
        m = re.search(r"uses:\s*(\S+)", line)
        if m:
            assert re.search(r"@[0-9a-f]{40}$", m.group(1)), line


@pytest.mark.parametrize("name", DATA_WORKFLOWS)
def test_commit_step_stages_the_change_log(name):
    """I8: the change log is written under docs/data, which both commit steps
    stage and diff, so it publishes with the data it describes and only from
    a run that exited 0."""
    config = json.loads((WORKFLOWS.parents[1] / "config.json").read_text())
    log = Path(config["files"]["changes"])
    assert log.parts[:2] == ("docs", "data") and log.name == "changes.json.gz"
    step = (WORKFLOWS / name).read_text().split("- name: Commit and push if data changed", 1)[1]
    assert "git add docs/data docs/database lastUpdate.txt" in step
    assert "git diff --cached --quiet -- docs/data docs/database" in step
