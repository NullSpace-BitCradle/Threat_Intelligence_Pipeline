"""The data workflows can only publish from main.

A workflow_dispatch from any other ref must not run the job, and the commit
step pushes only when the local branch is exactly one new data commit on top
of origin/main. Parsed as text (no YAML dependency); actionlint validates the
syntax separately.
"""
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


@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_issues_write_only_on_alerting_jobs(name):
    text = (WORKFLOWS / name).read_text()
    top = text.split("\njobs:\n", 1)[0]
    assert "issues:" not in top, "issues permission must be job-level only"
    with_issues = {job for job, body in _jobs(text).items() if "issues: write" in body}
    assert with_issues == ALERTING_JOBS.get(name, set())


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
    assert "if: always()" in step
    assert "FRESHNESS_URL: https://nullspace-bitcradle.github.io/Threat_Intelligence_Pipeline/data/freshness.json" in step
    assert "run: python3 scripts/pipeline_alert.py stale" in step
    assert "pipeline_alert" not in _jobs(text)["smoke-local"]


@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_actions_stay_sha_pinned(name):
    for line in (WORKFLOWS / name).read_text().splitlines():
        m = re.search(r"uses:\s*(\S+)", line)
        if m:
            assert re.search(r"@[0-9a-f]{40}$", m.group(1)), line
