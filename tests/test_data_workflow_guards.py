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
