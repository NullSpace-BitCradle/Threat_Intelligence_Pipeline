#!/usr/bin/env python3
"""Open, update and close GitHub issues for failed data runs and stale data.

Two modes, both driven by environment variables so no workflow expression is
ever interpolated into a shell:

``run``    after a data workflow job. WORKFLOW_NAME, RUN_OUTCOME (the job
           status: success, failure or cancelled) and RUN_URL. A failure opens
           one ``pipeline-failure`` issue per workflow, or comments on the one
           already open; a success closes it with a recovery comment.
``stale``  the daily live canary. FRESHNESS_URL and RUN_URL. Opens (or
           comments on) one ``pipeline-stale`` issue when any source in the
           deployed freshness.json is past its threshold, or the file cannot
           be read; closes it when everything is fresh.

gh is called with argument lists (never a shell) and authenticates from
GH_TOKEN. Alerting never fails the workflow: every error is logged and the
script exits 0. Standard library only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, List, Mapping, Optional, Sequence

FAILURE_LABEL = "pipeline-failure"
STALE_LABEL = "pipeline-stale"
STALE_TITLE = "Published data is stale"
LABELS = {
    FAILURE_LABEL: ("d73a4a", "A scheduled data workflow failed"),
    STALE_LABEL: ("fbca04", "Published data is older than its expected cadence"),
}
# Daily sources go stale after 36 hours, weekly ones after 8 days, when the
# file does not carry its own stale_after_hours.
DAILY_STALE_HOURS = 36
WEEKLY_STALE_HOURS = 192

Gh = Callable[[Sequence[str]], str]
Fetch = Callable[[str], str]


class GhError(RuntimeError):
    """A gh invocation failed."""


def run_gh(args: Sequence[str]) -> str:
    """Run gh with an argument list and return stdout."""
    try:
        done = subprocess.run(
            ["gh", *args], check=True, capture_output=True, text=True, timeout=60
        )
    except subprocess.CalledProcessError as e:
        raise GhError(f"gh {' '.join(args[:2])} failed: {(e.stderr or '').strip()}") from e
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GhError(f"gh {' '.join(args[:2])} failed: {e}") from e
    return str(done.stdout)


def fetch_url(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as resp:
        return str(resp.read().decode("utf-8"))


def failure_title(workflow: str) -> str:
    return f"Data workflow failing: {workflow}"


def ensure_label(gh: Gh, name: str) -> None:
    color, description = LABELS[name]
    # --force updates an existing label instead of erroring: idempotent.
    gh(["label", "create", name, "--color", color, "--description", description, "--force"])


def find_open_issue(gh: Gh, label: str, title: str) -> Optional[int]:
    out = gh([
        "issue", "list", "--label", label, "--state", "open",
        "--json", "number,title", "--limit", "100",
    ])
    for item in json.loads(out or "[]"):
        if item.get("title") == title:
            return int(item["number"])
    return None


def open_or_comment(gh: Gh, label: str, title: str, body: str) -> None:
    ensure_label(gh, label)
    number = find_open_issue(gh, label, title)
    if number is None:
        gh(["issue", "create", "--title", title, "--body", body, "--label", label])
        print(f"Opened issue: {title}")
    else:
        gh(["issue", "comment", str(number), "--body", body])
        print(f"Commented on issue #{number}: {title}")


def close_if_open(gh: Gh, label: str, title: str, comment: str) -> None:
    # The label may not exist yet on a repo that has never failed; create it
    # first so the list below never errors on an unknown label.
    ensure_label(gh, label)
    number = find_open_issue(gh, label, title)
    if number is None:
        print(f"No open issue to close: {title}")
        return
    gh(["issue", "close", str(number), "--comment", comment])
    print(f"Closed issue #{number}: {title}")


def _require(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ValueError(f"environment variable {name} is not set")
    return value


def handle_run(env: Mapping[str, str], gh: Gh) -> None:
    workflow = _require(env, "WORKFLOW_NAME")
    outcome = _require(env, "RUN_OUTCOME")
    run_url = _require(env, "RUN_URL")
    title = failure_title(workflow)
    if outcome == "success":
        close_if_open(gh, FAILURE_LABEL, title, f"Recovered: the next run succeeded.\n\nRun: {run_url}")
        return
    body = (
        f"The **{workflow}** workflow finished with status `{outcome}`, so it "
        f"published nothing this run.\n\nRun: {run_url}\n\n"
        "This issue gets a comment on each further failure and closes itself "
        "on the next successful run."
    )
    open_or_comment(gh, FAILURE_LABEL, title, body)


@dataclass(frozen=True)
class Stale:
    key: str
    detail: str


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _threshold_hours(entry: Mapping[str, Any]) -> float:
    explicit = entry.get("stale_after_hours")
    if isinstance(explicit, (int, float)) and not isinstance(explicit, bool) and explicit > 0:
        return float(explicit)
    cadence = entry.get("cadence_hours")
    if isinstance(cadence, (int, float)) and not isinstance(cadence, bool) and cadence > 24:
        return float(WEEKLY_STALE_HOURS)
    return float(DAILY_STALE_HOURS)


def stale_sources(doc: Any, now: datetime) -> List[Stale]:
    """Sources past their threshold. Raises ValueError when the document has
    no readable sources at all. Sources absent from the file are unknown, not
    stale."""
    sources = doc.get("sources") if isinstance(doc, dict) else None
    if not isinstance(sources, dict) or not sources:
        raise ValueError("freshness.json has no sources")
    stale: List[Stale] = []
    for key, entry in sources.items():
        if not isinstance(entry, dict):
            stale.append(Stale(key, f"{key}: unreadable entry"))
            continue
        label = entry.get("label") if isinstance(entry.get("label"), str) else key
        when = _parse_time(entry.get("last_success"))
        if when is None:
            stale.append(Stale(key, f"{label}: last_success is missing or unreadable"))
            continue
        age = (now - when).total_seconds() / 3600
        limit = _threshold_hours(entry)
        if age > limit:
            stale.append(Stale(
                key,
                f"{label}: last success {entry['last_success']} "
                f"({age:.0f} hours ago; threshold {limit:.0f} hours)",
            ))
    return stale


def handle_stale(env: Mapping[str, str], gh: Gh, fetch: Fetch, now: datetime) -> None:
    url = _require(env, "FRESHNESS_URL")
    run_url = env.get("RUN_URL", "").strip() or "(no run URL)"
    try:
        problems = [s.detail for s in stale_sources(json.loads(fetch(url)), now)]
    except Exception as e:  # unreachable, malformed, or empty: runs never landed
        problems = [f"could not read {url}: {e}"]
    if problems:
        body = (
            "The deployed site's data is older than its expected cadence, "
            "which means data runs failed or never ran.\n\n"
            + "\n".join(f"- {p}" for p in problems)
            + f"\n\nChecked by: {run_url}\n\n"
            "This issue closes itself when the canary next finds every source fresh."
        )
        open_or_comment(gh, STALE_LABEL, STALE_TITLE, body)
    else:
        close_if_open(gh, STALE_LABEL, STALE_TITLE, f"Fresh again: every source is within its threshold.\n\nChecked by: {run_url}")


def main(
    argv: Sequence[str],
    env: Optional[Mapping[str, str]] = None,
    gh: Gh = run_gh,
    fetch: Fetch = fetch_url,
    now: Optional[datetime] = None,
) -> int:
    env = os.environ if env is None else env
    try:
        mode = argv[0] if argv else ""
        if mode == "run":
            handle_run(env, gh)
        elif mode == "stale":
            handle_stale(env, gh, fetch, now or datetime.now(timezone.utc))
        else:
            raise ValueError(f"unknown mode {mode!r}; expected 'run' or 'stale'")
    except Exception as e:
        # A broken alert must never turn a green run red, or hide a red one
        # behind a second failure. Log it where the run log shows it.
        print(f"::warning::alerting failed: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
