"""I16 F3: the failure and staleness alert script, against a mocked gh.

The script never touches the network or the real gh here: both are injected.
It must never raise or exit non-zero, because a broken alert must not turn a
green data run red.
"""
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pipeline_alert.py"
_spec = importlib.util.spec_from_file_location("pipeline_alert", SCRIPT)
assert _spec and _spec.loader
alert = importlib.util.module_from_spec(_spec)
sys.modules["pipeline_alert"] = alert
_spec.loader.exec_module(alert)

RUN_URL = "https://github.com/o/r/actions/runs/42"
WORKFLOW = "Update Reference Databases"
NOW = datetime(2026, 9, 27, 7, 0, tzinfo=timezone.utc)


class FakeGh:
    """Records every gh call; answers `issue list` from a fixed issue list."""

    def __init__(self, issues=None, fail_on=None):
        self.issues = issues or []
        self.fail_on = fail_on
        self.calls: list[list[str]] = []

    def __call__(self, args):
        args = list(args)
        self.calls.append(args)
        if self.fail_on and args[:2] == self.fail_on:
            raise alert.GhError("gh exploded")
        if args[:2] == ["issue", "list"]:
            label = args[args.index("--label") + 1]
            return json.dumps([
                {"number": i["number"], "title": i["title"]}
                for i in self.issues if i["label"] == label
            ])
        return ""

    def verbs(self):
        return [c[:2] for c in self.calls]

    def call(self, verb):
        return next(c for c in self.calls if c[:2] == verb)


OWNER = "NullSpace-BitCradle"


def _run_env(outcome, owner=OWNER):
    env = {"WORKFLOW_NAME": WORKFLOW, "RUN_OUTCOME": outcome, "RUN_URL": RUN_URL}
    if owner is not None:
        env["REPO_OWNER"] = owner
    return env


def _body(call, flag="--body"):
    return call[call.index(flag) + 1]


def _main(argv, env, gh, fetch=None):
    return alert.main(argv, env=env, gh=gh, fetch=fetch or (lambda url: "{}"), now=NOW)


# ISC-7: a failing data workflow opens or comments.

def test_failure_opens_issue_with_label_title_and_run_url():
    gh = FakeGh()
    assert _main(["run"], _run_env("failure"), gh) == 0
    label = gh.call(["label", "create"])
    assert "pipeline-failure" in label and "--force" in label  # idempotent
    create = gh.call(["issue", "create"])
    assert create[create.index("--title") + 1] == f"Data workflow failing: {WORKFLOW}"
    assert create[create.index("--label") + 1] == "pipeline-failure"
    assert RUN_URL in create[create.index("--body") + 1]
    assert ["issue", "comment"] not in gh.verbs()


def test_failure_comments_on_existing_open_issue():
    gh = FakeGh([{"number": 7, "title": f"Data workflow failing: {WORKFLOW}",
                  "label": "pipeline-failure"}])
    assert _main(["run"], _run_env("failure"), gh) == 0
    comment = gh.call(["issue", "comment"])
    assert comment[2] == "7"
    assert RUN_URL in comment[comment.index("--body") + 1]
    assert ["issue", "create"] not in gh.verbs()


def test_failure_does_not_reuse_another_workflows_issue():
    gh = FakeGh([{"number": 7, "title": "Data workflow failing: Run CVE Pipeline",
                  "label": "pipeline-failure"}])
    _main(["run"], _run_env("failure"), gh)
    assert ["issue", "create"] in gh.verbs()
    assert ["issue", "comment"] not in gh.verbs()


def test_cancelled_run_is_alerted_like_a_failure():
    """A job timeout cancels rather than fails; it still alerts."""
    gh = FakeGh()
    _main(["run"], _run_env("cancelled"), gh)
    create = gh.call(["issue", "create"])
    assert "cancelled" in create[create.index("--body") + 1]


# ISC-8: a successful run closes its open issue.

def test_success_closes_open_issue_with_recovery_comment():
    gh = FakeGh([{"number": 7, "title": f"Data workflow failing: {WORKFLOW}",
                  "label": "pipeline-failure"}])
    assert _main(["run"], _run_env("success"), gh) == 0
    close = gh.call(["issue", "close"])
    assert close[2] == "7"
    assert RUN_URL in close[close.index("--comment") + 1]
    assert ["issue", "create"] not in gh.verbs()


def test_success_without_open_issue_does_nothing():
    gh = FakeGh()
    _main(["run"], _run_env("success"), gh)
    # The label is ensured first, so listing never errors on a repo that has
    # never failed; nothing else happens.
    assert gh.verbs() == [["label", "create"], ["issue", "list"]]


# ISC-9: the canary over the live freshness.json.

def _fresh_doc(**ages_hours):
    sources = {}
    for key, age in ages_hours.items():
        weekly = key in ("nvd", "entity_index")
        ts = datetime.fromtimestamp(NOW.timestamp() - age * 3600, tz=timezone.utc)
        sources[key] = {
            "label": key.upper(),
            "last_success": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cadence_hours": 168 if weekly else 24,
            "stale_after_hours": 192 if weekly else 36,
        }
    return json.dumps({"schema": 1, "sources": sources})


STALE_ENV = {"FRESHNESS_URL": "https://example.test/data/freshness.json", "RUN_URL": RUN_URL,
             "REPO_OWNER": OWNER}


def test_stale_source_opens_stale_issue_naming_it():
    gh = FakeGh()
    doc = _fresh_doc(kev=40, nvd=24)
    assert _main(["stale"], STALE_ENV, gh, fetch=lambda url: doc) == 0
    assert "pipeline-stale" in gh.call(["label", "create"])
    create = gh.call(["issue", "create"])
    body = create[create.index("--body") + 1]
    assert create[create.index("--label") + 1] == "pipeline-stale"
    assert "KEV" in body and "NVD" not in body
    assert RUN_URL in body


def test_stale_comments_on_existing_stale_issue():
    gh = FakeGh([{"number": 9, "title": alert.STALE_TITLE, "label": "pipeline-stale"}])
    _main(["stale"], STALE_ENV, gh, fetch=lambda url: _fresh_doc(nvd=200))
    assert gh.call(["issue", "comment"])[2] == "9"
    assert ["issue", "create"] not in gh.verbs()


def test_fresh_data_closes_stale_issue():
    gh = FakeGh([{"number": 9, "title": alert.STALE_TITLE, "label": "pipeline-stale"}])
    _main(["stale"], STALE_ENV, gh, fetch=lambda url: _fresh_doc(kev=30, nvd=190))
    assert gh.call(["issue", "close"])[2] == "9"
    assert ["issue", "create"] not in gh.verbs()


@pytest.mark.parametrize("body", ["not json", "[]", '{"sources": {}}', '{"x": 1}'])
def test_malformed_live_file_opens_stale_issue(body):
    gh = FakeGh()
    _main(["stale"], STALE_ENV, gh, fetch=lambda url: body)
    assert ["issue", "create"] in gh.verbs()


def test_unreachable_live_file_opens_stale_issue():
    def fetch(url):
        raise OSError("HTTP Error 404: Not Found")

    gh = FakeGh()
    _main(["stale"], STALE_ENV, gh, fetch=fetch)
    create = gh.call(["issue", "create"])
    assert "404" in create[create.index("--body") + 1]


def test_threshold_falls_back_to_cadence_when_missing():
    doc = json.loads(_fresh_doc(kev=37, nvd=191))
    for entry in doc["sources"].values():
        del entry["stale_after_hours"]
    stale = alert.stale_sources(doc, NOW)
    assert [s.key for s in stale] == ["kev"]


def test_unparseable_entry_counts_as_stale():
    doc = {"sources": {"kev": {"label": "KEV", "last_success": "yesterday"}}}
    assert [s.key for s in alert.stale_sources(doc, NOW)] == ["kev"]


# Alerting must never fail the workflow.

@pytest.mark.parametrize("fail_on", [["label", "create"], ["issue", "list"],
                                     ["issue", "create"], ["issue", "close"]])
def test_gh_failure_in_run_mode_does_not_raise_or_exit_nonzero(fail_on, capsys):
    closing = fail_on == ["issue", "close"]
    gh = FakeGh(fail_on=fail_on)
    if closing:
        gh.issues = [{"number": 7, "title": f"Data workflow failing: {WORKFLOW}",
                      "label": "pipeline-failure"}]
    assert _main(["run"], _run_env("success" if closing else "failure"), gh) == 0
    assert "alerting failed" in capsys.readouterr().out


def test_missing_env_does_not_raise():
    assert _main(["run"], {}, FakeGh()) == 0


def test_unknown_mode_does_not_raise():
    assert _main(["bogus"], {}, FakeGh()) == 0


def test_real_gh_runner_uses_argument_list(monkeypatch):
    """No shell: gh gets an argv list, so titles and bodies are never parsed
    by a shell."""
    seen = {}

    class Done:
        stdout = "[]"

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return Done()

    monkeypatch.setattr(alert.subprocess, "run", fake_run)
    alert.run_gh(["issue", "list", "--label", "x; rm -rf /"])
    assert seen["argv"] == ["gh", "issue", "list", "--label", "x; rm -rf /"]
    assert not seen["kwargs"].get("shell")


def test_real_gh_failure_becomes_gh_error(monkeypatch):
    def fake_run(argv, **kwargs):
        raise alert.subprocess.CalledProcessError(1, argv, stderr="bad token")

    monkeypatch.setattr(alert.subprocess, "run", fake_run)
    with pytest.raises(alert.GhError, match="bad token"):
        alert.run_gh(["issue", "list"])


# The repository has no watchers, so an unmentioned issue notifies nobody.
# Every alert body mentions the owner; recovery comments do not.

def test_failure_issue_mentions_owner():
    gh = FakeGh()
    _main(["run"], _run_env("failure"), gh)
    assert f"@{OWNER}" in _body(gh.call(["issue", "create"]))


def test_repeat_failure_comment_mentions_owner():
    gh = FakeGh([{"number": 7, "title": f"Data workflow failing: {WORKFLOW}",
                  "label": "pipeline-failure"}])
    _main(["run"], _run_env("failure"), gh)
    assert f"@{OWNER}" in _body(gh.call(["issue", "comment"]))


def test_stale_issue_and_comment_mention_owner():
    doc = _fresh_doc(kev=40)
    gh = FakeGh()
    _main(["stale"], STALE_ENV, gh, fetch=lambda url: doc)
    assert f"@{OWNER}" in _body(gh.call(["issue", "create"]))
    gh = FakeGh([{"number": 9, "title": alert.STALE_TITLE, "label": "pipeline-stale"}])
    _main(["stale"], STALE_ENV, gh, fetch=lambda url: doc)
    assert f"@{OWNER}" in _body(gh.call(["issue", "comment"]))


def test_recovery_comments_do_not_mention_owner():
    gh = FakeGh([{"number": 7, "title": f"Data workflow failing: {WORKFLOW}",
                  "label": "pipeline-failure"}])
    _main(["run"], _run_env("success"), gh)
    assert "@" not in _body(gh.call(["issue", "close"]), "--comment")
    gh = FakeGh([{"number": 9, "title": alert.STALE_TITLE, "label": "pipeline-stale"}])
    _main(["stale"], STALE_ENV, gh, fetch=lambda url: _fresh_doc(kev=1))
    assert "@" not in _body(gh.call(["issue", "close"]), "--comment")


@pytest.mark.parametrize("owner", ["", "a" * 40, "bad owner", "x;rm", "@someone",
                                   "evil\n@other", "name_with_underscore", None])
def test_invalid_owner_is_never_mentioned(owner, capsys):
    gh = FakeGh()
    assert _main(["run"], _run_env("failure", owner=owner), gh) == 0
    body = _body(gh.call(["issue", "create"]))  # the issue still opens
    assert "@" not in body
    assert "REPO_OWNER" in capsys.readouterr().out


@pytest.mark.parametrize("owner", ["a", "a" * 39, "Null-Space-9"])
def test_valid_owner_shapes_are_mentioned(owner):
    assert alert.owner_mention({"REPO_OWNER": owner}) == f"@{owner}"


# Stale mode: a canary that cannot alert must go red; run mode never does.

@pytest.mark.parametrize("fail_on", [["label", "create"], ["issue", "list"],
                                     ["issue", "create"], ["issue", "close"]])
def test_gh_failure_in_stale_mode_exits_1_with_error(fail_on, capsys):
    gh = FakeGh(fail_on=fail_on)
    doc = _fresh_doc(kev=1) if fail_on == ["issue", "close"] else _fresh_doc(kev=40)
    if fail_on == ["issue", "close"]:
        gh.issues = [{"number": 9, "title": alert.STALE_TITLE, "label": "pipeline-stale"}]
    assert _main(["stale"], STALE_ENV, gh, fetch=lambda url: doc) == 1
    assert "::error::" in capsys.readouterr().out


def test_stale_data_alerted_successfully_exits_0():
    gh = FakeGh()
    assert _main(["stale"], STALE_ENV, gh, fetch=lambda url: _fresh_doc(kev=40)) == 0
    assert ["issue", "create"] in gh.verbs()


def test_fresh_data_exits_0():
    assert _main(["stale"], STALE_ENV, FakeGh(), fetch=lambda url: _fresh_doc(kev=1)) == 0
