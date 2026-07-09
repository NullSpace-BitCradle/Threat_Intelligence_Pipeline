"""Tests for the NVD retrieval retry/backoff loop in CVEProcessor.

Regression coverage for the 2026-06-21 incident: NVD returned 503/read
timeouts and the fetch exhausted its retry window, failing the pipeline.
These tests pin the hardened behavior — bounded exponential backoff capped
at ``max_delay`` and recovery after transient failures — without standing up
the full processor (heavy ``__init__`` loads databases and sub-processors).
"""
import logging

import pytest
import requests

import tip.core.cve_processor as cve_mod
from tip.core.cve_processor import CVEProcessor
from tip.utils.error_handler import NVDUnavailableError


class _FakeConfig:
    """Minimal config stub exposing only what retrieve_cves_from_nvd reads."""

    def __init__(self, rate_limit):
        self._rate_limit = rate_limit

    def get_api_key(self, _service):
        return None

    def get(self, key, default=None):
        values = {
            "api.nvd.base_url": "https://nvd.example/cves",
            "api.nvd.results_per_page": 2000,
            "api.nvd.timeout": 30,
            "api.nvd.rate_limit": self._rate_limit,
            # Path that does not exist -> no resume, no progress file side effects.
            "files.progress_file": "/nonexistent/cve_progress.json",
            "progress_tracking.save_interval": 5000,
            "progress_tracking.log_interval": 10000,
        }
        return values.get(key, default)


class _OkResponse:
    """A 200 response carrying an empty result page so the loop exits cleanly."""

    status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return {"vulnerabilities": []}


def _make_processor(rate_limit):
    """Build a CVEProcessor without running its heavy __init__."""
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.config = _FakeConfig(rate_limit)
    proc.logger = logging.getLogger("test_cve_processor_retry")
    return proc


@pytest.fixture
def captured_sleeps(monkeypatch):
    """Record (without waiting for) every backoff sleep the loop performs."""
    sleeps = []
    monkeypatch.setattr(cve_mod.time, "sleep", lambda s: sleeps.append(s))
    return sleeps


def _patch_get(monkeypatch, side_effects):
    """Patch requests.get to walk through ``side_effects`` (exceptions or responses)."""
    calls = {"n": 0}

    def fake_get(*_args, **_kwargs):
        effect = side_effects[min(calls["n"], len(side_effects) - 1)]
        calls["n"] += 1
        if isinstance(effect, Exception):
            raise effect
        return effect

    monkeypatch.setattr(cve_mod.requests, "get", fake_get)
    return calls


def test_recovers_after_transient_failures(monkeypatch, captured_sleeps):
    """Two transient network errors, then success -> returns cleanly, sleeps twice."""
    rate_limit = {"base_delay": 0.1, "max_delay": 0.5,
                  "backoff_multiplier": 2.0, "max_retries": 5}
    proc = _make_processor(rate_limit)
    _patch_get(monkeypatch, [
        requests.exceptions.ConnectionError("boom"),
        requests.exceptions.ReadTimeout("slow"),
        _OkResponse(),
    ])

    result = proc.retrieve_cves_from_nvd()

    assert result == []
    assert len(captured_sleeps) == 2  # one per failed attempt before success


def test_backoff_is_capped_at_max_delay(monkeypatch, captured_sleeps):
    """Persistent failures exhaust retries; every backoff stays <= max_delay.

    Hardened contract (2026-06-22): on exhaustion the method RAISES
    NVDUnavailableError instead of returning []. The old empty return made an
    NVD outage read downstream as "no new CVEs" -> a falsely-successful run.
    Raising lets the orchestrator record a distinct 'degraded' status and leave
    last-good output untouched. The backoff-cap behavior is unchanged.
    """
    rate_limit = {"base_delay": 0.1, "max_delay": 0.5,
                  "backoff_multiplier": 2.0, "max_retries": 5}
    proc = _make_processor(rate_limit)
    _patch_get(monkeypatch, [requests.exceptions.ConnectionError("always down")])

    with pytest.raises(NVDUnavailableError):
        proc.retrieve_cves_from_nvd()

    # max_retries attempts -> max_retries - 1 backoff sleeps before giving up.
    assert len(captured_sleeps) == rate_limit["max_retries"] - 1
    assert max(captured_sleeps) <= rate_limit["max_delay"]


def test_default_retry_budget_is_hardened(monkeypatch, captured_sleeps):
    """With no config overrides, the function's own fallbacks give 8 attempts.

    Exercises the hardcoded defaults directly: an empty rate_limit dict forces
    retrieve_cves_from_nvd to fall back to max_retries=8 (post-incident value).
    Reverting the default to 5 would drop this to 4 sleeps and fail the test.
    On exhaustion it raises NVDUnavailableError (hardened contract).
    """
    proc = _make_processor({})  # empty -> function uses its hardcoded fallbacks
    _patch_get(monkeypatch, [requests.exceptions.ConnectionError("always down")])

    with pytest.raises(NVDUnavailableError):
        proc.retrieve_cves_from_nvd()

    assert len(captured_sleeps) == 7  # max_retries(8) - 1
    assert max(captured_sleeps) <= 60.0  # default max_delay


def test_genuine_empty_page_returns_empty(monkeypatch, captured_sleeps):
    """A clean 200 with an empty 'vulnerabilities' list is NOT a failure.

    Pins the distinction the hardening exists to preserve: genuine-empty still
    returns [] (success); only upstream-unavailability raises. No retries, no
    sleeps, no exception.
    """
    rate_limit = {"base_delay": 0.1, "max_delay": 0.5,
                  "backoff_multiplier": 2.0, "max_retries": 5}
    proc = _make_processor(rate_limit)
    _patch_get(monkeypatch, [_OkResponse()])

    result = proc.retrieve_cves_from_nvd()

    assert result == []
    assert captured_sleeps == []  # no failure path taken


class _MalformedOkResponse:
    """A 200 whose body lacks the NVD 'vulnerabilities' envelope.

    Mimics an error/maintenance page served with status 200 during a brownout.
    """

    status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return {"message": "Service Unavailable"}


def test_200_without_envelope_raises(monkeypatch, captured_sleeps):
    """A 200 missing 'vulnerabilities' is an outage, not genuine-empty -> raises.

    Closes the residual silent-success hole: a missing key must not read as
    "no new CVEs". No retry path (it's a 200), so no sleeps.
    """
    rate_limit = {"base_delay": 0.1, "max_delay": 0.5,
                  "backoff_multiplier": 2.0, "max_retries": 5}
    proc = _make_processor(rate_limit)
    _patch_get(monkeypatch, [_MalformedOkResponse()])

    with pytest.raises(NVDUnavailableError):
        proc.retrieve_cves_from_nvd()

    assert captured_sleeps == []  # 200 -> no backoff path taken
