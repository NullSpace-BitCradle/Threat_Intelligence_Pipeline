"""Shared reference-data fetch: retry on transient failures, STIX once per run.

No test here touches the network; requests.get is replaced.
"""
import logging

import pytest
import requests

import tip.utils.http as http_mod
from tip.utils.http import fetch_stix_bundle, get_with_retry

URL = "https://raw.example/data.json"


class _Resp:
    def __init__(self, status=200, payload=None, headers=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def _script(monkeypatch, *outcomes):
    """requests.get returns (or raises) each outcome in turn; records kwargs."""
    calls = []
    queue = list(outcomes)

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        effect = queue.pop(0)
        if isinstance(effect, Exception):
            raise effect
        return effect

    monkeypatch.setattr(http_mod.requests, "get", fake_get)
    return calls


def _sleeps(monkeypatch):
    waits = []
    monkeypatch.setattr(http_mod, "_sleep", waits.append)
    return waits


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_transient_status_is_retried(monkeypatch, status):
    calls = _script(monkeypatch, _Resp(status), _Resp(200, {"ok": 1}))
    assert get_with_retry(URL, timeout=5).status_code == 200
    assert len(calls) == 2


@pytest.mark.parametrize("exc", [requests.exceptions.ConnectionError("reset"),
                                 requests.exceptions.ReadTimeout("slow"),
                                 requests.exceptions.ChunkedEncodingError("truncated body")])
def test_connection_error_is_retried_then_raised(monkeypatch, exc):
    calls = _script(monkeypatch, exc, exc, exc)
    with pytest.raises(type(exc)):
        get_with_retry(URL, timeout=5)
    assert len(calls) == http_mod.MAX_ATTEMPTS


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_other_4xx_returns_without_retry(monkeypatch, status):
    calls = _script(monkeypatch, _Resp(status))
    assert get_with_retry(URL, timeout=5).status_code == status
    assert len(calls) == 1


def test_exhausted_retries_return_the_last_response(monkeypatch):
    calls = _script(monkeypatch, _Resp(503), _Resp(503), _Resp(503))
    assert get_with_retry(URL, timeout=5).status_code == 503
    assert len(calls) == http_mod.MAX_ATTEMPTS


@pytest.mark.parametrize("header,expected", [("5", 5.0), ("999", http_mod.MAX_WAIT)])
def test_retry_after_sets_the_wait_and_is_capped(monkeypatch, header, expected):
    waits = _sleeps(monkeypatch)
    _script(monkeypatch, _Resp(429, headers={"Retry-After": header}), _Resp(200))
    get_with_retry(URL, timeout=5)
    assert waits == [expected]


def test_kwargs_reach_requests_unchanged(monkeypatch):
    calls = _script(monkeypatch, _Resp(200))
    get_with_retry(URL, headers={"Authorization": "Bearer t"}, timeout=7)
    assert calls[0][1] == {"headers": {"Authorization": "Bearer t"}, "timeout": 7}


def test_retry_log_never_contains_header_values(monkeypatch, caplog):
    _script(monkeypatch, _Resp(503), _Resp(200))
    with caplog.at_level(logging.DEBUG):
        get_with_retry(URL, headers={"Authorization": "Bearer sekrit-token"}, timeout=5)
    assert caplog.records
    assert "sekrit-token" not in caplog.text


def test_stix_bundle_downloads_once_for_every_caller(monkeypatch):
    import tip.core.campaign_fetcher as campaign_fetcher
    from tip.core.apt_processor import APTProcessor
    from tip.core.database_manager import DatabaseManager

    calls = _script(monkeypatch, _Resp(200, {"objects": [{"type": "x"}]}))
    fetch_stix_bundle()
    APTProcessor().download()
    campaign_fetcher._download_stix_bundle()
    DatabaseManager()._process_techniques_data()
    assert len(calls) == 1


def test_failed_stix_download_is_not_cached(monkeypatch):
    calls = _script(monkeypatch, _Resp(404), _Resp(200, {"objects": []}))
    with pytest.raises(requests.exceptions.HTTPError):
        fetch_stix_bundle()
    assert fetch_stix_bundle() == {"objects": []}
    assert len(calls) == 2
