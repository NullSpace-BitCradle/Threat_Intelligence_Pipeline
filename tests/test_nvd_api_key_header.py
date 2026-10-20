"""The NVD API key reaches a request header stripped.

A pasted secret can carry a trailing newline. requests then refuses the
header and quotes the whole value, key included, in an InvalidHeader that
the NVD fetch logs (cve_processor) or prints on every retry (backfill_cvss).
"""
import importlib.util
from pathlib import Path

import requests

from tip.utils.config import get_config

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_backfill():
    spec = importlib.util.spec_from_file_location("backfill_cvss", REPO_ROOT / "scripts" / "backfill_cvss.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_config_api_key_is_stripped(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "sekrit-key\n")
    key = get_config().get_api_key("nvd")
    requests.models.PreparedRequest().prepare_headers({"apiKey": key})
    assert key == "sekrit-key"
    monkeypatch.setenv("NVD_API_KEY", " \n")
    assert get_config().get_api_key("nvd") is None


class _Page:
    status_code = 200

    def json(self):
        return {"totalResults": 0, "vulnerabilities": []}


def test_backfill_sends_a_valid_header_and_prints_no_key(monkeypatch, tmp_path, capsys):
    backfill = _load_backfill()
    monkeypatch.setattr(backfill, "CHECKPOINT", tmp_path / "checkpoint.json")
    monkeypatch.setattr(backfill.time, "sleep", lambda _s: None)
    monkeypatch.setenv("NVD_API_KEY", "sekrit-key\n")
    sent = []

    class _Session:
        def get(self, url, headers=None, **kwargs):
            # Real header validation, as requests applies it before sending.
            requests.models.PreparedRequest().prepare_headers(headers)
            sent.append(headers)
            return _Page()

    monkeypatch.setattr(backfill.requests, "Session", _Session)
    backfill.fetch_cvss_map(set(), delay=0)

    assert sent == [{"apiKey": "sekrit-key"}]
    assert "sekrit-key" not in capsys.readouterr().out
