"""ISC-54: the CLI and the --db-only / --force paths import and construct
without the removed monitoring modules, and nothing here touches the network.
"""
import sys
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import run_pipeline  # noqa: E402


@pytest.fixture
def no_network(monkeypatch):
    """Any HTTP call fails loudly instead of reaching NVD, GitHub or MITRE."""
    def _blocked(*_a, **_k):
        raise requests.exceptions.ConnectionError("network blocked in unit tests")
    monkeypatch.setattr(requests, "get", _blocked)
    monkeypatch.setattr(requests.Session, "get", _blocked)


def test_help_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", "--help"])
    with pytest.raises(SystemExit) as exc:
        run_pipeline.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--db-only" in out and "--force" in out


@pytest.mark.parametrize("flag", ["--web-interface", "--health-check", "--metrics"])
def test_removed_flags_are_rejected(monkeypatch, flag):
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", flag])
    with pytest.raises(SystemExit) as exc:
        run_pipeline.main()
    assert exc.value.code == 2


def test_orchestrator_constructs_offline(no_network):
    from tip.core.pipeline_orchestrator import PipelineOrchestrator
    orch = PipelineOrchestrator()
    status = orch.get_pipeline_status()
    assert set(status) == {"database_status", "last_update", "pipeline_ready"}


class _FakeOrchestrator:
    calls: list = []

    def __init__(self):
        pass

    def _summary(self):
        return {
            "pipeline_session": {
                "total_duration": 0.0, "successful_steps": 1,
                "failed_steps": 0, "total_steps": 1,
            },
            "results": {},
        }

    def run_database_updates_only(self):
        self.calls.append("db_only")
        return self._summary()

    def run_full_pipeline(self, force_update=False):
        self.calls.append(("full", force_update))
        return self._summary()


@pytest.mark.parametrize("argv, expected", [
    (["--db-only"], "db_only"),
    (["--force"], ("full", True)),
])
def test_cli_dispatch(monkeypatch, argv, expected):
    _FakeOrchestrator.calls = []
    monkeypatch.setattr(run_pipeline, "PipelineOrchestrator", _FakeOrchestrator)
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", *argv])
    assert run_pipeline.main() == 0
    assert _FakeOrchestrator.calls == [expected]


def test_download_failure_without_recovery_wrapper(no_network, tmp_path, monkeypatch):
    """With @with_recovery gone, a failed download still ends as a False
    update result (the caller's try/except), and nothing is written."""
    monkeypatch.chdir(tmp_path)
    from tip.core.database_manager import DatabaseManager
    from tip.utils.error_handler import NetworkError
    manager = DatabaseManager()
    with pytest.raises(NetworkError):
        manager._download_file("https://capec.example/1000.csv.zip", "capec_data.zip")
    assert manager.update_database("capec") is False
    assert not (tmp_path / "capec_data.zip").exists()


def test_kev_update_failure_returns_false(no_network, tmp_path):
    from tip.core.kev_processor import KEVProcessor
    proc = KEVProcessor()
    proc.db_path = str(tmp_path / "kev_db.json")
    from tip.utils.error_handler import NetworkError
    with pytest.raises(NetworkError):
        proc.download()
    assert proc.update() is False
    assert not (tmp_path / "kev_db.json").exists()
