"""Orchestrator behavior when NVD is unavailable (degraded run).

Regression coverage for the 2026-06-22 hardening: an NVD brownout must surface
as a distinct 'degraded' status — success False, no output-file write, resume
metadata preserved — NOT as a falsely-successful "no new CVEs" run.
"""
import logging
import sys
import types

# pipeline_orchestrator imports monitoring.health_check, which imports psutil at
# module load. psutil is a declared runtime dep (requirements.txt); stub it ONLY
# when genuinely absent so this test can import the orchestrator in minimal envs.
# Real environments use the real psutil — the stub is never installed there.
try:  # pragma: no cover - environment dependent
    import psutil  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    sys.modules["psutil"] = types.ModuleType("psutil")

from tip.core.pipeline_orchestrator import PipelineOrchestrator
from tip.utils.error_handler import NVDUnavailableError


class _StubProcessor:
    """cve_processor stub whose NVD fetch always reports an outage."""

    def retrieve_cves_from_nvd(self, *_a, **_k):
        raise NVDUnavailableError(
            "NVD unreachable after 8 attempts: boom",
            url="https://nvd.example/cves",
            partial_count=4000,
            last_index=4000,
        )


def _make_orchestrator(tmp_path):
    """Build a PipelineOrchestrator without its heavy __init__."""
    orch = PipelineOrchestrator.__new__(PipelineOrchestrator)
    orch.cve_processor = _StubProcessor()
    orch.results = {}
    orch.logger = logging.getLogger("test_orchestrator_nvd_degraded")

    class _Cfg:
        def get_output_path(self, _key):
            # Path that MUST NOT be written on the degraded path.
            return str(tmp_path / "new_cves.jsonl")

    orch.config = _Cfg()
    return orch, tmp_path / "new_cves.jsonl"


def test_nvd_outage_is_degraded_not_success(tmp_path):
    orch, out_file = _make_orchestrator(tmp_path)

    result = orch._retrieve_cves()

    # Distinct degraded outcome, never reported as success.
    assert result["success"] is False
    assert result["degraded"] is True
    assert result["reason"] == "nvd_unavailable"

    # Status recorded distinctly (not 'success', not 'failed').
    assert orch.results["cve_retrieval"]["status"] == "degraded"
    assert orch.results["cve_retrieval"]["partial_count"] == 4000
    assert orch.results["cve_retrieval"]["last_index"] == 4000

    # Last-good output is left untouched — the degraded arm writes nothing.
    assert not out_file.exists()
