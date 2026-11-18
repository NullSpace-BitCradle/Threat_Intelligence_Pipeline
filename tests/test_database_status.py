"""Audit 2026-11-18 L6: run_pipeline.py --status reports true counts.

It read every file with json.load and counted top-level keys: the D3FEND
JSONL file failed to parse yet printed [OK] with "Unknown entries", groups
showed 3 (its top-level keys), and EPSS showed the bulk total (408,395)
instead of the 1,790 curated scores the file holds.
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import run_pipeline  # noqa: E402
import tip.core.database_manager as dm_mod  # noqa: E402


def _files(tmp_path):
    defend = tmp_path / "defend_db.jsonl"
    defend.write_text("".join(json.dumps({f"T100{i}": {"defensive_techniques": []}}) + "\n" for i in range(4)))
    groups = tmp_path / "groups_db.json"
    groups.write_text(json.dumps({"groups": {f"G000{i}": {} for i in range(5)},
                                  "technique_to_groups": {}, "attributions": {}}))
    epss = tmp_path / "epss_curated.json"
    epss.write_text(json.dumps({"meta": {"date": "2026-11-18", "total_count": 408395},
                                "scores": {"CVE-2021-44228": {}, "CVE-2023-4966": {}}}))
    ctid = tmp_path / "ctid_db.json"
    ctid.write_text(json.dumps({"meta": {}, "cves": {"CVE-2021-44228": []}}))
    owasp = tmp_path / "owasp_db.json"
    owasp.write_text(json.dumps({"categories": {f"A{i:02d}:2021": {} for i in range(1, 11)}, "cwe_mapping": {}}))
    kev = tmp_path / "kev_db.json"
    kev.write_text("{ broken")
    return {"defend": defend, "groups": groups, "epss": epss, "ctid": ctid, "owasp": owasp, "kev": kev}


def _manager(tmp_path):
    manager = dm_mod.DatabaseManager()
    files = _files(tmp_path)
    for name, cfg in manager.databases.items():
        cfg["file"] = str(files.get(name, tmp_path / f"missing_{name}.json"))
    return manager


def test_status_counts_records_the_way_each_file_holds_them(tmp_path):
    status = _manager(tmp_path).get_database_status()
    assert status["defend"]["entries"] == 4
    assert status["groups"]["entries"] == 5
    assert status["epss"]["entries"] == 2
    assert status["ctid"]["entries"] == 1
    assert status["owasp"]["entries"] == 10
    assert status["kev"]["exists"] is True and "error" in status["kev"] and "entries" not in status["kev"]
    assert status["capec"] == {"exists": False}


def test_status_output_marks_an_unreadable_file(tmp_path, monkeypatch, capsys):
    manager = _manager(tmp_path)

    class _Orch:
        def get_pipeline_status(self):
            return {"database_status": manager.get_database_status(), "last_update": None,
                    "pipeline_ready": False}

    monkeypatch.setattr(run_pipeline, "PipelineOrchestrator", _Orch)
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", "--status"])
    assert run_pipeline.main() == 0
    out = capsys.readouterr().out
    assert "[ERROR] KEV: unreadable" in out
    assert "[OK] DEFEND: 4 entries" in out
    assert "[OK] EPSS: 2 entries" in out
    assert "[X] CAPEC: Not found" in out
