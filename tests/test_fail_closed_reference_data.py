"""F1: fail-closed reference data (root ISA ISC-6 to ISC-11; Vulnrichment
refresh per Plans/workflow-hardening.isa.md F1).

A failed upstream fetch must leave the last good file on disk
byte-identical and report failure. No test here touches the network: every
requests.get and the vulnrichment git clone are replaced.
"""
import io
import json
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests

import tip.core.vulnrichment_processor as vr_mod
from tip.core.vulnrichment_processor import VulnrichmentProcessor

OLD_SHA = "a" * 40
NEW_SHA = "b" * 40


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def _enrichment_json(cve_id):
    return {"containers": {"adp": [{
        "providerMetadata": {"orgId": vr_mod.CISA_ADP_ORG_ID},
        "metrics": [{"other": {"type": "ssvc", "content": {"id": cve_id, "options": [
            {"Exploitation": "active"}, {"Automatable": "no"}, {"Technical Impact": "partial"},
        ]}}}],
    }]}}


@pytest.fixture
def vr_env(tmp_path):
    """A processor pointed at tmp files, with an existing 3-entry DB and state."""
    db = tmp_path / "vulnrichment_db.json"
    state = tmp_path / "vulnrichment_state.json"
    existing = {f"CVE-2024-000{i}": {"ssvcExploitStatus": "none"} for i in range(1, 4)}
    db.write_text(json.dumps(existing, indent=2))
    state.write_text(json.dumps({"last_commit_sha": OLD_SHA}))
    proc = VulnrichmentProcessor()
    proc.db_path = str(db)
    proc.state_path = str(state)
    return proc, db, state


def _route(monkeypatch, routes):
    """Patch requests.get; ``routes`` maps a URL substring to a response or exception."""
    calls = []

    def fake_get(url, *_a, **_k):
        calls.append(url)
        for key, effect in routes.items():
            if key in url:
                if isinstance(effect, Exception):
                    raise effect
                return effect
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(vr_mod.requests, "get", fake_get)
    return calls


def _no_clone(monkeypatch):
    def boom(self):
        raise AssertionError("bootstrap clone must not run in this test")
    monkeypatch.setattr(VulnrichmentProcessor, "_bootstrap_clone", boom)


# ISC-6 ---------------------------------------------------------------------

def test_github_api_error_leaves_db_unchanged_and_reports_failure(vr_env, monkeypatch, tmp_path):
    proc, db, state = vr_env
    before_db, before_state = db.read_bytes(), state.read_bytes()
    _no_clone(monkeypatch)
    _route(monkeypatch, {"api.github.com": requests.exceptions.ConnectionError("down")})

    import tip.core.database_manager as dm_mod
    monkeypatch.setattr(dm_mod, "VulnrichmentProcessor", lambda: proc)
    manager = dm_mod.DatabaseManager()
    manager.databases["vulnrichment"]["file"] = str(db)

    assert manager.update_database("vulnrichment") is False
    assert db.read_bytes() == before_db
    assert state.read_bytes() == before_state


def test_unchanged_repo_does_not_wipe_db(vr_env, monkeypatch):
    """HEAD equals the stored sha: the DB on disk must survive (was saved as {})."""
    proc, db, state = vr_env
    _no_clone(monkeypatch)
    _route(monkeypatch, {"commits?per_page=1": _Resp([{"sha": OLD_SHA}])})

    assert proc.update() is True
    assert json.loads(db.read_text()) == {
        f"CVE-2024-000{i}": {"ssvcExploitStatus": "none"} for i in range(1, 4)
    }
    assert json.loads(state.read_text())["last_commit_sha"] == OLD_SHA


# workflow-hardening F1 (supersedes root ISA ISC-7 / ISC-8) -----------------
# Upstream moved: the refresh is a full shallow clone, never a compare delta
# of anonymous per-file fetches (403s on shared runners, 2026-09-30).

def _fake_resync(monkeypatch, ok=True):
    resync = {"called": 0}

    def fake_bootstrap(self):
        resync["called"] += 1
        if not ok:
            return False
        self.vulnrichment_db = {f"CVE-2025-{i:04d}": {"ssvcExploitStatus": "none"} for i in range(10)}
        self._pending_sha = "c" * 40
        return True

    monkeypatch.setattr(VulnrichmentProcessor, "_bootstrap_clone", fake_bootstrap)
    return resync


def test_moved_head_refreshes_by_clone_and_makes_no_other_request(vr_env, monkeypatch):
    proc, db, state = vr_env
    calls = _route(monkeypatch, {"commits?per_page=1": _Resp([{"sha": NEW_SHA}])})
    resync = _fake_resync(monkeypatch)

    assert proc.update() is True
    assert resync["called"] == 1
    assert len(calls) == 1 and urlsplit(calls[0]).hostname == "api.github.com"
    assert len(json.loads(db.read_text())) == 10
    # State is the clone HEAD, not the sha the API reported.
    assert json.loads(state.read_text())["last_commit_sha"] == "c" * 40


def test_moved_head_with_failed_clone_keeps_everything(vr_env, monkeypatch):
    proc, db, state = vr_env
    before_db, before_state = db.read_bytes(), state.read_bytes()
    _route(monkeypatch, {"commits?per_page=1": _Resp([{"sha": NEW_SHA}])})
    resync = _fake_resync(monkeypatch, ok=False)

    assert proc.update() is False
    assert resync["called"] == 1
    assert db.read_bytes() == before_db
    assert state.read_bytes() == before_state


def test_unchanged_head_does_not_clone(vr_env, monkeypatch):
    proc, db, state = vr_env
    before_db = db.read_bytes()
    _no_clone(monkeypatch)
    _route(monkeypatch, {"commits?per_page=1": _Resp([{"sha": OLD_SHA}])})

    assert proc.update() is True
    assert db.read_bytes() == before_db


# ISC-9 ---------------------------------------------------------------------

def _big(n):
    return {str(i): {"name": f"entry {i}"} for i in range(n)}


def _groups(n):
    return {"groups": {f"G{i:04d}": {"name": str(i), "aliases": [], "techniques": []} for i in range(n)},
            "technique_to_groups": {}}


def _campaigns(n):
    return {f"C{i:04d}": {"name": str(i), "groups": [], "techniques": []} for i in range(n)}


def _owasp(n):
    return {"categories": {f"A{i:02d}:2021": {"name": str(i), "cwe_ids": []} for i in range(n)},
            "cwe_mapping": {}}


def _write_via_manager(name, suffix=".json"):
    def write(path, data):
        import tip.core.database_manager as dm_mod
        manager = dm_mod.DatabaseManager()
        manager.databases[name]["file"] = str(path)
        manager.databases[name]["processor"] = lambda *a: data
        manager._download_file = lambda url, filename: True  # type: ignore[method-assign]
        return manager.update_database(name)
    return write, suffix


def _write_kev(path, data):
    from tip.core.kev_processor import KEVProcessor
    proc = KEVProcessor()
    proc.db_path = str(path)
    proc._save(data)
    return True


def _write_vulnrichment(path, data):
    proc = VulnrichmentProcessor()
    proc.db_path = str(path)
    proc._save(data)
    return True


def _write_groups_apt(path, data):
    from tip.core.apt_processor import APTProcessor
    proc = APTProcessor()
    proc.db_path = str(path)
    proc._save(data)
    return True


def _write_campaigns(path, data):
    import tip.core.campaign_fetcher as cf
    base = path.parent.parent.parent  # <base>/docs/data/campaigns_db.json
    orig_dl, orig_ex = cf._download_stix_bundle, cf._extract_campaigns
    cf._download_stix_bundle = lambda: {}  # type: ignore[assignment]
    cf._extract_campaigns = lambda stix: data  # type: ignore[assignment]
    try:
        cf.fetch_campaigns(base)
    finally:
        cf._download_stix_bundle, cf._extract_campaigns = orig_dl, orig_ex
    return True


def _write_owasp(path, data):
    from tip.core.owasp_processor import OWASPProcessor
    proc = OWASPProcessor.__new__(OWASPProcessor)
    proc.owasp_db_path = path
    proc.owasp_categories = data["categories"]
    proc.cwe_owasp_mapping = data["cwe_mapping"]
    proc._save_owasp_database()  # logs and swallows by design; file must hold
    return True


WRITERS = {
    "capec": (*_write_via_manager("capec"), _big),
    "cwe": (*_write_via_manager("cwe"), _big),
    "techniques": (*_write_via_manager("techniques"), _big),
    "defend": (*_write_via_manager("defend", ".jsonl"), _big),
    "kev_manager": (*_write_via_manager("kev"), _big),
    "vulnrichment_manager": (*_write_via_manager("vulnrichment"), _big),
    "groups_manager": (*_write_via_manager("groups"), _groups),
    "kev": (_write_kev, ".json", _big),
    "vulnrichment": (_write_vulnrichment, ".json", _big),
    "groups": (_write_groups_apt, ".json", _groups),
    "campaigns": (_write_campaigns, ".json", _campaigns),
    "owasp": (_write_owasp, ".json", _owasp),
}


def _seed(path, data):
    if path.suffix == ".jsonl":
        path.write_text("".join(json.dumps({k: v}) + "\n" for k, v in data.items()))
    else:
        path.write_text(json.dumps(data))


@pytest.mark.parametrize("name", sorted(WRITERS))
@pytest.mark.parametrize("new_size, expect_written", [
    (0, False),    # upstream outage parsed to {}
    (4, False),    # under 50% of 10
    (5, True),     # exactly the floor
    (25, True),    # growth always allowed (vulnrichment full resync)
])
def test_reference_db_writers_enforce_floor(tmp_path, monkeypatch, name, new_size, expect_written):
    monkeypatch.chdir(tmp_path)
    write, suffix, make = WRITERS[name]
    target_dir = tmp_path / "docs" / "data"
    target_dir.mkdir(parents=True)
    fname = "campaigns_db.json" if name == "campaigns" else f"{name}_db{suffix}"
    path = target_dir / fname
    _seed(path, make(10))
    before = path.read_bytes()

    try:
        ok = write(path, make(new_size))
    except Exception:
        ok = False

    if expect_written:
        assert ok is True
        assert path.read_bytes() != before
    else:
        assert ok is not True or name == "owasp"
        assert path.read_bytes() == before
    leftovers = [p.name for p in target_dir.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []


# ISC-10 / ISC-11 ------------------------------------------------------------

def test_cwe_url_is_https():
    from tip.utils.config import Config
    repo_root = Path(__file__).resolve().parents[1]
    cfg = json.loads((repo_root / "config.json").read_text())
    assert cfg["database"]["cwe"]["url"].startswith("https://")
    default = Config.__new__(Config)._get_default_config()
    assert default["database"]["cwe"]["url"].startswith("https://")


def _cwe_zip(path):
    ns = "http://cwe.mitre.org/cwe-7"
    xml = (
        f'<Weakness_Catalog xmlns="{ns}"><Weaknesses>'
        '<Weakness ID="79" Name="XSS"><Description>d</Description>'
        '<Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="74"/></Related_Weaknesses>'
        '<Related_Attack_Patterns><Related_Attack_Pattern CAPEC_ID="63"/></Related_Attack_Patterns>'
        '</Weakness></Weaknesses></Weakness_Catalog>'
    )
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("cwec_v4.99.xml", xml)
        z.writestr("../evil.xml", "<x/>")


def test_cwe_zip_is_read_in_memory_not_extracted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    zip_path = tmp_path / "dl" / "cwe.zip"
    zip_path.parent.mkdir()
    _cwe_zip(zip_path)
    from tip.core.database_manager import DatabaseManager
    data = DatabaseManager()._process_cwe_data(str(zip_path))
    assert data == {"79": {"name": "XSS", "description": "d", "ChildOf": ["74"],
                           "RelatedAttackPatterns": ["63"]}}
    # Nothing landed in the working directory (the repo root in CI).
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dl"]
    assert sorted(p.name for p in zip_path.parent.iterdir()) == ["cwe.zip"]


def test_capec_zip_is_read_in_memory_not_extracted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    zip_path = tmp_path / "capec.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("1000.csv", "'ID,Name,Taxonomy Mappings\n1,Pattern,::TAXONOMY NAME:ATTACK:ENTRY ID:1574.010::\n")
    from tip.core.database_manager import DatabaseManager
    data = DatabaseManager()._process_capec_data(str(zip_path))
    assert data == {"1": {"name": "Pattern", "techniques": "::TAXONOMY NAME:ATTACK:ENTRY ID:1574.010::"}}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["capec.zip"]


def test_update_database_downloads_into_a_temp_dir(tmp_path, monkeypatch):
    """The CWE/CAPEC archive is never written into the working directory."""
    monkeypatch.chdir(tmp_path)
    from tip.core.database_manager import DatabaseManager
    manager = DatabaseManager()
    seen = {}

    def fake_download(url, filename):
        seen["path"] = Path(filename)
        _cwe_zip(filename)
        return True

    manager._download_file = fake_download  # type: ignore[method-assign]
    out = tmp_path / "cwe_db.json"
    manager.databases["cwe"]["file"] = str(out)
    assert manager.update_database("cwe") is True
    assert seen["path"].resolve().parent != tmp_path.resolve()
    assert not seen["path"].exists()  # temp dir cleaned up
    assert json.loads(out.read_text())["79"]["ChildOf"] == ["74"]


# GitHub API auth -----------------------------------------------------------

def _record_headers(monkeypatch, routes):
    """Like _route, but records (url, headers) for every call."""
    calls = []

    def fake_get(url, headers=None, **_k):
        calls.append((url, dict(headers or {})))
        for key, effect in routes.items():
            if key in url:
                return effect
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(vr_mod.requests, "get", fake_get)
    return calls


def test_head_check_sends_github_token_and_only_to_the_api(vr_env, monkeypatch):
    """Unauthenticated API calls hit the per-IP limit on shared runners (403, 2026-09-30)."""
    proc, db, state = vr_env
    monkeypatch.setenv("GITHUB_TOKEN", "sekrit-token")
    calls = _record_headers(monkeypatch, {"commits?per_page=1": _Resp([{"sha": NEW_SHA}])})
    _fake_resync(monkeypatch)

    assert proc.update() is True
    assert calls
    assert all(urlsplit(u).hostname == "api.github.com" for u, _ in calls)
    assert all(h["Authorization"] == "Bearer sekrit-token" for _, h in calls)
    assert all("sekrit-token" not in u for u, _ in calls)


def test_api_calls_without_token_send_no_auth_header(vr_env, monkeypatch):
    proc, db, state = vr_env
    _no_clone(monkeypatch)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    calls = _record_headers(monkeypatch, {"commits?per_page=1": _Resp([{"sha": OLD_SHA}])})

    assert proc.update() is True
    assert calls and "Authorization" not in calls[0][1]
