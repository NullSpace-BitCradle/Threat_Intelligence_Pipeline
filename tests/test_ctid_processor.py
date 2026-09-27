"""I21 F1: CTID Mappings Explorer (KEV) ingestion (ISC-1, ISC-2).

The processor picks the newest enterprise KEV file from the repository tree,
parses it into per-CVE technique mappings, and writes ctid_db.json
atomically behind a floor. Every failure keeps the previous file
byte-identical and is not a fresh write. No test here touches the network.
"""
import json

import pytest
import requests

import tip.core.ctid_processor as ctid
from tip.core import database_manager as dm

from urllib.parse import urlsplit


def _is_api(url: str) -> bool:
    """Route a mocked request by its exact host, never by substring."""
    return urlsplit(url).hostname == "api.github.com"

KEV_16 = "mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json"
KEV_15 = "mappings/kev/attack-15.1/kev-02.13.2025/enterprise/kev-02.13.2025_attack-15.1-enterprise.json"


def _tree(*paths, truncated=False):
    return {"sha": "x", "truncated": truncated, "tree": [{"path": p, "type": "blob"} for p in paths]}


def _obj(cve, tech, mtype, comment="c", group="xxe"):
    return {
        "capability_id": cve, "capability_description": "d", "mapping_type": mtype,
        "attack_object_id": tech, "attack_object_name": "n", "capability_group": group,
        "comments": comment, "references": [], "status": "complete",
    }


def _mapping(n=3):
    objs = []
    for i in range(1, n + 1):
        cve = f"CVE-2024-{i:04d}"
        objs.append(_obj(cve, "T1190", "exploitation_technique", comment=f"exploit {i}"))
        objs.append(_obj(cve, "T1059", "primary_impact", comment=f"impact {i}"))
    return {"metadata": {"attack_version": "16.1"}, "mapping_objects": objs}


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A processor writing to tmp, and a router for requests.get."""
    proc = ctid.CTIDProcessor()
    proc.db_path = str(tmp_path / "ctid_db.json")
    calls = []

    def route(tree, mapping):
        def fake_get(url, headers=None, timeout=None, **_):
            calls.append((url, dict(headers or {})))
            if _is_api(url):
                return tree() if callable(tree) else tree
            return mapping() if callable(mapping) else mapping
        monkeypatch.setattr(ctid.requests, "get", fake_get)

    return proc, tmp_path / "ctid_db.json", route, calls


# ── discovery ────────────────────────────────────────────────────────


def test_select_picks_newest_attack_version_then_newest_date():
    newer_date_older_attack = "mappings/kev/attack-15.1/kev-12.31.2025/enterprise/x.json"
    older_date_same_attack = "mappings/kev/attack-16.1/kev-01.01.2025/enterprise/y.json"
    path, ver, day = ctid.select_kev_file(_tree(KEV_15, newer_date_older_attack, older_date_same_attack, KEV_16))
    assert (path, ver, day) == (KEV_16, "16.1", "07.28.2025")


def test_select_compares_versions_numerically():
    v9 = "mappings/kev/attack-9.0/kev-01.01.2024/enterprise/a.json"
    v10 = "mappings/kev/attack-10.0/kev-01.01.2024/enterprise/b.json"
    assert ctid.select_kev_file(_tree(v9, v10))[1] == "10.0"


def test_select_ignores_mobile_and_other_frameworks():
    mobile = "mappings/kev/attack-17.0/kev-01.01.2026/mobile/m.json"
    other = "mappings/aws/attack-17.0/aws-01.01.2026/enterprise/a.json"
    assert ctid.select_kev_file(_tree(KEV_15, mobile, other))[0] == KEV_15


@pytest.mark.parametrize("tree", [
    _tree(),
    _tree("mappings/kev/attack-16.1/kev-07.28.2025/mobile/m.json"),
    _tree(KEV_16, truncated=True),
    {"message": "API rate limit exceeded"},
    [],
])
def test_select_fails_on_unusable_tree(tree):
    with pytest.raises(ctid.CTIDFormatError):
        ctid.select_kev_file(tree)


# ── parsing ──────────────────────────────────────────────────────────


def test_parse_groups_mappings_per_cve_with_type_and_comment():
    raw = {"mapping_objects": [
        _obj("CVE-2024-34102", "T1190", "exploitation_technique", comment="XXE exploit"),
        _obj("CVE-2024-34102", "T1059", "primary_impact"),
        _obj("CVE-2024-34102", "T1005", "secondary_impact"),
    ]}
    out = ctid.parse_mappings(raw)
    rec = out["CVE-2024-34102"]
    assert rec["group"] == "xxe"
    assert [t["id"] for t in rec["techniques"]] == ["T1190", "T1059", "T1005"]
    assert rec["techniques"][0] == {"id": "T1190", "mapping_type": ["exploitation_technique"],
                                    "comment": "XXE exploit"}


def test_parse_merges_one_technique_under_two_mapping_types():
    raw = {"mapping_objects": [
        _obj("CVE-2024-0001", "T1068", "secondary_impact", comment=""),
        _obj("CVE-2024-0001", "T1068", "exploitation_technique", comment="later comment"),
    ]}
    (tech,) = ctid.parse_mappings(raw)["CVE-2024-0001"]["techniques"]
    assert tech["mapping_type"] == ["exploitation_technique", "secondary_impact"]
    assert tech["comment"] == "later comment"


def test_parse_missing_comment_is_null():
    obj = _obj("CVE-2024-0001", "T1190", "exploitation_technique")
    del obj["comments"]
    assert ctid.parse_mappings({"mapping_objects": [obj]})["CVE-2024-0001"]["techniques"][0]["comment"] is None


def test_parse_skips_uncategorized_and_non_cve_capabilities():
    raw = {"mapping_objects": [
        _obj("CVE-2024-0001", "T1190", "uncategorized"),
        _obj("not-a-cve", "T1190", "exploitation_technique"),
    ]}
    assert ctid.parse_mappings(raw) == {}


@pytest.mark.parametrize("raw", [
    {},
    {"mapping_objects": "nope"},
    {"mapping_objects": ["nope"]},
    {"mapping_objects": [_obj("CVE-2024-0001", "not-a-technique", "exploitation_technique")]},
])
def test_parse_fails_on_malformed_file(raw):
    with pytest.raises(ctid.CTIDFormatError):
        ctid.parse_mappings(raw)


# ── fetch, write, fail closed ─────────────────────────────────────────


def test_update_writes_compact_db_with_meta(env):
    proc, db, route, calls = env
    route(_Resp(_tree(KEV_15, KEV_16)), _Resp(_mapping(3)))
    proc.update()
    data = json.loads(db.read_text())
    assert data["meta"]["path"] == KEV_16
    assert data["meta"]["attack_version"] == "16.1"
    assert data["meta"]["kev_date"] == "07.28.2025"
    assert data["meta"]["source"] == ctid.SOURCE
    assert len(data["cves"]) == 3
    assert calls[1][0] == ctid.DEFAULT_RAW_BASE + KEV_16
    assert ": " not in db.read_text()  # compact separators


def test_token_goes_in_a_header_never_a_url(env, monkeypatch):
    proc, _, route, calls = env
    monkeypatch.setenv("GITHUB_TOKEN", "sekrit-token")
    route(_Resp(_tree(KEV_16)), _Resp(_mapping(1)))
    proc.update()
    tree_url, tree_headers = calls[0]
    assert tree_headers["Authorization"] == "Bearer sekrit-token"
    assert all("sekrit-token" not in url for url, _ in calls)
    # The raw file host gets no token at all.
    assert "Authorization" not in calls[1][1]


def test_no_token_means_no_authorization_header(env, monkeypatch):
    proc, _, route, calls = env
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    route(_Resp(_tree(KEV_16)), _Resp(_mapping(1)))
    proc.update()
    assert "Authorization" not in calls[0][1]


def _seed(db, n=4):
    existing = {"meta": {"path": "old"}, "cves": {f"CVE-2020-{i:04d}": {"techniques": []} for i in range(n)}}
    db.write_text(json.dumps(existing))
    return db.read_bytes()


FAILURES = {
    "tree HTTP error": (_Resp({}, 403), _Resp(_mapping(4))),
    "tree connection error": (lambda: (_ for _ in ()).throw(requests.exceptions.ConnectionError("down")),
                              _Resp(_mapping(4))),
    "tree truncated": (_Resp(_tree(KEV_16, truncated=True)), _Resp(_mapping(4))),
    "tree lists no file": (_Resp(_tree()), _Resp(_mapping(4))),
    "file 404": (_Resp(_tree(KEV_16)), _Resp({}, 404)),
    "file not JSON": (_Resp(_tree(KEV_16)), _Resp(ValueError("html"))),
    "file malformed": (_Resp(_tree(KEV_16)), _Resp({"objects": []})),
    "file maps no CVE": (_Resp(_tree(KEV_16)), _Resp({"mapping_objects": []})),
    "under the floor": (_Resp(_tree(KEV_16)), _Resp(_mapping(1))),
}


@pytest.mark.parametrize("case", sorted(FAILURES))
def test_failure_keeps_prior_db_byte_identical(env, case):
    proc, db, route, _ = env
    before = _seed(db)
    route(*FAILURES[case])
    with pytest.raises(Exception):
        proc.update()
    assert db.read_bytes() == before


@pytest.fixture
def manager(tmp_path, monkeypatch):
    m = dm.DatabaseManager()
    monkeypatch.setattr(ctid.CTIDProcessor, "__init__", _init_at(tmp_path / "ctid_db.json"))
    return m


def _init_at(path):
    real = ctid.CTIDProcessor.__init__

    def init(self):
        real(self)
        self.db_path = str(path)
    return init


@pytest.mark.parametrize("case", sorted(FAILURES))
def test_manager_failure_is_not_fresh(manager, tmp_path, monkeypatch, case):
    db = tmp_path / "ctid_db.json"
    before = _seed(db)
    tree, mapping = FAILURES[case]

    def fake_get(url, headers=None, timeout=None, **_):
        r = tree if _is_api(url) else mapping
        return r() if callable(r) else r
    monkeypatch.setattr(ctid.requests, "get", fake_get)
    assert manager.update_database("ctid") is False
    assert "ctid" not in manager.fresh_writes
    assert db.read_bytes() == before


def test_manager_success_is_fresh(manager, tmp_path, monkeypatch):
    def fake_get(url, headers=None, timeout=None, **_):
        return _Resp(_tree(KEV_16)) if _is_api(url) else _Resp(_mapping(3))
    monkeypatch.setattr(ctid.requests, "get", fake_get)
    assert manager.update_database("ctid") is True
    assert "ctid" in manager.fresh_writes
    assert ctid.count_ctid(json.loads((tmp_path / "ctid_db.json").read_text())) == 3


def test_ctid_runs_in_the_daily_update_order(manager, monkeypatch):
    seen = []
    monkeypatch.setattr(manager, "update_database", lambda name: seen.append(name) or True)
    manager.update_all_databases()
    assert "ctid" in seen


def test_load_ctid_db_tolerates_missing_and_malformed(tmp_path):
    assert ctid.load_ctid_db(str(tmp_path / "nope.json")) is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert ctid.load_ctid_db(str(bad)) is None
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"cves": {"CVE-2024-0001": {"techniques": [{"id": "T1190"}]}}}))
    assert ctid.ctid_techniques(ctid.load_ctid_db(str(good))["CVE-2024-0001"]) == [{"id": "T1190"}]
