"""F4: correlation correctness (ISC-21 to ISC-29).

Fixture data only; NVD is never contacted.
"""
import gzip
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

import tip.core.cve_processor as cve_mod
from tip.core import id_normalize as ids
from tip.core.cve_processor import CVEProcessor, nvd_request_delay
from tip.core.entity_index_generator import generate_entity_index
from tip.utils.error_handler import NVDUnavailableError

# 79 -ChildOf-> 74 -ChildOf-> 707 ; only 707 carries a CAPEC.
CWE_DB = {
    "79": {"name": "XSS", "ChildOf": ["74"], "RelatedAttackPatterns": ["63"]},
    "74": {"name": "Injection", "ChildOf": ["707"], "RelatedAttackPatterns": []},
    "707": {"name": "Improper Neutralization", "ChildOf": [], "RelatedAttackPatterns": ["152"]},
}


# ISC-21 / ISC-23 ---------------------------------------------------------------

def test_normalizers():
    assert ids.normalize_cwe_id(" cwe-079 ") == "CWE-79"
    assert ids.normalize_cwe_id("74") == "CWE-74"
    assert ids.normalize_cwe_id("NVD-CWE-Other") is None
    assert ids.normalize_technique_id("1562.003") == "T1562.003"
    assert ids.normalize_technique_id("t1059") == "T1059"
    assert ids.normalize_capec_id("63") == "CAPEC-63"


def _bare_processor():
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.cwe_db = CWE_DB
    proc.capec_db = {}
    proc.techniques_db = {}
    proc.logger = logging.getLogger("test")
    proc.owasp_processor = SimpleNamespace(get_owasp_categories_for_cve=lambda rec: [])
    proc.kev_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.vulnrichment_processor = SimpleNamespace(lookup=lambda cid: None)
    proc.apt_processor = SimpleNamespace(lookup_by_techniques=lambda t: [])
    return proc


def test_ingest_normalizes_mixed_cwe_shape_with_one_parent_level():
    """The real shard shape ['74','CWE-79'] comes out as CWE-<n> only."""
    out = _bare_processor().process_cve_pipeline({"CVE-2024-0001": {"CWE": ["74", "CWE-79"]}})
    rec = out["CVE-2024-0001"]
    # 79 -> +74 ; 74 -> +707 (one level from each listed CWE), all prefixed.
    assert rec["CWE"] == ["CWE-74", "CWE-79", "CWE-707"]
    assert all(c.startswith("CWE-") for c in rec["CWE"])
    assert rec["CAPEC"] == ["152", "63"]


def test_processor_and_shared_definition_agree():
    """One parent definition: the processor's expansion IS expand_cwe_list."""
    proc = _bare_processor()
    for cwes in (["CWE-79"], ["79"], ["74", "CWE-79"], ["CWE-707"], []):
        out = proc.process_cve_pipeline({"CVE-2024-0002": {"CWE": cwes}})
        assert out["CVE-2024-0002"]["CWE"] == ids.expand_cwe_list(CWE_DB, cwes)
    assert proc.get_parent_cwe("79") == ["CWE-74"]  # one level only
    # CAPEC inheritance walks the whole chain: 79 reaches 707's CAPEC-152.
    assert ids.cwe_capecs_with_ancestors(CWE_DB, "CWE-79") == {"63", "152"}


# Generator fixture ---------------------------------------------------------------

def _write_fixture(base: Path, shard_records: dict, *, kev=None, vulnrich=None):
    data = base / "docs" / "data"
    db = base / "docs" / "database"
    data.mkdir(parents=True)
    db.mkdir(parents=True)
    (data / "cwe_db.json").write_text(json.dumps(CWE_DB))
    (data / "capec_db.json").write_text(json.dumps({
        "63": {"name": "XSS pattern", "techniques": "::TAXONOMY NAME:ATTACK:ENTRY ID:1059::"},
        "152": {"name": "Inject", "techniques": "::TAXONOMY NAME:ATTACK:ENTRY ID:1562.003::"},
    }))
    (data / "techniques_db.json").write_text(json.dumps({"1059": {"name": "Command Interpreter"}}))
    (data / "groups_db.json").write_text(json.dumps({
        "groups": {"G0007": {"name": "APT28", "aliases": [], "techniques": ["T1059", "T9999"]}},
        "technique_to_groups": {"T1059": ["G0007"]},
    }))
    (data / "campaigns_db.json").write_text(json.dumps({}))
    (data / "kev_db.json").write_text(json.dumps(kev or {}))
    (data / "vulnrichment_db.json").write_text(json.dumps(vulnrich or {}))
    with open(data / "defend_db.jsonl", "w") as f:
        f.write(json.dumps({"1059": {"defensive_techniques": [{"id": "D3-EAL", "name": "Allowlisting"}]}}) + "\n")
    with gzip.open(db / "CVE-2024.jsonl.gz", "wt") as f:
        for k, v in shard_records.items():
            f.write(json.dumps({k: v}) + "\n")


def _dangling(entities):
    return [(eid, rel, t) for eid, e in entities.items()
            for rel, v in e["rels"].items() for t in v["ids"] if t not in entities]


KEV_ENTRY = {"inKEV": True, "dateAdded": "2024-01-01", "vendorProject": "V", "product": "P"}


def test_generator_links_existing_bare_shards_resolvably(tmp_path):
    """ISC-22: an old shard with bare parent CWEs and bare technique ids."""
    _write_fixture(tmp_path, {
        "CVE-2024-0001": {"CWE": ["74", "CWE-79"], "CAPEC": ["63"], "TECHNIQUES": ["1059"]},
    }, kev={"CVE-2024-0001": KEV_ENTRY})
    ei, _, _ = generate_entity_index(tmp_path)
    rels = ei["entities"]["CVE-2024-0001"]["rels"]
    assert rels["cwe"]["ids"] == ["CWE-74", "CWE-79"]
    assert rels["technique"]["ids"] == ["T1059"]
    assert rels["capec"]["ids"] == ["CAPEC-63"]
    assert rels["apt_group"]["ids"] == ["G0007"]
    assert rels["defend"]["ids"] == ["D3-EAL"]
    assert "CVE-2024-0001" in ei["entities"]["CWE-74"]["rels"]["cve"]["ids"]


def test_generator_drops_and_counts_dangling_rels(tmp_path):
    """ISC-24: targets with no entity are dropped from both sides and counted."""
    _write_fixture(tmp_path, {
        # CWE-399 is a category (not in cwe_db), T1562.003 is absent from ATT&CK.
        "CVE-2024-0001": {"CWE": ["CWE-79", "CWE-399"], "CAPEC": ["63", "999"],
                          "TECHNIQUES": ["1059", "1562.003"], "OWASP": ["A03:2021"]},
    }, kev={"CVE-2024-0001": KEV_ENTRY})
    ei, _, _ = generate_entity_index(tmp_path)
    ents = ei["entities"]
    assert _dangling(ents) == []
    # CWE-399, CAPEC-999, T1562.003 (from the CVE and from CAPEC-152), T9999 (group).
    assert ei["meta"]["dropped_dangling_rels"] >= 5
    assert ents["CVE-2024-0001"]["rels"]["technique"]["ids"] == ["T1059"]
    assert "technique" not in ents["CAPEC-152"]["rels"]
    assert ents["A03:2021"]["type"] == "owasp"  # OWASP entities still created


def test_layer2_rule(tmp_path):
    """ISC-26: KEV, APT-linked, SSVC active qualify; plain vulnrichment does not.
    KEV CVEs without CWE data or without any shard record are still indexed."""
    active = {"ssvcExploitStatus": "active"}
    _write_fixture(tmp_path, {
        "CVE-2024-0001": {"CWE": ["CWE-79"]},                       # KEV
        "CVE-2024-0002": {"CWE": []},                               # KEV, no CWE
        "CVE-2024-0003": {"CWE": ["CWE-79"], "APT_GROUPS": [{"id": "G0007"}]},
        "CVE-2024-0004": {"CWE": ["CWE-79"], "VULNRICHMENT": active},
        "CVE-2024-0005": {"CWE": ["CWE-79"]},                       # SSVC active via db
        "CVE-2024-0006": {"CWE": ["CWE-79"], "VULNRICHMENT": {"ssvcExploitStatus": "none"}},
        "CVE-2024-0007": {"CWE": ["CWE-79"]},                       # vulnrichment 'poc' only
        "CVE-2024-0008": {"CWE": ["CWE-79"]},                       # nothing
    }, kev={
        "CVE-2024-0001": KEV_ENTRY, "CVE-2024-0002": KEV_ENTRY,
        "CVE-2026-9999": KEV_ENTRY,                                 # no shard record yet
    }, vulnrich={
        "CVE-2024-0005": active,
        "CVE-2024-0007": {"ssvcExploitStatus": "poc"},
    })
    ei, _, cve_ids = generate_entity_index(tmp_path)
    cves = sorted(k for k, e in ei["entities"].items() if e["type"] == "cve")
    assert cves == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003",
                    "CVE-2024-0004", "CVE-2024-0005", "CVE-2026-9999"]
    synth = ei["entities"]["CVE-2026-9999"]
    assert synth["kev"] is True and synth["kev_detail"]["vendorProject"] == "V"
    assert ei["entities"]["CVE-2024-0002"]["kev"] is True
    assert cve_ids["count"] == 8  # Layer 1 still covers every shard CVE


def test_layer2_is_stable_across_vulnrichment_wipe_and_resync(tmp_path):
    """A wiped or massively grown vulnrichment_db cannot change Layer 2 membership
    beyond SSVC-active entries."""
    shard = {f"CVE-2024-{i:04d}": {"CWE": ["CWE-79"]} for i in range(1, 51)}
    kev = {"CVE-2024-0001": KEV_ENTRY}

    def cve_count(vulnrich, base):
        _write_fixture(base, shard, kev=kev, vulnrich=vulnrich)
        ei, _, _ = generate_entity_index(base)
        return sum(1 for e in ei["entities"].values() if e["type"] == "cve")

    wiped = cve_count({}, tmp_path / "wiped")
    resynced = cve_count({k: {"ssvcExploitStatus": "none"} for k in shard}, tmp_path / "resync")
    assert wiped == resynced == 1


# ISC-27 / ISC-28 / ISC-29 ------------------------------------------------------

class _Cfg:
    def __init__(self, progress_file, key=None):
        self._progress = str(progress_file)
        self._key = key

    def get_api_key(self, _):
        return self._key

    def get(self, key, default=None):
        return {
            "api.nvd.base_url": "https://nvd.example/cves",
            "api.nvd.results_per_page": 2,
            "api.nvd.timeout": 30,
            "api.nvd.rate_limit": {"base_delay": 0.1, "max_delay": 0.5, "max_retries": 2},
            "files.progress_file": self._progress,
            "progress_tracking.save_interval": 2,
            "progress_tracking.log_interval": 10,
        }.get(key, default)


class _Page:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _vulns(start, n):
    return [{"cve": {"id": f"CVE-2024-{start + i:04d}"}} for i in range(n)]


def _crawl(tmp_path, monkeypatch, pages, key=None):
    proc = CVEProcessor.__new__(CVEProcessor)
    proc.config = _Cfg(tmp_path / "progress.json", key)
    proc.logger = logging.getLogger("test_nvd")
    sleeps, seen = [], []
    monkeypatch.setattr(cve_mod.time, "sleep", lambda s: sleeps.append(s))

    def fake_get(url, headers=None, params=None, timeout=None):
        seen.append(params["startIndex"])
        return _Page(pages[params["startIndex"]])

    monkeypatch.setattr(cve_mod.requests, "get", fake_get)
    return proc, sleeps, seen


def test_crawl_completes_on_total_results(tmp_path, monkeypatch):
    pages = {0: {"totalResults": 5, "vulnerabilities": _vulns(0, 2)},
             2: {"totalResults": 5, "vulnerabilities": _vulns(2, 2)},
             4: {"totalResults": 5, "vulnerabilities": _vulns(4, 1)}}
    proc, _, seen = _crawl(tmp_path, monkeypatch, pages)
    assert len(proc.retrieve_cves_from_nvd()) == 5
    assert seen == [0, 2, 4]


def test_short_page_mid_crawl_is_not_end_of_corpus(tmp_path, monkeypatch):
    pages = {0: {"totalResults": 5, "vulnerabilities": _vulns(0, 1)},   # short page
             1: {"totalResults": 5, "vulnerabilities": _vulns(1, 2)},
             3: {"totalResults": 5, "vulnerabilities": _vulns(3, 2)}}
    proc, _, seen = _crawl(tmp_path, monkeypatch, pages)
    assert len(proc.retrieve_cves_from_nvd()) == 5
    assert seen == [0, 1, 3]


@pytest.mark.parametrize("bad_page", [
    {"totalResults": 5, "vulnerabilities": []},   # empty before totalResults
    {"vulnerabilities": _vulns(2, 2)},            # totalResults missing
])
def test_truncated_or_malformed_page_fails(tmp_path, monkeypatch, bad_page):
    pages = {0: {"totalResults": 5, "vulnerabilities": _vulns(0, 2)}, 2: bad_page}
    proc, _, _ = _crawl(tmp_path, monkeypatch, pages)
    with pytest.raises(NVDUnavailableError) as exc:
        proc.retrieve_cves_from_nvd()
    assert exc.value.last_index == 2


def test_pacing_matches_nvd_guidance(tmp_path, monkeypatch):
    assert nvd_request_delay(False) == 6.0
    assert nvd_request_delay(True) == 0.6
    pages = {0: {"totalResults": 4, "vulnerabilities": _vulns(0, 2)},
             2: {"totalResults": 4, "vulnerabilities": _vulns(2, 2)}}
    for key, expected in ((None, 6.0), ("k", 0.6)):
        proc, sleeps, _ = _crawl(tmp_path, monkeypatch, pages, key=key)
        proc.retrieve_cves_from_nvd()
        assert sleeps == [expected]  # one gap between two pages, no adaptive drift


def test_resumed_fetch_is_flagged_and_reported_partial(tmp_path, monkeypatch):
    (tmp_path / "progress.json").write_text(json.dumps({"last_index": 2}))
    pages = {2: {"totalResults": 4, "vulnerabilities": _vulns(2, 2)}}
    proc, _, seen = _crawl(tmp_path, monkeypatch, pages)
    assert len(proc.retrieve_cves_from_nvd()) == 2
    assert seen == [2]
    assert proc.last_fetch_resumed_from == 2

    from tip.core.pipeline_orchestrator import PipelineOrchestrator
    orch = PipelineOrchestrator.__new__(PipelineOrchestrator)
    orch.results = {}
    orch.config = SimpleNamespace(get_output_path=lambda _: str(tmp_path / "new_cves.jsonl"))
    orch.cve_processor = proc
    monkeypatch.setattr(proc, "process_nvd_cves", lambda cves: {c["cve"]["id"]: {} for c in cves})
    (tmp_path / "progress.json").write_text(json.dumps({"last_index": 2}))  # consumed above
    orch._retrieve_cves()
    assert orch.results["cve_retrieval"]["status"] == "partial"
    assert orch.results["cve_retrieval"]["resumed_from_index"] == 2


def test_fresh_fetch_is_not_flagged(tmp_path, monkeypatch):
    pages = {0: {"totalResults": 2, "vulnerabilities": _vulns(0, 2)}}
    proc, _, _ = _crawl(tmp_path, monkeypatch, pages)
    proc.retrieve_cves_from_nvd()
    assert proc.last_fetch_resumed_from == 0
