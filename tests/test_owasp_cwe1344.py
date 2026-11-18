"""Audit 2026-11-18 H3: the OWASP Top 10 2021 mapping is MITRE's CWE-1344 view.

The hand-written table that said it followed CWE-1344 had 98 memberships the
view does not and lacked 10 it does (CWE-327 under A02, A04 and A07; A09
with 21 CWEs against the view's 4). The database step now derives
owasp_db.json from the CWE XML each run, and the CVE processor reads it.

Fixture XML only; nothing touches the network.
"""
import json
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest

import tip.core.cve_processor as cve_mod
import tip.core.database_manager as dm_mod
from tip.core.owasp_processor import OWASPProcessor, owasp_mapping_from_cwe_xml

NAMES = {
    "A01": "Broken Access Control", "A02": "Cryptographic Failures", "A03": "Injection",
    "A04": "Insecure Design", "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}
# Members per category in the fixture. CWE-327 sits under A02 only, as in
# the real view; A09 has the view's four CWEs.
MEMBERS = {
    "A01": ["22", "862"], "A02": ["319", "327"], "A03": ["79", "89"], "A04": ["419", "444"],
    "A05": ["16"], "A06": ["937", "1104"], "A07": ["287", "346", "613", "940"],
    "A08": ["502"], "A09": ["117", "223", "532", "778"], "A10": ["918"],
}


def _catalog(ns="http://cwe.mitre.org/cwe-8", tag="Grouping", skip=(), version="5.0"):
    groups = []
    for n, (key, cwes) in enumerate(sorted(MEMBERS.items())):
        if key in skip:
            continue
        members = "".join(f'<Has_Member CWE_ID="{c}" View_ID="1344"/>' for c in cwes)
        # A membership in another view must not count.
        members += '<Has_Member CWE_ID="99999" View_ID="1400"/>'
        groups.append(
            f'<{tag} ID="{1345 + n}" Name="OWASP Top Ten 2021 Category {key}:2021 - {NAMES[key]}" '
            f'Status="Incomplete"><Summary>About {key}.</Summary>'
            f'<Relationships>{members}</Relationships></{tag}>'
        )
    # An unrelated grouping and the 2017 edition's category are ignored.
    groups.append(f'<{tag} ID="1" Name="Comprehensive Categorization: Injection"><Relationships>'
                  f'<Has_Member CWE_ID="79" View_ID="1344"/></Relationships></{tag}>')
    groups.append(f'<{tag} ID="2" Name="OWASP Top Ten 2017 Category A1 - Injection"><Relationships>'
                  f'<Has_Member CWE_ID="77" View_ID="1026"/></Relationships></{tag}>')
    container = "Groupings" if tag == "Grouping" else "Categories"
    return (f'<?xml version="1.0" encoding="UTF-8"?><Weakness_Catalog Name="CWE" Version="{version}" '
            f'xmlns="{ns}"><Weaknesses><Weakness ID="79" Name="XSS"><Description>x</Description>'
            f'</Weakness></Weaknesses><{container}>{"".join(groups)}</{container}></Weakness_Catalog>')


def test_mapping_comes_from_the_1344_view():
    data = owasp_mapping_from_cwe_xml(ET.fromstring(_catalog()))
    assert list(data["categories"]) == [f"A{n:02d}:2021" for n in range(1, 11)]
    assert data["categories"]["A09:2021"]["cwe_ids"] == ["117", "223", "532", "778"]
    assert data["categories"]["A07:2021"]["name"] == "Identification and Authentication Failures"
    assert data["categories"]["A07:2021"]["cwe_grouping"] == "CWE-1351"
    assert data["cwe_mapping"]["327"] == ["A02:2021"]
    assert "99999" not in data["cwe_mapping"]  # other view
    assert "77" not in data["cwe_mapping"]     # 2017 edition
    assert data["cwe_mapping"]["79"] == ["A03:2021"]
    assert data["source"] == "MITRE CWE-1344 view, CWE catalog 5.0"


def test_cwe4_category_form_parses_the_same():
    old = owasp_mapping_from_cwe_xml(ET.fromstring(_catalog("http://cwe.mitre.org/cwe-7", "Category")))
    new = owasp_mapping_from_cwe_xml(ET.fromstring(_catalog()))
    assert old["cwe_mapping"] == new["cwe_mapping"]


@pytest.mark.parametrize("skip", [("A09",), ("A01", "A10")])
def test_a_missing_category_raises(skip):
    with pytest.raises(ValueError, match="A"):
        owasp_mapping_from_cwe_xml(ET.fromstring(_catalog(skip=skip)))


def _zip(tmp_path: Path, xml: str) -> Path:
    path = tmp_path / "cwec_latest.xml.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("cwec_v5.0.xml", xml)
    return path


def _manager(tmp_path, target, xml):
    manager = dm_mod.DatabaseManager()
    manager.databases["owasp"]["file"] = str(target)
    src = _zip(tmp_path, xml)

    def fake_download(url, filename):
        Path(filename).write_bytes(src.read_bytes())
        return True
    manager._download_file = fake_download  # type: ignore[method-assign]
    return manager


def test_database_step_writes_owasp_db(tmp_path):
    target = tmp_path / "owasp_db.json"
    manager = _manager(tmp_path, target, _catalog())
    assert manager.update_database("owasp") is True
    data = json.loads(target.read_text())
    assert data["cwe_mapping"]["327"] == ["A02:2021"]
    assert "owasp" in manager.fresh_writes


def test_database_step_fails_and_keeps_the_file_without_all_categories(tmp_path):
    target = tmp_path / "owasp_db.json"
    target.write_text(json.dumps(owasp_mapping_from_cwe_xml(ET.fromstring(_catalog()))))
    before = target.read_bytes()
    manager = _manager(tmp_path, target, _catalog(skip=("A04",)))
    assert manager.update_database("owasp") is False
    assert target.read_bytes() == before


def test_processor_reads_the_published_file(tmp_path):
    path = tmp_path / "owasp_db.json"
    path.write_text(json.dumps(owasp_mapping_from_cwe_xml(ET.fromstring(_catalog()))))
    proc = OWASPProcessor(path)
    assert proc.get_owasp_categories_for_cwe("CWE-327") == ["A02:2021"]
    assert proc.get_owasp_categories_for_cwes(["CWE-862", "319"]) == {"A01:2021", "A02:2021"}
    assert proc.get_owasp_categories_for_cwe("CWE-1") == []


def test_processor_keeps_its_mapping_when_a_reload_fails(tmp_path):
    path = tmp_path / "owasp_db.json"
    path.write_text(json.dumps(owasp_mapping_from_cwe_xml(ET.fromstring(_catalog()))))
    proc = OWASPProcessor(path)
    path.write_text("{")
    assert proc.load() is False
    assert proc.get_owasp_categories_for_cwe("327") == ["A02:2021"]


def test_cve_step_fails_without_an_owasp_mapping(tmp_path, monkeypatch):
    """A missing owasp_db.json must not strip OWASP from every rewritten record."""
    monkeypatch.chdir(tmp_path)
    proc = cve_mod.CVEProcessor.__new__(cve_mod.CVEProcessor)
    proc.logger = cve_mod.get_logger("test_owasp")
    proc.cwe_db, proc.capec_db = {}, {}
    proc.cwe_file = str(tmp_path / "cwe_db.json")
    proc.capec_file = str(tmp_path / "capec_db.json")
    proc.owasp_processor = OWASPProcessor(tmp_path / "missing_owasp_db.json")
    proc.epss_processor = None
    proc.cve_file = str(tmp_path / "new_cves.jsonl")
    Path(proc.cve_file).write_text(json.dumps({"CVE-2026-0001": {
        "CWE": [], "CAPEC": [], "TECHNIQUES": [], "DEFEND": []}}) + "\n")
    saved = []
    proc.save_results = lambda results: saved.append(results)  # type: ignore[method-assign]
    monkeypatch.setattr(cve_mod, "load_ctid_db", lambda path: None)

    assert proc.process_file() is False
    assert saved == []
