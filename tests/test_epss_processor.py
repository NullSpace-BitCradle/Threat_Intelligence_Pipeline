"""I1: EPSS processor (ISC-1 to ISC-4, ISC-12 shape).

The bulk file is FIRST's daily CSV, gzipped: a ``#model_version:...,score_date:...``
comment line, a ``cve,epss,percentile`` header, then one row per CVE. All HTTP
is mocked; tests run in a scratch cwd so config-relative paths never touch the
real docs/data.
"""
import gzip
import json
import sys
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tip.core import epss_processor as ep  # noqa: E402
from tip.utils.atomic_io import DataFloorError  # noqa: E402

HEADER = "#model_version:v2026.06.15,score_date:2026-09-26T12:00:22Z\n"
ROWS = [
    ("CVE-1999-0001", "0.03351", "0.88243"),
    ("CVE-2023-44487", "0.99999", "0.99998"),
    ("CVE-2024-1234", "0.5", "0.97"),
]


def make_csv(rows=ROWS, header=HEADER, columns="cve,epss,percentile\n") -> bytes:
    body = header + columns + "".join(f"{c},{s},{p}\n" for c, s, p in rows)
    return gzip.compress(body.encode("utf-8"))


class _Resp:
    def __init__(self, content: bytes, status: int = 200):
        self.content = content
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")


@pytest.fixture
def scratch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "docs" / "data"
    data.mkdir(parents=True)
    entities = {
        "CVE-2023-44487": {"type": "cve", "id": "CVE-2023-44487"},
        "CVE-2024-1234": {"type": "cve", "id": "CVE-2024-1234"},
        "CVE-2099-0001": {"type": "cve", "id": "CVE-2099-0001"},  # FIRST has no score
        "T1499": {"type": "technique", "id": "T1499"},
    }
    (data / "entity_index.json").write_text(json.dumps({"meta": {}, "entities": entities}))
    return data


def _serve(monkeypatch, content: bytes, status: int = 200):
    calls = []

    def fake_get(url, *a, **k):
        calls.append(url)
        return _Resp(content, status)

    monkeypatch.setattr(ep.requests, "get", fake_get)
    return calls


# ISC-1 ---------------------------------------------------------------------

def test_parse_bulk_csv_scores_and_header():
    snap = ep.parse_bulk(make_csv())
    assert snap.model_version == "v2026.06.15"
    assert snap.score_date == "2026-09-26T12:00:22Z"
    assert snap.date == "2026-09-26"
    assert snap.row_count == 3
    assert snap.lookup("CVE-2023-44487") == {
        "score": 0.99999, "percentile": 0.99998, "date": "2026-09-26", "model_version": "v2026.06.15",
    }
    assert snap.lookup("cve-1999-0001")["score"] == 0.03351
    assert snap.lookup("CVE-2000-0000") is None


@pytest.mark.parametrize("header", [
    "",                                             # no comment line at all
    "#model_version:v2026.06.15\n",                 # score_date missing
    "#score_date:2026-09-26T12:00:22Z\n",           # model_version missing
    "#model_version:,score_date:2026-09-26\n",      # empty model_version
    "#model_version:v1,score_date:not-a-date\n",    # unparseable date
])
def test_malformed_header_raises(header):
    with pytest.raises(ep.EPSSFormatError):
        ep.parse_bulk(make_csv(header=header))


def test_wrong_column_header_raises():
    with pytest.raises(ep.EPSSFormatError):
        ep.parse_bulk(make_csv(columns="cve,score,pct\n"))


@pytest.mark.parametrize("row", [
    ("NOT-A-CVE", "0.1", "0.1"),
    ("CVE-2024-0001", "abc", "0.1"),
    ("CVE-2024-0001", "1.5", "0.1"),
    ("CVE-2024-0001", "0.1", "-0.1"),
])
def test_malformed_row_raises(row):
    with pytest.raises(ep.EPSSFormatError):
        ep.parse_bulk(make_csv(rows=ROWS + [row]))


def test_not_gzip_raises():
    with pytest.raises(ep.EPSSFormatError):
        ep.parse_bulk(b"<html>maintenance</html>")


def test_empty_body_raises():
    with pytest.raises(ep.EPSSFormatError):
        ep.parse_bulk(make_csv(rows=[]))


def test_fetch_is_cached_per_instance(monkeypatch):
    calls = _serve(monkeypatch, make_csv())
    proc = ep.EPSSProcessor()
    first = proc.fetch()
    second = proc.fetch()
    assert first is second
    assert len(calls) == 1
    assert calls[0] == ep.DEFAULT_URL


def test_fetch_download_error_raises_network_error(monkeypatch):
    def boom(*a, **k):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(ep.requests, "get", boom)
    with pytest.raises(ep.NetworkError):
        ep.EPSSProcessor().fetch()


def test_fetch_http_error_raises(monkeypatch):
    _serve(monkeypatch, b"", status=503)
    with pytest.raises(ep.NetworkError):
        ep.EPSSProcessor().fetch()


# ISC-4 ---------------------------------------------------------------------

def test_build_curated_only_curated_tier(scratch, monkeypatch):
    _serve(monkeypatch, make_csv())
    proc = ep.EPSSProcessor()
    curated = proc.build_curated(proc.fetch())
    assert curated["meta"]["model_version"] == "v2026.06.15"
    assert curated["meta"]["score_date"] == "2026-09-26T12:00:22Z"
    assert curated["meta"]["date"] == "2026-09-26"
    assert curated["meta"]["total_count"] == 3
    assert curated["meta"]["curated_count"] == 2
    # Only curated-tier CVEs FIRST scores; CVE-1999-0001 is not curated,
    # CVE-2099-0001 has no score, T1499 is not a CVE.
    assert curated["scores"] == {
        "CVE-2023-44487": {"score": 0.99999, "percentile": 0.99998},
        "CVE-2024-1234": {"score": 0.5, "percentile": 0.97},
    }


def test_update_writes_curated_file(scratch, monkeypatch):
    _serve(monkeypatch, make_csv())
    proc = ep.EPSSProcessor()
    assert proc.update() is True
    out = json.loads((scratch / "epss_curated.json").read_text())
    assert out["meta"]["total_count"] == 3
    assert set(out["scores"]) == {"CVE-2023-44487", "CVE-2024-1234"}


def test_update_without_entity_index_skips_curated_file(scratch, monkeypatch, caplog):
    """A fresh fork has no entity index yet: the bulk file is still fetched and
    validated, the curated file is skipped with a clear log line, and the step
    does not fail."""
    (scratch / "entity_index.json").unlink()
    _serve(monkeypatch, make_csv())
    with caplog.at_level("WARNING"):
        assert ep.EPSSProcessor().update() is True
    assert not (scratch / "epss_curated.json").exists()
    assert "skipping epss_curated.json" in caplog.text


def test_update_without_entity_index_still_fails_on_bad_download(scratch, monkeypatch):
    (scratch / "entity_index.json").unlink()
    _serve(monkeypatch, make_csv(header="#nope\n"))
    assert ep.EPSSProcessor().update() is False


def _index(scratch, cves):
    (scratch / "entity_index.json").write_text(
        json.dumps({"entities": {c: {"type": "cve"} for c in cves}})
    )


def test_empty_index_does_not_replace_nonempty_curated_file(scratch, monkeypatch):
    """ISC-2 on the curated tier: an index that parses with zero CVE entities
    must not publish scores {} over a good file."""
    before = _seed_good(scratch, monkeypatch)
    _index(scratch, [])
    _serve(monkeypatch, make_csv())
    assert ep.EPSSProcessor().update() is False
    assert (scratch / "epss_curated.json").read_bytes() == before


def test_curated_count_under_half_of_prior_is_refused(scratch, monkeypatch):
    rows = ROWS + [(f"CVE-2020-{i:05d}", "0.1", "0.2") for i in range(10)]
    _index(scratch, [r[0] for r in rows])
    before = _seed_good(scratch, monkeypatch, rows=rows)  # 13 curated
    _index(scratch, [r[0] for r in rows[:6]])               # 6 < 50% of 13
    _serve(monkeypatch, make_csv(rows=rows))
    assert ep.EPSSProcessor().update() is False
    assert (scratch / "epss_curated.json").read_bytes() == before
    _index(scratch, [r[0] for r in rows[:7]])               # 7 >= 50% of 13
    assert ep.EPSSProcessor().update() is True


def test_empty_index_without_prior_file_is_refused(scratch, monkeypatch):
    _index(scratch, [])
    _serve(monkeypatch, make_csv())
    assert ep.EPSSProcessor().update() is False
    assert not (scratch / "epss_curated.json").exists()


# Item 3: bounded retry ------------------------------------------------------

@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    slept = []
    monkeypatch.setattr(ep.time, "sleep", lambda s: slept.append(s))
    return slept


def test_transient_download_error_is_retried(monkeypatch, no_sleep):
    calls = []

    def flaky(url, *a, **k):
        calls.append(url)
        if len(calls) < 3:
            raise requests.exceptions.ConnectionError("blip")
        return _Resp(make_csv())

    monkeypatch.setattr(ep.requests, "get", flaky)
    assert ep.EPSSProcessor().fetch().row_count == 3
    assert len(calls) == 3
    assert len(no_sleep) == 2 and all(0 < s <= 10 for s in no_sleep)


def test_retry_is_bounded(monkeypatch, no_sleep):
    calls = []

    def down(url, *a, **k):
        calls.append(url)
        return _Resp(b"", status=503)

    monkeypatch.setattr(ep.requests, "get", down)
    with pytest.raises(ep.NetworkError):
        ep.EPSSProcessor().fetch()
    assert len(calls) == ep.EPSS_ATTEMPTS == 3


def test_format_error_is_not_retried(monkeypatch, no_sleep):
    calls = _serve(monkeypatch, make_csv(header="#nope\n"))
    with pytest.raises(ep.EPSSFormatError):
        ep.EPSSProcessor().fetch()
    assert len(calls) == 1 and no_sleep == []


# ISC-2 ---------------------------------------------------------------------

def _seed_good(scratch, monkeypatch, rows=ROWS) -> bytes:
    _serve(monkeypatch, make_csv(rows=rows))
    assert ep.EPSSProcessor().update() is True
    return (scratch / "epss_curated.json").read_bytes()


def test_download_error_leaves_prior_output_identical(scratch, monkeypatch):
    before = _seed_good(scratch, monkeypatch)

    def boom(*a, **k):
        raise requests.exceptions.Timeout("slow")

    monkeypatch.setattr(ep.requests, "get", boom)
    assert ep.EPSSProcessor().update() is False
    assert (scratch / "epss_curated.json").read_bytes() == before


def test_malformed_header_leaves_prior_output_identical(scratch, monkeypatch):
    before = _seed_good(scratch, monkeypatch)
    _serve(monkeypatch, make_csv(header="#garbage\n"))
    assert ep.EPSSProcessor().update() is False
    assert (scratch / "epss_curated.json").read_bytes() == before


def test_row_count_under_half_of_last_good_is_refused(scratch, monkeypatch):
    big = ROWS + [(f"CVE-2020-{i:05d}", "0.1", "0.2") for i in range(1000)]
    before = _seed_good(scratch, monkeypatch, rows=big)
    # 400 rows is under 50% of the last good 1003.
    small = ROWS + [(f"CVE-2020-{i:05d}", "0.1", "0.2") for i in range(400)]
    _serve(monkeypatch, make_csv(rows=small))
    proc = ep.EPSSProcessor()
    with pytest.raises(DataFloorError):
        proc.write_curated(proc.fetch())
    assert ep.EPSSProcessor().update() is False
    assert (scratch / "epss_curated.json").read_bytes() == before


def test_row_count_at_half_is_accepted(scratch, monkeypatch):
    big = ROWS + [(f"CVE-2020-{i:05d}", "0.1", "0.2") for i in range(997)]  # 1000 rows
    _seed_good(scratch, monkeypatch, rows=big)
    half = ROWS + [(f"CVE-2020-{i:05d}", "0.1", "0.2") for i in range(497)]  # 500 rows
    _serve(monkeypatch, make_csv(rows=half))
    assert ep.EPSSProcessor().update() is True


# ISC-3 ---------------------------------------------------------------------

def test_db_step_at_real_row_count_writes_only_the_small_curated_file(scratch, monkeypatch):
    """ISC-3, behavioral: the real database step, fed a bulk file at the real
    2026-09-26 row count, adds exactly one file under docs/ (the curated one),
    and it is under 200 KB and holds only the curated tier."""
    from tip.core.database_manager import DatabaseManager

    total = 379_842
    rows = [(f"CVE-2020-{i:06d}", "0.12345", "0.67891") for i in range(total)]
    entities = {f"CVE-2020-{i:06d}": {"type": "cve"} for i in range(0, 1728 * 200, 200)}
    (scratch / "entity_index.json").write_text(json.dumps({"entities": entities}))
    docs = Path("docs")
    before = {p for p in docs.rglob("*") if p.is_file()}
    _serve(monkeypatch, make_csv(rows=rows))

    assert DatabaseManager().update_database("epss") is True

    added = {p for p in docs.rglob("*") if p.is_file()} - before
    assert added == {docs / "data" / "epss_curated.json"}
    out = docs / "data" / "epss_curated.json"
    assert out.stat().st_size < 200 * 1024, out.stat().st_size
    data = json.loads(out.read_text())
    assert data["meta"]["total_count"] == total
    assert len(data["scores"]) == 1728
