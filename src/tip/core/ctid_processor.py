"""
MITRE CTID Mappings Explorer (KEV) processor.

MITRE's Center for Threat-Informed Defense publishes hand-analyzed ATT&CK
mappings for CISA KEV CVEs in
github.com/center-for-threat-informed-defense/mappings-explorer (Apache-2.0),
under ``mappings/kev/attack-<ver>/kev-<MM.DD.YYYY>/enterprise/*.json``. Each
mapping object names a CVE (``capability_id``), a technique
(``attack_object_id``), how the technique relates to the CVE
(``mapping_type``: exploitation_technique, primary_impact or
secondary_impact) and the analyst's comment.

This processor discovers the newest enterprise KEV file from the repository
tree (newest ATT&CK version first, then newest KEV date), parses it into one
compact record per CVE, and writes docs/data/ctid_db.json. Fail closed: a
tree, download or parse failure raises, and the floor in write_reference_db
refuses a result under half of the previous CVE count, so the previous file
stays byte-identical.
"""
from __future__ import annotations

import json
import os
import re
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger
from tip.utils.atomic_io import write_reference_db

config = get_config()

SOURCE = "MITRE CTID Mappings Explorer (KEV)"
TIER = "official"
REPO = "center-for-threat-informed-defense/mappings-explorer"
BRANCH = "main"
DEFAULT_TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/{BRANCH}?recursive=1"
DEFAULT_RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/"
DEFAULT_FILE = "docs/data/ctid_db.json"

MAPPING_TYPES = ("exploitation_technique", "primary_impact", "secondary_impact")

_PATH_RE = re.compile(
    r"^mappings/kev/attack-(?P<ver>\d+(?:\.\d+)*)/kev-(?P<m>\d{2})\.(?P<d>\d{2})\.(?P<y>\d{4})"
    r"/enterprise/[^/]+\.json$"
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class CTIDFormatError(ValueError):
    """The tree or mapping file is not the shape CTID publishes."""


def count_ctid(data: Any) -> int:
    """ctid_db.json nests its records under ``cves``."""
    if isinstance(data, dict):
        cves = data.get("cves")
        if isinstance(cves, dict):
            return len(cves)
    return 0


def select_kev_file(tree: Any) -> Tuple[str, str, str]:
    """(path, attack_version, kev_date) of the newest enterprise KEV file.

    Newest ATT&CK version wins, then newest KEV date. Raises CTIDFormatError
    when the tree is truncated, malformed, or lists no such file.
    """
    if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
        raise CTIDFormatError("repository tree response has no 'tree' list")
    if tree.get("truncated"):
        raise CTIDFormatError("repository tree response is truncated")
    best: Optional[Tuple[Tuple[Tuple[int, ...], date], str, str, str]] = None
    for entry in tree["tree"]:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str):
            continue
        m = _PATH_RE.match(path)
        if not m:
            continue
        try:
            kev_day = date(int(m["y"]), int(m["m"]), int(m["d"]))
        except ValueError:
            continue
        version = tuple(int(p) for p in m["ver"].split("."))
        key = (version, kev_day)
        if best is None or key > best[0]:
            best = (key, path, m["ver"], f"{m['m']}.{m['d']}.{m['y']}")
    if best is None:
        raise CTIDFormatError("repository tree lists no enterprise KEV mapping file")
    return best[1], best[2], best[3]


def parse_mappings(raw: Any) -> Dict[str, Dict[str, Any]]:
    """Per-CVE technique mappings from one KEV mapping file.

    Returns {cve_id: {"group": str | None, "techniques": [{"id", "mapping_type":
    [..], "comment"}]}}. A technique mapped under several mapping types is one
    entry listing each type; its comment is the first non-empty one. Raises
    CTIDFormatError on a file that is not the published shape.
    """
    if not isinstance(raw, dict) or not isinstance(raw.get("mapping_objects"), list):
        raise CTIDFormatError("mapping file has no 'mapping_objects' list")
    out: Dict[str, Dict[str, Any]] = {}
    for i, obj in enumerate(raw["mapping_objects"]):
        if not isinstance(obj, dict):
            raise CTIDFormatError(f"mapping object {i} is not an object")
        cve = str(obj.get("capability_id") or "").strip().upper()
        tech = str(obj.get("attack_object_id") or "").strip().upper()
        mtype = obj.get("mapping_type")
        if not _CVE_RE.match(cve):
            # Non-CVE capabilities are out of scope; the KEV set has none today.
            continue
        if not _TECH_RE.match(tech):
            raise CTIDFormatError(f"mapping object {i} ({cve}) has technique {tech!r}")
        if mtype not in MAPPING_TYPES:
            # 'uncategorized' and unknown types carry no stated relation.
            continue
        comment = obj.get("comments")
        comment = comment.strip() if isinstance(comment, str) and comment.strip() else None
        rec = out.setdefault(cve, {"group": obj.get("capability_group") or None, "techniques": []})
        entry = next((t for t in rec["techniques"] if t["id"] == tech), None)
        if entry is None:
            entry = {"id": tech, "mapping_type": [], "comment": comment}
            rec["techniques"].append(entry)
        if mtype not in entry["mapping_type"]:
            entry["mapping_type"].append(mtype)
        if entry["comment"] is None:
            entry["comment"] = comment
    for rec in out.values():
        for t in rec["techniques"]:
            t["mapping_type"].sort(key=MAPPING_TYPES.index)
        # Exploitation technique first, then primary and secondary impact.
        rec["techniques"].sort(key=lambda t: (MAPPING_TYPES.index(t["mapping_type"][0]), t["id"]))
    return out


class CTIDProcessor:
    """Fetches the newest CTID KEV mapping file and writes ctid_db.json."""

    def __init__(self) -> None:
        self.logger = get_logger("ctid_processor")
        self.db_path = config.get("database.ctid.file", DEFAULT_FILE)
        self.tree_url = config.get("database.ctid.tree_url", DEFAULT_TREE_URL)
        self.raw_base = config.get("database.ctid.raw_base", DEFAULT_RAW_BASE)
        self.timeout = config.get("api.nvd.timeout", 60)

    def _headers(self, api: bool) -> Dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"} if api else {}
        # CI passes GITHUB_TOKEN so the tree call is not rate limited per IP.
        # The token goes in a header only, never in a URL.
        token = os.environ.get("GITHUB_TOKEN")
        if token and api:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _get_json(self, url: str, api: bool) -> Any:
        response = requests.get(url, headers=self._headers(api), timeout=self.timeout)
        response.raise_for_status()
        try:
            return response.json()
        except ValueError as e:
            raise CTIDFormatError(f"{url} did not return JSON: {e}") from e

    def fetch(self) -> Dict[str, Any]:
        """Discover, download and parse the newest file. Raises on any failure."""
        path, attack_version, kev_date = select_kev_file(self._get_json(self.tree_url, api=True))
        url = self.raw_base + path
        self.logger.info(f"Downloading CTID KEV mappings from {url}")
        cves = parse_mappings(self._get_json(url, api=False))
        if not cves:
            raise CTIDFormatError(f"{path} maps no CVE")
        self.logger.info(f"Parsed CTID mappings for {len(cves)} CVEs (ATT&CK {attack_version}, KEV {kev_date})")
        return {
            "meta": {
                "source": SOURCE,
                "repository": f"https://github.com/{REPO}",
                "license": "Apache-2.0",
                "path": path,
                "attack_version": attack_version,
                "kev_date": kev_date,
            },
            "cves": dict(sorted(cves.items())),
        }

    def update(self) -> Dict[str, Any]:
        """Fetch and write ctid_db.json (floor-checked, atomic). Raises on failure."""
        data = self.fetch()
        count = write_reference_db(
            self.db_path, data, count_ctid, indent=None, separators=(",", ":")
        )
        self.logger.info(f"Saved CTID mappings for {count} CVEs to {self.db_path}")
        return data


def load_ctid_db(path: str) -> Optional[Dict[str, Any]]:
    """The ``cves`` map of ctid_db.json, or None when missing or malformed."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    cves = data.get("cves") if isinstance(data, dict) else None
    return cves if isinstance(cves, dict) else None


def ctid_techniques(entry: Any) -> List[Dict[str, Any]]:
    """The technique list of one ctid_db.json CVE record, or []."""
    if isinstance(entry, dict) and isinstance(entry.get("techniques"), list):
        return [t for t in entry["techniques"] if isinstance(t, dict) and t.get("id")]
    return []
