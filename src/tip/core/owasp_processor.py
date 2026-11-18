"""
OWASP Top 10 2021 categories for CWEs.

The mapping is MITRE's CWE-1344 view, "Weaknesses in OWASP Top Ten (2021)".
Each category is a CWE grouping named "OWASP Top Ten 2021 Category A0x:2021
- <name>" whose members carry ``View_ID="1344"``. The database step derives
it from the CWE XML on every run (``owasp_mapping_from_cwe_xml``) and
publishes it as ``docs/data/owasp_db.json``; the CVE processor reads that
file through ``OWASPProcessor``. There is no hand-written fallback table: a
CWE catalog without all ten categories fails the step and keeps the
published file.
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from tip.utils.atomic_io import PathLike
from tip.utils.config import get_config

logger = logging.getLogger(__name__)

OWASP_2021_VIEW_ID = "1344"
OWASP_2021_CATEGORY_IDS = tuple(f"A{n:02d}:2021" for n in range(1, 11))
# CWE 5.0 files the categories as <Grouping>; CWE 4.x filed them as
# <Category>. Both carry this name pattern.
_CATEGORY_NAME = re.compile(r"^OWASP Top Ten 2021 Category (A(?:0[1-9]|10)):2021 - (.+)$")


def _namespace(root: ET.Element) -> str:
    """The ``{uri}`` prefix of the root tag, or '' (MITRE bumps it per schema major)."""
    return root.tag[:root.tag.index('}') + 1] if root.tag.startswith('{') else ''


def _cwe_sort_key(cwe_id: str) -> tuple[int, str]:
    return (int(cwe_id), "") if cwe_id.isdigit() else (1 << 30, cwe_id)


def owasp_mapping_from_cwe_xml(root: ET.Element) -> Dict[str, Any]:
    """Build owasp_db.json from a parsed CWE catalog.

    Returns ``{"source", "categories", "cwe_mapping"}`` where each category
    holds its name, the grouping's summary, the grouping's CWE id, and its
    member CWE numbers, and ``cwe_mapping`` maps a CWE number to the
    categories that list it. Raises ValueError unless all ten 2021
    categories are present with at least one member each.
    """
    ns = _namespace(root)
    categories: Dict[str, Dict[str, Any]] = {}
    for tag in ("Grouping", "Category"):
        for element in root.iter(f"{ns}{tag}"):
            match = _CATEGORY_NAME.match(element.get("Name", ""))
            if not match:
                continue
            category_id = f"{match.group(1)}:2021"
            members = {
                member.get("CWE_ID", "")
                for member in element.iter(f"{ns}Has_Member")
                if member.get("View_ID") == OWASP_2021_VIEW_ID and member.get("CWE_ID")
            }
            summary = element.find(f"{ns}Summary")
            categories[category_id] = {
                "name": match.group(2).strip(),
                "description": (summary.text or "").strip() if summary is not None else "",
                "cwe_grouping": f"CWE-{element.get('ID', '')}",
                "cwe_ids": sorted(members, key=_cwe_sort_key),
            }

    missing = [c for c in OWASP_2021_CATEGORY_IDS if not categories.get(c, {}).get("cwe_ids")]
    if missing:
        raise ValueError(
            f"CWE catalog lacks the CWE-{OWASP_2021_VIEW_ID} OWASP Top Ten 2021 "
            f"categories {missing}"
        )

    cwe_mapping: Dict[str, List[str]] = {}
    for category_id in OWASP_2021_CATEGORY_IDS:
        for cwe_id in categories[category_id]["cwe_ids"]:
            cwe_mapping.setdefault(cwe_id, []).append(category_id)
    return {
        "source": f"MITRE CWE-{OWASP_2021_VIEW_ID} view, CWE catalog {root.get('Version', 'unknown')}",
        "categories": {c: categories[c] for c in OWASP_2021_CATEGORY_IDS},
        "cwe_mapping": {k: cwe_mapping[k] for k in sorted(cwe_mapping, key=_cwe_sort_key)},
    }


class OWASPProcessor:
    """Looks up the OWASP Top 10 2021 categories of CWEs from owasp_db.json."""

    def __init__(self, db_path: Optional[PathLike] = None):
        self.owasp_db_path = Path(db_path or get_config().get_database_path('owasp'))
        self.cwe_owasp_mapping: Dict[str, List[str]] = {}
        self.owasp_categories: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self) -> bool:
        """Read owasp_db.json. On any failure the mapping already loaded is
        kept and False is returned; the caller decides whether that is fatal."""
        try:
            with open(self.owasp_db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            categories = data.get('categories') if isinstance(data, dict) else None
            mapping = data.get('cwe_mapping') if isinstance(data, dict) else None
            if not isinstance(categories, dict) or not isinstance(mapping, dict) or not mapping:
                raise ValueError("no categories or cwe_mapping")
        except (OSError, ValueError) as e:
            logger.error(f"Could not load OWASP mapping from {self.owasp_db_path}: {e}")
            return False
        self.owasp_categories = categories
        self.cwe_owasp_mapping = {str(k): [str(c) for c in v] for k, v in mapping.items() if isinstance(v, list)}
        logger.info(f"Loaded OWASP mapping: {len(self.owasp_categories)} categories, "
                    f"{len(self.cwe_owasp_mapping)} CWEs")
        return True

    def get_owasp_categories_for_cwe(self, cwe_id: str) -> List[str]:
        """OWASP categories for one CWE (``'79'`` or ``'CWE-79'``)."""
        cwe_id = cwe_id[4:] if cwe_id.startswith("CWE-") else cwe_id
        return self.cwe_owasp_mapping.get(cwe_id, [])

    def get_owasp_categories_for_cwes(self, cwe_ids: List[str]) -> Set[str]:
        """Every OWASP category any of the CWEs maps to."""
        all_categories: Set[str] = set()
        for cwe_id in cwe_ids:
            all_categories.update(self.get_owasp_categories_for_cwe(cwe_id))
        return all_categories
