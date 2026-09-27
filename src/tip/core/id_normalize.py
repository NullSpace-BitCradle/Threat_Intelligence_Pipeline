"""One definition of correlation ids and CWE parent expansion.

Shared by the CVE processor (ingestion) and the entity index generator
(linking), so neither can emit a bare ``74`` where an entity id
``CWE-74`` is expected.

Parent semantics (ISA Decisions 2026-09-26 11:40, amended by I29):
* A CVE keeps its NVD-assigned CWEs (``CWE``) apart from ONE level of
  ChildOf parents (``CWE_INHERITED``, ``split_cwe_list``). Pillar parents
  (``CWE_PILLARS``) are never inherited: they fan out into mappings nobody
  would defend.
* The CWE entity's CAPEC inheritance walks the FULL ChildOf chain
  (``cwe_capecs_with_ancestors``); the generator labels the CAPECs that are
  not the CWE's own RelatedAttackPatterns as inherited.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional

# The ten pillars of MITRE's CWE-1000 "Research Concepts" view, the most
# abstract weaknesses in the hierarchy. cwe_db.json carries no Abstraction
# field, so the set is named here rather than derived from data.
# Source: https://cwe.mitre.org/data/definitions/1000.html
CWE_PILLARS = frozenset({
    "CWE-284", "CWE-435", "CWE-664", "CWE-682", "CWE-691",
    "CWE-693", "CWE-697", "CWE-703", "CWE-707", "CWE-710",
})

_CWE_RE = re.compile(r"^(?:CWE-)?(\d+)$", re.IGNORECASE)
_CAPEC_RE = re.compile(r"^(?:CAPEC-)?(\d+)$", re.IGNORECASE)
_TECH_RE = re.compile(r"^T?(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def normalize_cwe_id(value: Any) -> Optional[str]:
    """``'74'``, ``'CWE-74'``, ``' cwe-74 '`` -> ``'CWE-74'``; anything else -> None.

    NVD placeholders such as ``NVD-CWE-Other`` and ``NVD-CWE-noinfo`` are not
    weaknesses and normalize to None.
    """
    m = _CWE_RE.match(str(value).strip())
    return f"CWE-{int(m.group(1))}" if m else None


def cwe_number(value: Any) -> Optional[str]:
    """``'CWE-74'`` or ``'74'`` -> ``'74'`` (the cwe_db.json key)."""
    norm = normalize_cwe_id(value)
    return norm[4:] if norm else None


def normalize_capec_id(value: Any) -> Optional[str]:
    """``'63'`` or ``'CAPEC-63'`` -> ``'CAPEC-63'``."""
    m = _CAPEC_RE.match(str(value).strip())
    return f"CAPEC-{int(m.group(1))}" if m else None


def normalize_technique_id(value: Any) -> Optional[str]:
    """``'1562.003'``, ``'t1562.003'``, ``'T1059'`` -> ``'T1562.003'`` / ``'T1059'``."""
    m = _TECH_RE.match(str(value).strip())
    return f"T{m.group(1)}" if m else None


def normalize_cwe_list(values: Iterable[Any]) -> list[str]:
    """Normalize, drop non-CWE placeholders, dedupe, sort."""
    out = {n for n in (normalize_cwe_id(v) for v in values) if n}
    return sorted(out, key=lambda c: int(c[4:]))


def cwe_parents(cwe_db: Mapping[str, Any], cwe: Any) -> list[str]:
    """One level of ChildOf parents for ``cwe``, as normalized ``CWE-<n>`` ids."""
    num = cwe_number(cwe)
    if num is None:
        return []
    entry = cwe_db.get(num) or {}
    return normalize_cwe_list(entry.get("ChildOf", []) or [])


def split_cwe_list(cwe_db: Mapping[str, Any], cwes: Iterable[Any]) -> tuple[list[str], list[str]]:
    """``(assigned, inherited)`` for a CVE's NVD CWE list.

    ``assigned`` is the NVD list normalized and sorted. ``inherited`` is one
    level of ChildOf parents that are neither assigned nor pillars.
    """
    assigned = normalize_cwe_list(cwes)
    inherited: set[str] = set()
    for cwe in assigned:
        inherited.update(cwe_parents(cwe_db, cwe))
    inherited -= set(assigned)
    inherited -= CWE_PILLARS
    return assigned, sorted(inherited, key=lambda c: int(c[4:]))


def cwe_capecs_with_ancestors(
    cwe_db: Mapping[str, Any],
    cwe: Any,
    _memo: Optional[dict[str, set[str]]] = None,
    _visiting: Optional[set[str]] = None,
) -> set[str]:
    """CAPEC numbers related to ``cwe`` or any ancestor on its full ChildOf chain."""
    memo = _memo if _memo is not None else {}
    visiting = _visiting if _visiting is not None else set()
    num = cwe_number(cwe)
    if num is None:
        return set()
    if num in memo:
        return memo[num]
    if num in visiting:
        return set()
    visiting.add(num)
    entry = cwe_db.get(num) or {}
    capecs = {str(c) for c in entry.get("RelatedAttackPatterns", []) or []}
    for parent in entry.get("ChildOf", []) or []:
        capecs |= cwe_capecs_with_ancestors(cwe_db, parent, memo, visiting)
    visiting.discard(num)
    memo[num] = capecs
    return capecs
