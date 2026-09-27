"""Technique links beyond the CWE chain: CTID official and CVSS inferred (I21).

A CVE's ATT&CK techniques come from four places, strongest first:

1. MITRE CTID Mappings Explorer (KEV): an analyst mapped the technique to the
   CVE (tier official). See tip.core.ctid_processor.
2. The CWE -> CAPEC -> technique chain from NVD-assigned CWEs (derived).
3. The same chain through an inherited parent CWE (derived, flagged
   inherited; ISA I29).
4. Inference from the CVSS vector, defined here (tier inferred).

Inference fills only an empty slot: a CVE that has any technique from 1, 2
or 3 gets no inferred technique. It names the likely exploitation technique
only; it never infers an impact technique.

The rules follow CTID's "Mapping ATT&CK to CVE for Impact" methodology
(github.com/center-for-threat-informed-defense/attack_to_cve,
methodology.md). Its "Exploitation Techniques" section maps "the attacker
exploits remote system application" to T1190, and its "Tactic-level
Techniques" section names the generic exploitation technique per tactic:
T1190 for Initial Access, T1203 for Execution, T1068 for Privilege
Escalation. The CVSS vector is the only structured statement of how a
vulnerability is reached, so each rule reads it, one line per technique:

* AV:N and UI:N -> T1190 Exploit Public-Facing Application (reached over the
  network with no user action).
* UI:R (v3) or UI:P / UI:A (v4), attack vector not physical -> T1203
  Exploitation for Client Execution (a user must open or visit something).
* AV:L, UI:N, and high confidentiality and integrity impact (v3 C:H and I:H,
  v4 VC:H and VI:H) -> T1068 Exploitation for Privilege Escalation (a local
  foothold turned into full control).

Anything else gets no inferred technique: CVSS v2 vectors (no user
interaction metric), physical access, adjacent network without user
interaction, local vectors without full impact, and vectors that do not
parse.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

from tip.core.ctid_processor import SOURCE as CTID_SOURCE, ctid_techniques
from tip.core.id_normalize import normalize_technique_id

INFERRED_TIER = "inferred"

# rule id -> (technique id, technique name, one-line condition)
RULES: Dict[str, tuple[str, str, str]] = {
    "network-no-interaction": ("T1190", "Exploit Public-Facing Application", "AV:N and UI:N"),
    "user-interaction": ("T1203", "Exploitation for Client Execution", "user interaction required, not physical"),
    "local-full-impact": ("T1068", "Exploitation for Privilege Escalation", "AV:L, UI:N, high C and I impact"),
}

_V3_RE = re.compile(r"^CVSS:3\.[01]/")
_V4_RE = re.compile(r"^CVSS:4\.0/")


def rule_source(rule: str) -> str:
    """The source string an inferred link carries, naming its rule."""
    tech, name, cond = RULES[rule]
    return f"TIP inference from the CVSS vector ({cond}: {tech} {name})"


def _metrics(vector: str) -> Optional[Dict[str, str]]:
    parts = vector.strip().split("/")
    out: Dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or not key or not value:
            return None
        out[key] = value
    return out


def infer_rule(vector: Any) -> Optional[str]:
    """The rule id that applies to a CVSS vector string, or None."""
    if not isinstance(vector, str):
        return None
    if _V3_RE.match(vector):
        m = _metrics(vector)
        interaction = {"N": False, "R": True}
        conf, integ = ("C", "I")
    elif _V4_RE.match(vector):
        m = _metrics(vector)
        interaction = {"N": False, "P": True, "A": True}
        conf, integ = ("VC", "VI")
    else:
        return None
    if m is None:
        return None
    av, ui = m.get("AV"), m.get("UI")
    if av not in ("N", "A", "L", "P") or ui not in interaction:
        return None
    if av == "N" and not interaction[ui]:
        return "network-no-interaction"
    if interaction[ui] and av != "P":
        return "user-interaction"
    if av == "L" and not interaction[ui] and m.get(conf) == "H" and m.get(integ) == "H":
        return "local-full-impact"
    return None


def ctid_links(entry: Any) -> List[Dict[str, Any]]:
    """Shard TECHNIQUES_CTID entries from one ctid_db.json CVE record."""
    out = []
    for t in ctid_techniques(entry):
        tid = normalize_technique_id(str(t["id"]))
        if not tid:
            continue
        link: Dict[str, Any] = {
            "id": tid,
            "mapping_type": list(t.get("mapping_type") or []),
            "source": CTID_SOURCE,
        }
        if t.get("comment"):
            link["comment"] = t["comment"]
        out.append(link)
    return out


def inferred_links(sourced: Iterable[Any], vector: Any) -> List[Dict[str, Any]]:
    """Shard TECHNIQUES_INFERRED entries: one inferred technique when no
    technique came from CTID, the chain, or an inherited parent, else []."""
    if any(normalize_technique_id(str(t)) for t in sourced):
        return []
    rule = infer_rule(vector)
    if rule is None:
        return []
    return [{"id": RULES[rule][0], "rule": rule, "source": rule_source(rule)}]


def extra_technique_links(
    chain_direct: Iterable[Any],
    chain_inherited: Iterable[Any],
    ctid_entry: Any,
    cvss_vector: Any,
) -> Dict[str, List[Dict[str, Any]]]:
    """TECHNIQUES_CTID and TECHNIQUES_INFERRED for one CVE. Pure, so the
    processor, the entity index generator and the probes share it."""
    ctid = ctid_links(ctid_entry)
    sourced = list(chain_direct) + list(chain_inherited) + [t["id"] for t in ctid]
    return {
        "TECHNIQUES_CTID": ctid,
        "TECHNIQUES_INFERRED": inferred_links(sourced, cvss_vector),
    }
