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

The rules follow CTID's ATT&CK to CVE methodology, "Using MITRE ATT&CK to
Describe Vulnerabilities" (center-for-threat-informed-defense/attack_to_cve,
methodology.md, read 2026-09-27). Its "Exploitation Techniques" section maps
"the attacker exploits remote system application" to T1190, and its
"Tactic-level Techniques" section names the generic exploitation technique
per tactic: T1190 for Initial Access, T1203 for Execution, T1068 for
Privilege Escalation. Its "Mapping & Methodology Scope" section and
"Vulnerability Type" table give no exploitation technique for
memory-modification bugs (buffer overflows and the like) because it varies
by bug, so the rules never read the CWE. They read how the vulnerability is
reached, which is what the Exploit Technique method keys on, and the CVSS
vector is the only structured statement of that. One line per technique:

* AV:N and UI:N -> T1190 Exploit Public-Facing Application (reached over the
  network with no user action; "Exploitation Techniques": the attacker
  exploits a remote system application).
* UI:R (v3) or UI:P / UI:A (v4), attack vector not physical -> T1204 User
  Execution ("Exploitation Techniques" routes user action to T1204.002,
  T1204.001 and T1189; T1203 is only the tactic-level fallback). The CVSS
  vector cannot tell a file from a link, so the rule names the parent.
* AV:L, UI:N, and high confidentiality and integrity impact (v3 C:H and I:H,
  v4 VC:H and VI:H) -> T1068 Exploitation for Privilege Escalation. This is
  privilege escalation, which CTID analysts usually record as the impact
  rather than the exploitation technique.

Measured agreement with CTID analysts (2026-09-27, kev-07.28.2025 on ATT&CK
16.1): of the 419 CTID KEV CVEs, the CWE chain (I29 approximation) reaches
no technique for 161; a rule fires on 155 of those (6 have no covered
vector). Per rule, the rule's technique against the analyst's mapping:

  rule                    fired  exploitation technique   any mapping type
  T1190 (AV:N, UI:N)         76  40 (53%)                 42 (55%)
  T1204 (user interaction)   49  1 exact, 24 (49%) as a   1 exact, 25 (51%)
                                 T1204 sub-technique
  T1068 (local, full C/I)    30  13 (43%)                 26 (87%)

The analysts' other exploitation picks were T1078 Valid Accounts (T1190
and T1068 rules), T1203 and T1189 (T1204 rule). An inferred link is a
starting point, not a mapping.

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
from tip_intel.link_tiers import INFERRED_FAMILY, INFERRED_TIER


# rule id -> (technique id, technique name, one-line condition, measured
# agreement with MITRE CTID analysts). Agreement: the 155 CTID KEV CVEs the
# CWE chain cannot reach and a rule fires on (161 unreached, 6 with no rule),
# measured 2026-09-27 against kev-07.28.2025_attack-16.1 (see module doc).
RULES: Dict[str, tuple[str, str, str, str]] = {
    "network-no-interaction": (
        "T1190", "Exploit Public-Facing Application", "AV:N and UI:N",
        "matches the CTID analyst's exploitation technique on 40 of 76 KEV CVEs (53%)",
    ),
    "user-interaction": (
        "T1204", "User Execution", "user interaction required, not physical",
        "CTID analysts chose a T1204 sub-technique as the exploitation technique on 24 of 49 "
        "KEV CVEs (49%), T1204 itself on 1",
    ),
    "local-full-impact": (
        "T1068", "Exploitation for Privilege Escalation", "AV:L, UI:N, high C and I impact",
        "privilege escalation, usually recorded by CTID analysts as the impact: their "
        "exploitation technique on 13 of 30 KEV CVEs (43%), any mapping type on 26 of 30 (87%)",
    ),
}

_V3_RE = re.compile(r"^CVSS:3\.[01]/")
_V4_RE = re.compile(r"^CVSS:4\.0/")


def rule_source(rule: str) -> str:
    """The source string an inferred link carries, naming its rule."""
    tech, name, cond, agreement = RULES[rule]
    return f"{INFERRED_FAMILY} ({cond}: {tech} {name}; {agreement})"


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
