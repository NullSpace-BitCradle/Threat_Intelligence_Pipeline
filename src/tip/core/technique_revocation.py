"""ATT&CK technique revocations: which retired technique IDs map to which live ones.

CAPEC still names ATT&CK techniques that ATT&CK has since revoked (for
example T1562.003, revoked by T1690). ``techniques_db.json`` holds live
techniques only, so a revoked ID carried through the CWE chain dangles: the
curated graph drops it while the shards and the MCP shard fallback serve it.

The techniques step writes ``technique_revocations.json`` from the same STIX
bundle: every revoked or deprecated technique ID, keyed without the ``T``
prefix like ``techniques_db.json``, mapped to the live technique that
replaces it, or to ``null`` when its ``revoked-by`` chain ends at nothing
live. The CVE chain and the entity index generator both pass CAPEC's
technique IDs through ``resolve_technique_ids``, so every surface carries
the same live IDs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from tip.utils.atomic_io import PathLike

RevocationMap = Dict[str, Optional[str]]


def _attack_id(obj: Mapping[str, Any]) -> str:
    """The ATT&CK external ID of a STIX object without its ``T`` prefix, or ''."""
    for ref in obj.get("external_references") or []:
        if isinstance(ref, Mapping) and ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if isinstance(ext, str) and ext:
                return ext[1:] if ext.startswith("T") else ext
    return ""


def build_revocation_map(bundle: Mapping[str, Any]) -> RevocationMap:
    """Map every revoked or deprecated technique to its live replacement.

    ``revoked-by`` relationships are followed transitively. A chain that
    ends at a revoked or deprecated technique, at an object outside the
    bundle, or in a cycle maps to None: the technique has no live
    replacement and is dropped from the chain. Deprecated techniques carry
    no ``revoked-by`` link, so they always map to None.
    """
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("STIX bundle has no objects list")

    stix_to_attack: Dict[str, str] = {}
    live: set[str] = set()
    retired: Dict[str, str] = {}  # stix id -> attack id
    revoked_by: Dict[str, str] = {}  # stix id -> stix id
    for obj in objects:
        if not isinstance(obj, Mapping):
            continue
        if obj.get("type") == "attack-pattern":
            stix_id = obj.get("id")
            attack_id = _attack_id(obj)
            if not isinstance(stix_id, str) or not attack_id:
                continue
            stix_to_attack[stix_id] = attack_id
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                retired[stix_id] = attack_id
            else:
                live.add(stix_id)
        elif obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            src, dst = obj.get("source_ref"), obj.get("target_ref")
            if isinstance(src, str) and isinstance(dst, str):
                revoked_by[src] = dst

    live_ids = {stix_to_attack[s] for s in live}
    revocations: RevocationMap = {}
    for stix_id, attack_id in retired.items():
        if attack_id in live_ids:
            # A live object still carries this ID; it is not retired.
            continue
        seen = {stix_id}
        target = revoked_by.get(stix_id)
        while target is not None and target not in live and target not in seen:
            seen.add(target)
            target = revoked_by.get(target)
        replacement = stix_to_attack.get(target) if target in live else None
        if attack_id in revocations and revocations[attack_id] is not None:
            # Two retired objects share an ID; keep the one that resolves.
            continue
        revocations[attack_id] = replacement
    return revocations


def load_revocation_map(path: PathLike) -> Optional[RevocationMap]:
    """Read technique_revocations.json, or None when it is missing or not a
    flat map of ID to ID-or-null."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if not all(isinstance(k, str) and (v is None or isinstance(v, str)) for k, v in data.items()):
        return None
    return data


def resolve_technique_ids(ids: Iterable[str], revocations: Optional[Mapping[str, Optional[str]]]) -> List[str]:
    """Replace revoked technique IDs with their live replacements.

    An ID with no live replacement is dropped; an ID the map does not name
    passes through unchanged. A ``T`` prefix on the input is kept on the
    output. Order is kept and duplicates removed, since two revoked IDs can
    share one replacement. With no map, the IDs pass through as given.
    """
    out: List[str] = []
    seen: set[str] = set()
    for raw in ids:
        tid = str(raw)
        if revocations is not None:
            prefixed = tid.startswith("T")
            key = tid[1:] if prefixed else tid
            if key in revocations:
                replacement = revocations[key]
                if replacement is None:
                    continue
                tid = f"T{replacement}" if prefixed else replacement
        if tid not in seen:
            seen.add(tid)
            out.append(tid)
    return out
