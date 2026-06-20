"""Canonical extractors for the rich CVE intelligence blocks.

Every block here is derived from a *shard payload* — the per-CVE dict that the
pipeline writes to ``docs/database/CVE-YYYY.jsonl.gz``. The generator's
``cve_data`` and the MCP loader's shard ``payload`` are the same shape, so one
set of extractors serves both producer and consumer. This is the contract that
replaces the three previously hand-maintained allowlists.

To add a new intelligence field: add its extractor here, list it in
``INTEL_FIELDS``, and the cross-seam parity test will require it to reach both
the generated entity record and the MCP record.
"""

from __future__ import annotations

from typing import Optional

# The canonical set of intelligence blocks attached to a CVE entity record.
# The cross-seam parity test asserts every name here round-trips producer ->
# consumer. Relationship-decoration (D3FEND semantics) is applied in place on
# existing rels and so is tracked separately by the test, not listed here.
INTEL_FIELDS = ("kev_detail", "ssvc", "cisa_cvss", "cvss_version", "cvss_source")


def kev_detail(payload: dict) -> Optional[dict]:
    """Rich CISA KEV detail block, or None when the CVE is not in KEV."""
    kev = payload.get("KEV")
    if not isinstance(kev, dict) or not kev.get("inKEV"):
        return None
    out: dict = {}
    for key in (
        "dateAdded",
        "dueDate",
        "knownRansomwareCampaignUse",
        "requiredAction",
        "vendorProject",
        "product",
    ):
        if kev.get(key) is not None:
            out[key] = kev[key]
    return out or None


def ssvc_block(payload: dict) -> Optional[dict]:
    """CISA SSVC decision block, or None. VULNRICHMENT is frequently null."""
    vuln = payload.get("VULNRICHMENT")
    if not isinstance(vuln, dict):
        return None
    out: dict = {}
    for key in ("ssvcExploitStatus", "ssvcAutomatable", "ssvcTechnicalImpact"):
        if vuln.get(key) is not None:
            out[key] = vuln[key]
    return out or None


def cisa_cvss(payload: dict) -> Optional[dict]:
    """CISA CVSS override block from VULNRICHMENT, or None."""
    vuln = payload.get("VULNRICHMENT")
    if not isinstance(vuln, dict):
        return None
    cisa = vuln.get("cisaCVSS")
    if isinstance(cisa, dict) and cisa:
        return cisa
    return None


def cvss_meta(payload: dict) -> dict:
    """CVSS provenance: {cvss_version?, cvss_source?} present-only."""
    out: dict = {}
    cvss = payload.get("CVSS")
    if isinstance(cvss, dict):
        if cvss.get("version"):
            out["cvss_version"] = cvss["version"]
        if cvss.get("source"):
            out["cvss_source"] = cvss["source"]
    return out


def defend_semantics(payload: dict) -> dict:
    """Map each D3FEND id to its {relationship, name} from DEFEND objects.

    Used to decorate D3FEND relationships that arrive as bare IDs with the
    defensive intent (isolates / monitors / hardens / ...). Matched by id so it
    works regardless of the rel_type label (``defend`` vs ``d3fend``).
    """
    out: dict = {}
    for defend in payload.get("DEFEND", []) or []:
        if not isinstance(defend, dict) or not defend.get("id"):
            continue
        sem = {k: defend[k] for k in ("relationship", "name") if defend.get(k) is not None}
        if sem:
            out[str(defend["id"])] = sem
    return out


def enrich(record: dict, payload: dict) -> None:
    """Attach every intelligence block to a CVE record in place (idempotent).

    Adds the INTEL_FIELDS blocks when present and decorates any D3FEND
    relationship (matched by target_id) with its relationship verb + name.
    Never overwrites a value already on the record (setdefault semantics), so
    it is safe to call on a partially-populated record.
    """
    kev = kev_detail(payload)
    if kev and "kev_detail" not in record:
        record["kev_detail"] = kev
    ssvc = ssvc_block(payload)
    if ssvc and "ssvc" not in record:
        record["ssvc"] = ssvc
    cisa = cisa_cvss(payload)
    if cisa and "cisa_cvss" not in record:
        record["cisa_cvss"] = cisa
    for key, value in cvss_meta(payload).items():
        record.setdefault(key, value)
    # D3FEND semantics decorate the MCP record's flat rels list. The generator's
    # entity rels are a dict (and absent at emission time), so guard for the
    # list shape — the scalar blocks above attach to both callers regardless.
    sem = defend_semantics(payload)
    rels = record.get("rels")
    if sem and isinstance(rels, list):
        for rel in rels:
            tid = rel.get("target_id")
            if tid in sem:
                for key, value in sem[tid].items():
                    rel.setdefault(key, value)
