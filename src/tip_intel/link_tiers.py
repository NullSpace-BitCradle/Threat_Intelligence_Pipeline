"""Technique-link provenance shared by the generator and the MCP layer (I21).

A CVE's technique links come from MITRE CTID's KEV analysis (official), the
CWE chain (derived), an inherited parent CWE (derived, flagged inherited),
or inference from the CVSS vector (inferred). Shards keep the CTID and
inferred links in their own lists; these names say how to label them.
Pure stdlib.
"""

CTID_SOURCE = "MITRE CTID Mappings Explorer (KEV)"
CTID_TIER = "official"
INFERRED_TIER = "inferred"

# Shard fields holding the non-chain technique links (lists of dicts, each
# with id and source; CTID entries add mapping_type and comment, inferred
# entries add rule).
CTID_FIELD = "TECHNIQUES_CTID"
INFERRED_FIELD = "TECHNIQUES_INFERRED"

# Provenance tiers, strongest first. An unknown tier ranks below them all.
TIER_RANK = {"authoritative": 3, "official": 2, "derived": 1, "inferred": 0}
