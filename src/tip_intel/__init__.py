"""Shared CVE intelligence contract for TIP.

One source of truth for the rich CVE intelligence blocks (full KEV detail,
SSVC decision, CISA CVSS override, CVSS provenance, D3FEND semantics) that are
captured in the per-year shards. Both the entity-index generator (producer) and
the MCP layer (consumer) derive their CVE intelligence projection from this
module, so a new field is added in exactly one place and a cross-seam test can
assert it reaches both surfaces. Pure stdlib; importable by both `tip` and
`tip_mcp` under PYTHONPATH=src.
"""
