# TIP v1.5: Provenance Badges + Campaign History

**Date:** 2026-03-18
**Status:** Approved
**Builds on:** TIP v1.0 Unified Entity System

## Context

TIP v1.0 introduced a unified entity system with search, detail panel, and investigation state across 3,840 entities. v1.5 adds two features that deepen the intelligence value:

1. **Provenance badges** — show where each data point comes from and its trust level
2. **Campaign history** — temporal context for APT group activity via MITRE ATT&CK Campaigns

## Design Decisions

- **Provenance sourcing:** Hybrid — entity-level provenance is derived from entity type (cheap, deterministic), relationship-level provenance is embedded during index generation (accurate where trust varies)
- **Trust tiers:** Three-tier system — Official (green), Authoritative (blue), Derived (amber)
- **Campaign data source:** MITRE ATT&CK Campaigns dataset (STIX 2.1, all available campaigns with dates, group/technique mappings)
- **Campaign UI placement:** Both entity panel (compact timeline) and APT card (full detail cards)
- **Campaigns as entities:** First-class entities with type `campaign`, phase `operation`, searchable and navigable like any other entity
- **Provenance UI:** Dedicated "Provenance" section at bottom of entity panel (Option B from design review)

## Trust Tiers

| Tier | Label | Color | Badge Color | Sources |
|------|-------|-------|-------------|---------|
| 1 | OFFICIAL | Green | `#4ade80` | MITRE CWE, MITRE CAPEC, MITRE ATT&CK, MITRE D3FEND, MITRE ATT&CK Campaigns |
| 2 | AUTHORITATIVE | Blue | `#60a5fa` | CISA KEV, NVD (CVE→CWE mappings, vulnrichment) |
| 3 | DERIVED | Amber | `#fbbf24` | Pipeline cross-references (CVE→CAPEC→Technique chain, technique→APT overlap) |

## Data Layer

### Campaign Database

**New pipeline step:** `campaign_fetcher.py` fetches MITRE ATT&CK Campaigns from `mitre/cti` GitHub repo (`enterprise-attack/campaign/` directory). Parses STIX 2.1 campaign objects + relationship objects from `enterprise-attack/relationship/`. Uses `with_recovery` and `create_data_context` for error handling consistent with other pipeline components.

**Integration:** Called as a standalone step in `PipelineOrchestrator.run_full_pipeline()` between database updates (step 1) and entity index generation (step 4). Does not modify `DatabaseManager` — campaigns are a self-contained fetch-and-write step.

**Output:** `docs/data/campaigns_db.json`

```json
{
  "C0022": {
    "name": "Operation Dream Job",
    "aliases": ["Operation North Star", "Operation Interception"],
    "description": "Cyber espionage effort attributed to Lazarus Group...",
    "first_seen": "2019-09-01",
    "last_seen": "2020-08-01",
    "groups": ["G0032"],
    "techniques": ["T1566.001", "T1204.002", "T1059.001"],
    "references": [{"source": "ClearSky", "url": "..."}]
  }
}
```

### Entity Index Changes

**New rels shape** — relationships change from `{type: [ids]}` to `{type: {ids, source, tier}}`:

```json
{
  "CWE-787": {
    "type": "cwe", "id": "CWE-787", "name": "Out-of-bounds Write",
    "phase": "weakness",
    "prov": {"source": "MITRE CWE Database", "tier": "official"},
    "rels": {
      "cve": {"ids": ["CVE-2024-4231"], "source": "NVD Enrichment", "tier": "authoritative"},
      "capec": {"ids": ["CAPEC-120"], "source": "MITRE CWE Database", "tier": "official"}
    }
  }
}
```

**Migration & compatibility:** Bump `meta.version` from `"1.0"` to `"1.5"`. The JS must handle both shapes during transition — if `relIds` is an array, treat as v1.0 (no provenance); if it's an object with `ids`, treat as v1.5. This allows the app to work even if index and JS are temporarily out of sync:

```javascript
const ids = Array.isArray(relData) ? relData : (relData.ids || []);
const relSource = relData.source || null;
const relTier = relData.tier || null;
```

**KEV flag:** Move from `rels` to a top-level `kev` boolean on the entity. No longer stored inside `rels`. The provenance section renders it as a line: "KEV Status: CISA KEV Catalog (AUTHORITATIVE)" when `entity.kev === true`.

**Entity-level provenance** derived from type:

```python
ENTITY_PROVENANCE = {
    'cve':       {'source': 'NVD', 'tier': 'authoritative'},
    'cwe':       {'source': 'MITRE CWE Database', 'tier': 'official'},
    'capec':     {'source': 'MITRE CAPEC Database', 'tier': 'official'},
    'technique': {'source': 'MITRE ATT&CK', 'tier': 'official'},
    'defend':    {'source': 'MITRE D3FEND', 'tier': 'official'},
    'apt_group': {'source': 'MITRE ATT&CK Groups', 'tier': 'official'},
    'campaign':  {'source': 'MITRE ATT&CK Campaigns', 'tier': 'official'},
    'owasp':     {'source': 'Pipeline (NVD/CWE mapping)', 'tier': 'derived'},
}
```

**Relationship-level provenance** by relationship type:

| Relationship | Source | Tier |
|---|---|---|
| CVE → CWE | NVD Enrichment | authoritative |
| CVE → CAPEC | Pipeline (CWE→CAPEC chain) | derived |
| CVE → Technique | Pipeline (CAPEC→Technique chain) | derived |
| CVE → D3FEND | Pipeline (Technique→D3FEND chain) | derived |
| CVE → OWASP | Pipeline (CWE→OWASP mapping) | derived |
| CVE → APT Group | Pipeline (technique overlap) | derived |
| CWE → CAPEC | MITRE CWE Database | official |
| CAPEC → Technique | MITRE CAPEC Database | official |
| Technique → D3FEND | MITRE D3FEND | official |
| APT Group → Technique | MITRE ATT&CK | official |
| Campaign → Group | MITRE ATT&CK Campaigns | official |
| Campaign → Technique | MITRE ATT&CK Campaigns | official |
| KEV flag | CISA KEV Catalog | authoritative |

### Campaign Entity Type

- **Type:** `campaign`
- **Kill-chain phase:** `operation` (new, between `defense` and `threat_actor`)
- **TYPE_CONFIG color:** `#e056a0`
- **Search terms:** campaign ID, name tokens, aliases, associated group names (e.g., searching "Lazarus" surfaces both G0032 and its campaigns)
- **External link:** `https://attack.mitre.org/campaigns/{id}/` — add `campaign` case to `buildExternalLink`: `else if (type === 'campaign') { url = 'https://attack.mitre.org/campaigns/' + entityId + '/'; text = 'View on MITRE ATT&CK'; }`
- **Extra fields:** `first_seen`, `last_seen` (ISO date strings)
- **Bidirectional rels:** Campaign ↔ APT Group, Campaign ↔ Technique (use `link()` not `link_one()` in generator for bidirectionality)

**Updated kill-chain phases:** `vulnerability → weakness → attack_pattern → attack → defense → operation → threat_actor → compliance` (operations grouped with their actors)

## Frontend

### Provenance Section (Entity Panel)

Added to `entity-system.js`, between relationships and actions:

- Entity source line: colored dot + source name + tier badge
- One line per relationship type showing source and tier
- Tier badge styles: green pill (OFFICIAL), blue pill (AUTHORITATIVE), amber pill (DERIVED)
- Only renders when `prov` field exists (backward compatible)

### Campaign Timeline (Entity Panel)

When viewing an APT group with campaign relationships:

- Vertical timeline with colored dots and connector line
- Each entry: campaign name (clickable → opens campaign entity), date range, up to 3 technique tags with "+N more"
- Sorted by `first_seen` descending (most recent first)
- Appears between relationship sections and provenance section

**Data source for timeline:** Campaign entities in entity_index.json already contain `first_seen`, `last_seen`, and technique relationships. The APT group entity has campaign IDs in its `rels.campaign.ids` array. The timeline is rendered by looking up each campaign entity from the already-loaded `entityIndex.entities` — no additional fetch needed. The entity panel does NOT need `campaigns_db.json`; that file is only used by `tip-views.js` for the full campaign descriptions in APT cards.

When viewing a campaign entity directly:

- Campaign name, date range
- Linked APT groups (clickable)
- Techniques used (clickable)
- Provenance section

### Campaign Section in APT Cards

In `tip-views.js`, APT card expanded view gets a "Campaigns" section after techniques:

- Full campaign cards with colored left border
- Each card: name (clickable → entity detail), date range, description (truncated), technique tags
- Only renders if group has campaigns
- Campaign data loaded from `campaigns_db.json` alongside existing `groups_db.json`
- Remove existing placeholder text ("Recent confirmed attack campaigns not yet available in dataset.") from APT cards when campaigns data is present; show it only as fallback when no campaigns exist for a group

### entity-system.js Updates

- New `campaign` type in TYPE_CONFIG
- Handle new rels shape: `{type: {ids, source, tier}}` instead of `{type: [ids]}`
- Render provenance section in entity detail panel
- Render campaign timeline for APT group entities
- External link builder for campaign type

## Files to Create/Modify

| File | Action | What |
|------|--------|------|
| `src/tip/core/campaign_fetcher.py` | **CREATE** | Fetch ATT&CK campaigns STIX data → campaigns_db.json |
| `src/tip/core/entity_index_generator.py` | MODIFY | Campaign entities, provenance fields, new rels shape |
| `docs/js/entity-system.js` | MODIFY | Provenance section, campaign timeline, new rels shape, campaign type |
| `docs/js/tip-views.js` | MODIFY | Campaign section in APT cards |
| `docs/css/theme.css` | MODIFY | Provenance badges, campaign timeline, campaign card styles |
| `src/tip/core/pipeline_orchestrator.py` | MODIFY | Add campaign fetch as step between DB updates and entity index generation |

## Build Sequence

| Step | Task | Depends On | Parallel? |
|------|------|-----------|-----------|
| 1 | Campaign fetcher (Python) | — | [P] |
| 2 | Entity index generator: campaigns + provenance + new rels shape | 1 | [S] |
| 3 | Run generator → produce updated index files | 2 | [S] |
| 4 | entity-system.js: new rels shape + provenance section + campaign timeline | 3 | [S] |
| 5 | tip-views.js: campaign section in APT cards | 3 | [P with 4] |
| 6 | CSS: provenance badges, timeline, campaign cards | — | [P] |
| 7 | Verify all views still work + new features | All | [S] |

## Verification

- Search "Dream Job" → C0022 result appears
- Click C0022 → campaign entity panel with groups, techniques, date range
- View APT38 entity → campaign timeline shows with clickable entries
- View APT38 card → campaigns section with full detail cards
- All entities show provenance section with correct tier badges
- CWE entity → OFFICIAL badge, CVE relationships show AUTHORITATIVE
- Derived relationships (CVE→CAPEC) show DERIVED badge
- Existing v1.0 features still work (search, entity linking, investigation)
- Theme toggle works on all new elements
- Search non-existent campaign → no results (graceful)
- Entity loaded from v1.0 index (no `prov` field) → provenance section hidden, no errors
- APT card "campaigns not available" placeholder removed when campaigns data exists
- Search "Lazarus" → surfaces both G0032 and its campaigns

## Out of Scope

- Temporal weighting on relationships (v2.0)
- Asset watchlist / alerting (v2.0)
- Backend or authentication (v2.0+)
