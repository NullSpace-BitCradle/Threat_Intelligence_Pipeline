/**
 * TIP Entity System — Pure Data Layer
 * Provides TYPE_CONFIG, index loading, search, and entity lookup.
 * No DOM rendering. Called by app.js, results.js, and graph.js.
 */

let entityIndex = null;
let searchIndex = null;
let indicesLoading = false;

const TYPE_CONFIG = {
    cve:       { color: '#ff6b6b', label: 'CVE',       relLabel: 'Vulnerabilities' },
    cwe:       { color: '#4ecdc4', label: 'CWE',       relLabel: 'Weaknesses' },
    capec:     { color: '#45b7d1', label: 'CAPEC',     relLabel: 'Attack Patterns' },
    technique: { color: '#96ceb4', label: 'Technique', relLabel: 'Techniques' },
    defend:    { color: '#feca57', label: 'D3FEND',    relLabel: 'Defenses' },
    apt_group: { color: '#a5d6ff', label: 'APT',       relLabel: 'Threat Actors' },
    owasp:     { color: '#ff9ff3', label: 'OWASP',     relLabel: 'OWASP Categories' },
    campaign:  { color: '#e056a0', label: 'Campaign', relLabel: 'Campaigns' }
};

// ── Data Loading ────────────────────────────────────────────────

async function loadIndices() {
    if (entityIndex) return;
    if (indicesLoading) return;
    indicesLoading = true;
    try {
        const [eiRes, siRes] = await Promise.all([
            fetch('data/entity_index.json'),
            fetch('data/search_index.json')
        ]);
        entityIndex = await eiRes.json();
        searchIndex = await siRes.json();
    } catch (e) {
        console.error('Failed to load entity indices:', e);
        entityIndex = null;
        searchIndex = null;
    } finally {
        indicesLoading = false;
    }
}

// ── Search ──────────────────────────────────────────────────────

function searchEntities(query) {
    if (!entityIndex || !searchIndex) return {};
    const q = query.toLowerCase().trim();
    if (!q) return {};

    const matchedIds = new Set();
    for (const key of Object.keys(searchIndex)) {
        if (key.startsWith(q)) {
            const ids = searchIndex[key];
            (Array.isArray(ids) ? ids : [ids]).forEach(id => matchedIds.add(id));
        }
    }

    const grouped = {};
    for (const id of matchedIds) {
        const entity = entityIndex.entities[id];
        if (!entity) continue;
        const type = entity.type || 'unknown';
        if (!grouped[type]) grouped[type] = [];
        grouped[type].push({ id, ...entity, exact: id.toLowerCase() === q });
    }

    for (const type of Object.keys(grouped)) {
        grouped[type].sort((a, b) => (b.exact ? 1 : 0) - (a.exact ? 1 : 0));
        grouped[type] = grouped[type].slice(0, 5);
    }
    return grouped;
}

// ── Entity Helpers ──────────────────────────────────────────────

function getEntity(entityId) {
    if (!entityIndex || !entityIndex.entities[entityId]) return null;
    return { id: entityId, ...entityIndex.entities[entityId] };
}

function getRelatedEntities(entityId) {
    const entity = getEntity(entityId);
    if (!entity || !entity.rels) return {};
    const related = {};
    for (const [relType, relData] of Object.entries(entity.rels)) {
        related[relType] = {
            ids: relData.ids || [],
            source: relData.source || '',
            tier: relData.tier || 'derived',
            entities: (relData.ids || []).map(id => getEntity(id)).filter(Boolean)
        };
    }
    return related;
}

function getEntityCount() {
    if (!entityIndex || !entityIndex.entities) return 0;
    return Object.keys(entityIndex.entities).length;
}

function getEntitiesByType(type) {
    if (!entityIndex || !entityIndex.entities) return [];
    return Object.entries(entityIndex.entities)
        .filter(([, e]) => e.type === type)
        .map(([id, e]) => ({ id, ...e }));
}

// Return the canonical external URL for an entity on its source site,
// or null if the type has no well-known external home page.
function buildExternalLink(entity) {
    if (!entity || !entity.id || !entity.type) return null;
    const id = entity.id;
    switch (entity.type) {
        case 'cve':
            return 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(id);
        case 'cwe':
            return 'https://cwe.mitre.org/data/definitions/' +
                encodeURIComponent(id.replace(/^CWE-/, '')) + '.html';
        case 'capec':
            return 'https://capec.mitre.org/data/definitions/' +
                encodeURIComponent(id.replace(/^CAPEC-/, '')) + '.html';
        case 'technique': {
            // T1059 -> T1059; T1059.001 -> T1059/001 on ATT&CK
            const parts = id.replace(/^T/, '').split('.');
            const tail = parts.length > 1 ? parts[0] + '/' + parts[1] : parts[0];
            return 'https://attack.mitre.org/techniques/T' + tail + '/';
        }
        case 'apt_group':
            return 'https://attack.mitre.org/groups/' + encodeURIComponent(id) + '/';
        case 'campaign':
            return 'https://attack.mitre.org/campaigns/' + encodeURIComponent(id) + '/';
        case 'defend':
            return 'https://d3fend.mitre.org/technique/d3f:' + encodeURIComponent(id) + '/';
        case 'owasp':
            // OWASP IDs like A03:2021; canonical URL is the top 10 landing page
            return 'https://owasp.org/Top10/';
        default:
            return null;
    }
}

// ── Detail Fetching (lazy-loaded from raw DB files) ────────────

const detailCache = {};

async function fetchEntityDetail(entityId) {
    if (detailCache[entityId]) return detailCache[entityId];

    const entity = getEntity(entityId);
    if (!entity) return null;

    var detail = {};

    try {
        if (entity.type === 'cwe') {
            var num = entityId.replace('CWE-', '');
            var cweDb = await fetchJson('data/cwe_db.json');
            var cweEntry = cweDb[num];
            if (cweEntry) {
                detail.description = cweEntry.description || '';
                detail.parents = (cweEntry.ChildOf || []).map(function(id) { return 'CWE-' + id; });
            }
        } else if (entity.type === 'technique') {
            var techId = entityId.replace('T', '');
            var techDb = await fetchJson('data/techniques_db.json');
            var techEntry = techDb[techId];
            if (techEntry) {
                detail.description = techEntry.description || '';
                detail.framework = techEntry.framework || '';
            }
        } else if (entity.type === 'apt_group') {
            var groupsDb = await fetchJson('data/groups_db.json');
            var groupEntry = (groupsDb.groups || groupsDb)[entityId];
            if (groupEntry) {
                detail.description = groupEntry.description || '';
                detail.aliases = groupEntry.aliases || [];
            }
        } else if (entity.type === 'cve') {
            var kevDb = await fetchJson('data/kev_db.json');
            var kevEntry = kevDb[entityId];
            if (kevEntry) {
                detail.kev = kevEntry;
            }
        } else if (entity.type === 'campaign') {
            detail.first_seen = entity.first_seen || '';
            detail.last_seen = entity.last_seen || '';
        } else if (entity.type === 'capec') {
            var capecNum = entityId.replace('CAPEC-', '');
            var capecDb = await fetchJson('data/capec_db.json');
            var capecEntry = capecDb[capecNum];
            if (capecEntry) {
                detail.fullName = capecEntry.name || '';
            }
        }
    } catch (e) {
        console.log('Could not fetch detail for ' + entityId + ':', e.message);
    }

    detailCache[entityId] = detail;
    return detail;
}

const jsonCache = {};
async function fetchJson(url) {
    if (jsonCache[url]) return jsonCache[url];
    var res = await fetch(url);
    if (!res.ok) throw new Error('Fetch failed: ' + url);
    var data = await res.json();
    jsonCache[url] = data;
    return data;
}
