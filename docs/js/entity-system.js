/**
 * TIP Entity System — Pure Data Layer
 * Provides TYPE_CONFIG, index loading, search, and entity lookup.
 * No DOM rendering. Called by app.js, results.js, and graph.js.
 */

let entityIndex = null;
let searchIndex = null;
let indicesLoading = false;
// Set to a short reason string when the entity/search index fails to load,
// so the UI can show an error state instead of "0 entities" or "not found".
let indexLoadError = null;

// Layer 1: all-CVE-IDs index (lazily loaded; ~1.8 MB)
let cveIdsIndex = null;
let cveIdsLoading = null;  // promise-of-load to dedupe concurrent calls

// Daily FIRST EPSS scores for the curated tier (epss_curated.json); lazily
// loaded once. Resolves to null when absent (older deployments) or broken.
let epssCurated = null;
let epssLoading = null;
let epssFailed = false;

// Layer 3: per-year shard cache (parsed Map<cve_id, payload>)
const shardCache = new Map();
const shardLoading = new Map();  // year -> in-flight promise

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
        if (!eiRes.ok) throw new Error('entity_index.json HTTP ' + eiRes.status);
        if (!siRes.ok) throw new Error('search_index.json HTTP ' + siRes.status);
        const ei = await eiRes.json();
        const si = await siRes.json();
        if (!ei || typeof ei !== 'object' || !ei.entities || typeof ei.entities !== 'object') {
            throw new Error('entity_index.json has no entities map');
        }
        if (!si || typeof si !== 'object') throw new Error('search_index.json is not an object');
        entityIndex = ei;
        searchIndex = si;
        indexLoadError = null;
    } catch (e) {
        console.error('Failed to load entity indices:', e);
        entityIndex = null;
        searchIndex = null;
        indexLoadError = (e && e.message) ? e.message : String(e);
    } finally {
        indicesLoading = false;
    }
}

function getIndexLoadError() {
    return indexLoadError;
}

// Lazy-load the Layer 1 all-IDs index. Called only when the user types
// a CVE prefix in the search bar or navigates to a CVE not in the rich
// entity_index. Returns the parsed index or null on failure.
async function loadCveIdsIndex() {
    if (cveIdsIndex) return cveIdsIndex;
    if (cveIdsLoading) return cveIdsLoading;
    cveIdsLoading = (async function() {
        try {
            const res = await fetch('data/cve_ids_index.json');
            if (!res.ok) throw new Error('cve_ids_index.json HTTP ' + res.status);
            cveIdsIndex = await res.json();
            return cveIdsIndex;
        } catch (e) {
            console.error('Failed to load cve_ids_index.json:', e);
            return null;
        } finally {
            cveIdsLoading = null;
        }
    })();
    return cveIdsLoading;
}

async function loadEpssCurated() {
    if (epssCurated) return epssCurated;
    // A failed load (absent on older deployments, or broken) is remembered
    // for the page lifetime so every render does not refetch it.
    if (epssFailed) return null;
    if (epssLoading) return epssLoading;
    epssLoading = (async function() {
        try {
            const res = await fetch('data/epss_curated.json');
            if (!res.ok) { epssFailed = true; return null; }
            const data = await res.json();
            if (!data || !data.meta || typeof data.meta.date !== 'string' || !data.scores) {
                epssFailed = true;
                return null;
            }
            epssCurated = data;
            return epssCurated;
        } catch (e) {
            epssFailed = true;
            return null;
        } finally {
            epssLoading = null;
        }
    })();
    return epssLoading;
}

function isProbability(x) {
    return typeof x === 'number' && x >= 0 && x <= 1;
}

// EPSS for a CVE from the daily curated file or the weekly value carried on
// the entity record or shard ({score, percentile, date, model_version?}).
// The newer score date wins; the daily file wins a tie. Returns {score,
// percentile, date, cadence, model} or null. Every value carries its date.
function pickEpss(cveId, weekly) {
    var d = epssCurated && epssCurated.scores ? epssCurated.scores[cveId] : null;
    var daily = (d && isProbability(d.score) && isProbability(d.percentile))
        ? { score: d.score, percentile: d.percentile, date: epssCurated.meta.date, cadence: 'daily',
            model: epssCurated.meta.model_version || '' }
        : null;
    var week = (weekly && isProbability(weekly.score) && isProbability(weekly.percentile) && weekly.date)
        ? { score: weekly.score, percentile: weekly.percentile, date: String(weekly.date), cadence: 'weekly',
            model: weekly.model_version || '' }
        : null;
    if (daily && week) return (week.date > daily.date) ? week : daily;
    return daily || week;
}

// English ordinal of the percentile as displayed (rounded to 3 decimals).
// Whole numbers take their proper suffix (1st, 2nd, 3rd, 11th, 21st, ...);
// a fractional percentile reads as "th".
function formatEpssPercentile(p) {
    var v = Math.round(p * 100000) / 1000;
    var suffix = 'th';
    if (Number.isInteger(v)) {
        var mod100 = v % 100;
        var mod10 = v % 10;
        if (mod100 < 11 || mod100 > 13) {
            if (mod10 === 1) suffix = 'st';
            else if (mod10 === 2) suffix = 'nd';
            else if (mod10 === 3) suffix = 'rd';
        }
    }
    return v + suffix + ' percentile';
}

// Tooltip text naming source cadence, score date, and model.
function epssTitle(epss) {
    return 'FIRST EPSS: probability of exploitation in the next 30 days. ' +
        formatEpssPercentile(epss.percentile) + ', scored ' + epss.date + ' (' + epss.cadence +
        (epss.model ? ', model ' + epss.model : '') + ')';
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

// ── Layer 1: All-CVE-IDs search ─────────────────────────────────

const _CVE_ID_RE = /^cve(?:-(\d{4})(?:-(\d+))?)?$/i;

// Parse a free-form query into {year, tail} when it looks like a CVE prefix.
// Accepts: "CVE", "CVE-2024", "CVE-2024-", "CVE-2024-1", "cve-2024-12345", etc.
function _parseCvePrefix(query) {
    const q = (query || '').trim().toLowerCase();
    if (!q.startsWith('cve')) return null;
    const m = q.match(_CVE_ID_RE);
    if (!m) return null;
    return { year: m[1] || null, tail: m[2] || null };
}

// Returns up to `limit` CVE IDs matching the prefix from the Layer 1 index.
// `cveIdsIndex` must be loaded first (caller awaits loadCveIdsIndex).
function searchAllCves(query, limit) {
    if (!cveIdsIndex || !cveIdsIndex.years) return [];
    limit = limit || 10;
    const parsed = _parseCvePrefix(query);
    if (!parsed) return [];

    const hits = [];
    const years = parsed.year
        ? (cveIdsIndex.years[parsed.year] ? [parsed.year] : [])
        : Object.keys(cveIdsIndex.years).sort().reverse();  // newest first

    for (const yr of years) {
        const tails = cveIdsIndex.years[yr];
        if (!tails) continue;
        if (parsed.tail) {
            const tailPrefix = parsed.tail;
            for (let i = 0; i < tails.length && hits.length < limit; i++) {
                const tStr = String(tails[i]).padStart(4, '0');
                if (tStr.startsWith(tailPrefix) || String(tails[i]).startsWith(tailPrefix)) {
                    hits.push('CVE-' + yr + '-' + tStr);
                }
            }
        } else {
            // Year matched, no tail; return first N from that year.
            for (let i = 0; i < Math.min(tails.length, limit - hits.length); i++) {
                hits.push('CVE-' + yr + '-' + String(tails[i]).padStart(4, '0'));
            }
        }
        if (hits.length >= limit) break;
    }
    return hits;
}

// Returns the total count of CVEs matching the prefix (for "+K more" indicator)
function countAllCves(query) {
    if (!cveIdsIndex || !cveIdsIndex.years) return 0;
    const parsed = _parseCvePrefix(query);
    if (!parsed) return 0;
    let total = 0;
    const years = parsed.year
        ? (cveIdsIndex.years[parsed.year] ? [parsed.year] : [])
        : Object.keys(cveIdsIndex.years);
    for (const yr of years) {
        const tails = cveIdsIndex.years[yr];
        if (!tails) continue;
        if (!parsed.tail) {
            total += tails.length;
            continue;
        }
        for (let i = 0; i < tails.length; i++) {
            const tStr = String(tails[i]).padStart(4, '0');
            if (tStr.startsWith(parsed.tail) || String(tails[i]).startsWith(parsed.tail)) {
                total++;
            }
        }
    }
    return total;
}

// ── Layer 3: On-demand shard fetch ──────────────────────────────

const _CVE_FULL_RE = /^cve-(\d{4})-\d+$/i;

// Raised when a shard could not be loaded for a reason other than "there is
// no shard for that year" (network failure, HTTP error, no gzip support).
// Callers show an error state for this instead of "not found".
class ShardLoadError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ShardLoadError';
    }
}

// Fetch and parse the per-year CVE shard. Caches the parsed Map for reuse.
// Uses native DecompressionStream (Chrome 80+, Firefox 113+, Safari 16.4+).
// Returns Map<cve_id, payload>, or null when the year has no shard (HTTP 404).
// Throws ShardLoadError for every other failure; failures are not cached.
async function fetchShardForYear(year) {
    if (shardCache.has(year)) return shardCache.get(year);
    if (shardLoading.has(year)) return shardLoading.get(year);

    if (typeof DecompressionStream === 'undefined') {
        throw new ShardLoadError('This browser cannot decompress CVE shards (no DecompressionStream support).');
    }

    const promise = (async function() {
        try {
            const url = 'database/CVE-' + year + '.jsonl.gz';
            let response;
            try {
                response = await fetch(url);
            } catch (netErr) {
                throw new ShardLoadError('Network error loading the ' + year + ' CVE shard.');
            }
            if (response.status === 404) {
                console.warn('Shard not found:', url);
                return null;
            }
            if (!response.ok) {
                throw new ShardLoadError('The ' + year + ' CVE shard returned HTTP ' + response.status + '.');
            }
            const ds = new DecompressionStream('gzip');
            const decompressed = response.body.pipeThrough(ds);
            const text = await new Response(decompressed).text();

            const cves = new Map();
            const lines = text.split('\n');
            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                try {
                    const obj = JSON.parse(trimmed);
                    for (const key in obj) {
                        cves.set(key.toUpperCase(), obj[key]);
                    }
                } catch (parseErr) {
                    // Skip malformed lines; do not abort the whole shard.
                }
            }
            shardCache.set(year, cves);
            return cves;
        } catch (err) {
            console.error('Shard fetch failed for year', year, err);
            if (err instanceof ShardLoadError) throw err;
            throw new ShardLoadError('Could not read the ' + year + ' CVE shard.');
        } finally {
            shardLoading.delete(year);
        }
    })();
    shardLoading.set(year, promise);
    return promise;
}

// Look up a single CVE in the shard for its year. Returns the payload dict
// (DESCRIPTION, CWE, CAPEC, TECHNIQUES, OWASP, CVSS, ...) or null when the
// CVE is not in any shard. Throws ShardLoadError when the shard failed to load.
async function fetchCveFromShard(cveId) {
    if (!cveId) return null;
    const m = cveId.match(_CVE_FULL_RE);
    if (!m) return null;
    const year = m[1];
    const cves = await fetchShardForYear(year);
    if (!cves) return null;
    return cves.get(cveId.toUpperCase()) || null;
}

// ── Entity Helpers ──────────────────────────────────────────────

function getEntity(entityId) {
    if (!entityIndex || !entityIndex.entities[entityId]) return null;
    return { id: entityId, ...entityIndex.entities[entityId] };
}

// Some curated entity_index rels carry a bare numeric id (e.g. a CWE stored
// as "664" instead of "CWE-664"), which renders as an unprefixed, untyped
// node in the graph and a dead link in the tabs. Normalize to the canonical
// prefixed form so the label, color, and navigation all resolve. Mirrors the
// normalization the MCP shard projection already does (_shard_rels).
function normalizeRelId(relType, id) {
    const s = String(id);
    if (/^\d+$/.test(s)) {
        if (relType === 'cwe') return 'CWE-' + s;
        if (relType === 'capec') return 'CAPEC-' + s;
    }
    return s;
}

function getRelatedEntities(entityId) {
    const entity = getEntity(entityId);
    if (!entity || !entity.rels) return {};
    const related = {};
    for (const [relType, relData] of Object.entries(entity.rels)) {
        const ids = (relData.ids || []).map(id => normalizeRelId(relType, id));
        related[relType] = {
            ids: ids,
            source: relData.source || '',
            tier: relData.tier || 'derived',
            // Additive (I29): ids reached only through an inherited parent
            // CWE. Older indexes have none, so nothing is marked.
            inherited: (relData.inherited || []).map(id => normalizeRelId(relType, id)),
            entities: ids.map(id => getEntity(id)).filter(Boolean)
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

// CAPEC numbers a CWE lists itself or any ancestor on its ChildOf chain lists,
// the same walk the generator uses for cwe -> capec inheritance.
function cweAncestorCapecs(cweDb, num, visiting) {
    var out = new Set();
    if (visiting[num]) return out;
    visiting[num] = true;
    var entry = cweDb[num];
    if (!entry) return out;
    (entry.RelatedAttackPatterns || []).forEach(function(c) { out.add(String(c)); });
    (entry.ChildOf || []).forEach(function(pid) {
        cweAncestorCapecs(cweDb, String(pid), visiting).forEach(function(c) { out.add(c); });
    });
    return out;
}

async function fetchEntityDetail(entityId) {
    if (detailCache[entityId]) return detailCache[entityId];

    const entity = getEntity(entityId);
    if (!entity) return null;

    var detail = {};
    var failed = false;

    try {
        if (entity.type === 'cwe') {
            var num = entityId.replace('CWE-', '');
            var cweDb = await fetchJson('data/cwe_db.json');
            var cweEntry = cweDb[num];
            if (cweEntry) {
                detail.description = cweEntry.description || '';
                // ChildOf repeats a parent once per CWE view; list it once.
                var parentNums = (cweEntry.ChildOf || []).map(String).filter(function(id, i, all) {
                    return all.indexOf(id) === i;
                });
                detail.parents = parentNums.map(function(id) { return 'CWE-' + id; });
                // I29: which direct parent leads to each ancestor CAPEC, so an
                // inherited CAPEC's tooltip names only that parent.
                detail.capecParents = {};
                parentNums.forEach(function(pid) {
                    cweAncestorCapecs(cweDb, pid, {}).forEach(function(cnum) {
                        var cid = 'CAPEC-' + cnum;
                        (detail.capecParents[cid] = detail.capecParents[cid] || []).push('CWE-' + pid);
                    });
                });
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
        failed = true;
    }

    // Do not cache a failed fetch, so a later visit can retry.
    if (!failed) detailCache[entityId] = detail;
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
