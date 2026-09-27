/**
 * TIP Watchlist and change feed (I7, I8).
 *
 * The pipeline publishes data/changes.json.gz: the last 30 days of observed
 * changes (KEV adds and removals, SSVC exploitation, EPSS jumps, CVSS, the
 * curated set), each with the entities it touches. A reader watches CVEs,
 * CWEs, techniques, and APT groups from their pages, and a KEV vendor or
 * product from the KEV block on a CVE page. The watchlist lives in this
 * browser only (localStorage), is validated on every read, and can never
 * break the page. Safe DOM only (no innerHTML).
 */

var WATCH_KEY = 'tip-watchlist';
var WATCH_MAX = 500;
var WATCH_TYPES = ['cve', 'cwe', 'technique', 'apt_group', 'kev_vendor', 'kev_product'];
var WATCH_LABELS = {
    cve: 'CVE', cwe: 'CWE', technique: 'Technique', apt_group: 'APT group',
    kev_vendor: 'KEV vendor', kev_product: 'KEV product'
};

var CHANGE_TYPES = [
    'kev_added', 'kev_removed', 'ssvc_exploitation_changed', 'epss_jump',
    'cvss_changed', 'curated_added', 'curated_removed'
];
var CHANGE_LABELS = {
    kev_added: 'Entered KEV',
    kev_removed: 'Left KEV',
    ssvc_exploitation_changed: 'SSVC exploitation',
    epss_jump: 'EPSS jump',
    cvss_changed: 'CVSS changed',
    curated_added: 'Joined curated graph',
    curated_removed: 'Left curated graph'
};
var CHANGES_URL = 'data/changes.json.gz';
var WATCH_RECENT_DAYS = 7;

// ── Watchlist storage ──────────────────────────────────────────

// A KEV product is namespaced by its vendor: product names repeat across
// vendors ("Windows", "Firmware").
function kevProductId(vendor, product) {
    return String(vendor) + '/' + String(product);
}

// Only a JSON array of {type, id} with a known type and a sane id survives;
// anything else (corrupt JSON, an object, a hostile value) reads as empty.
function parseWatchlist(raw) {
    if (!raw) return [];
    var parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (e) {
        return [];
    }
    if (!Array.isArray(parsed)) return [];
    var seen = {};
    var out = [];
    for (var i = 0; i < parsed.length && out.length < WATCH_MAX; i++) {
        var w = parsed[i];
        if (!w || typeof w !== 'object' || Array.isArray(w)) continue;
        if (WATCH_TYPES.indexOf(w.type) === -1) continue;
        if (typeof w.id !== 'string' || !w.id.trim() || w.id.length > 200) continue;
        var key = w.type + '|' + w.id.toLowerCase();
        if (seen[key]) continue;
        seen[key] = true;
        out.push({ type: w.type, id: w.id });
    }
    return out;
}

function loadWatchlist() {
    return parseWatchlist(storageGet(WATCH_KEY));
}

function saveWatchlist(list) {
    storageSet(WATCH_KEY, JSON.stringify(list));
}

function watchIndex(list, type, id) {
    var lid = String(id).toLowerCase();
    for (var i = 0; i < list.length; i++) {
        if (list[i].type === type && list[i].id.toLowerCase() === lid) return i;
    }
    return -1;
}

function isWatched(type, id) {
    return watchIndex(loadWatchlist(), type, id) !== -1;
}

// Returns true when the entity is watched after the toggle.
function toggleWatch(type, id) {
    var list = loadWatchlist();
    var idx = watchIndex(list, type, id);
    if (idx === -1) {
        if (list.length >= WATCH_MAX) return false;
        list.push({ type: type, id: id });
    } else {
        list.splice(idx, 1);
    }
    saveWatchlist(list);
    return idx === -1;
}

// ── Change log ─────────────────────────────────────────────────

var CHANGE_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
var CHANGE_CVE_RE = /^CVE-\d{4}-\d{4,}$/;

// Keeps only well-formed events; returns null when the document itself is
// not a change log.
function parseChanges(doc) {
    if (!doc || typeof doc !== 'object' || Array.isArray(doc) || !Array.isArray(doc.events)) return null;
    var events = [];
    for (var i = 0; i < doc.events.length; i++) {
        var ev = doc.events[i];
        if (!ev || typeof ev !== 'object' || Array.isArray(ev)) continue;
        if (typeof ev.date !== 'string' || !CHANGE_DATE_RE.test(ev.date)) continue;
        if (CHANGE_TYPES.indexOf(ev.type) === -1) continue;
        if (typeof ev.cve !== 'string' || !CHANGE_CVE_RE.test(ev.cve)) continue;
        var rel = (ev.related && typeof ev.related === 'object' && !Array.isArray(ev.related)) ? ev.related : {};
        events.push({ date: ev.date, type: ev.type, cve: ev.cve, before: ev.before, after: ev.after, related: rel });
    }
    events.sort(function(a, b) { return a.date < b.date ? 1 : a.date > b.date ? -1 : 0; });
    return {
        since: (typeof doc.since === 'string' && CHANGE_DATE_RE.test(doc.since)) ? doc.since : null,
        events: events
    };
}

var changesLoading = null;

// Resolves to {log} (a parsed log), {missing: true}, or {error: message}.
// Never rejects. A failure is not cached, so a later visit retries.
function loadChanges() {
    if (changesLoading) return changesLoading;
    changesLoading = (async function() {
        try {
            var res = await fetch(CHANGES_URL, { cache: 'no-cache' });
            if (res.status === 404) return { missing: true };
            if (!res.ok) throw new Error('HTTP ' + res.status);
            if (typeof DecompressionStream === 'undefined') throw new Error('no DecompressionStream support');
            var text = await new Response(res.body.pipeThrough(new DecompressionStream('gzip'))).text();
            var log = parseChanges(JSON.parse(text));
            if (!log) throw new Error('not a change log');
            return { log: log };
        } catch (e) {
            changesLoading = null;
            return { error: (e && e.message) ? e.message : String(e) };
        }
    })();
    return changesLoading;
}

function relatedIds(ev, type) {
    var ids = ev.related[type];
    return Array.isArray(ids) ? ids.filter(function(x) { return typeof x === 'string'; }) : [];
}

function eventMatchesWatch(ev, w) {
    var id = w.id.toLowerCase();
    var rel = ev.related;
    if (w.type === 'cve') return ev.cve.toLowerCase() === id;
    if (w.type === 'kev_vendor') return typeof rel.vendor === 'string' && rel.vendor.toLowerCase() === id;
    if (w.type === 'kev_product') {
        return typeof rel.vendor === 'string' && typeof rel.product === 'string' &&
            kevProductId(rel.vendor, rel.product).toLowerCase() === id;
    }
    return relatedIds(ev, w.type).some(function(x) { return x.toLowerCase() === id; });
}

// Events touching any watched entity, newest first, each with the watches
// it matched.
function matchWatchEvents(events, watchlist) {
    var out = [];
    for (var i = 0; i < events.length; i++) {
        var hits = watchlist.filter(function(w) { return eventMatchesWatch(events[i], w); });
        if (hits.length) out.push({ event: events[i], watches: hits });
    }
    return out;
}

function daysBefore(isoDay, days) {
    var d = new Date(isoDay + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() - days);
    return d.toISOString().slice(0, 10);
}

function fmtValue(v) {
    if (v === null || v === undefined) return 'none';
    return String(v);
}

// One line saying what changed, before and after.
function describeChange(ev) {
    var a = ev.after && typeof ev.after === 'object' ? ev.after : {};
    var b = ev.before && typeof ev.before === 'object' ? ev.before : {};
    var who = [ev.related.vendor, ev.related.product].filter(function(x) { return typeof x === 'string' && x; }).join(' ');
    switch (ev.type) {
        case 'kev_added':
            return 'Entered KEV' + (who ? ' (' + who + ')' : '') +
                (a.date_added ? ', added ' + a.date_added : '') + (a.due_date ? ', due ' + a.due_date : '');
        case 'kev_removed':
            return 'Removed from KEV' + (who ? ' (' + who + ')' : '') + (b.date_added ? ', listed since ' + b.date_added : '');
        case 'ssvc_exploitation_changed':
            return ev.before === null || ev.before === undefined
                ? 'SSVC exploitation first set to ' + fmtValue(ev.after)
                : 'SSVC exploitation ' + fmtValue(ev.before) + ' → ' + fmtValue(ev.after);
        case 'epss_jump':
            return 'EPSS ' + fmtValue(ev.before) + ' → ' + fmtValue(ev.after);
        case 'cvss_changed':
            return 'CVSS ' + fmtValue(ev.before) + ' → ' + fmtValue(ev.after);
        case 'curated_added':
            return 'Joined the curated entity graph';
        case 'curated_removed':
            return 'Left the curated entity graph';
    }
    return ev.type;
}

// ── Rendering ──────────────────────────────────────────────────

function watchLabel(type, id) {
    return (WATCH_LABELS[type] || type) + ' ' + id;
}

// A watch toggle button; the caller places it.
function makeWatchToggle(type, id, label) {
    var btn = document.createElement('button');
    btn.className = 'watch-toggle';
    btn.setAttribute('data-watch-type', type);
    btn.setAttribute('data-watch-id', id);
    function paint(on) {
        btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        btn.classList.toggle('is-watched', on);
        btn.textContent = (on ? '★ Watching' : '☆ Watch') + (label ? ' ' + label : '');
        btn.title = on ? 'Stop watching ' + watchLabel(type, id) : 'Watch ' + watchLabel(type, id) + ' for changes';
    }
    paint(isWatched(type, id));
    btn.addEventListener('click', function() {
        paint(toggleWatch(type, id));
        updateWatchSummary();
    });
    return btn;
}

var WATCHABLE_ENTITY_TYPES = ['cve', 'cwe', 'technique', 'apt_group'];

function isWatchableEntity(entity) {
    return !!entity && WATCHABLE_ENTITY_TYPES.indexOf(entity.type) !== -1 && typeof entity.id === 'string';
}

function renderChangeRow(ev, watches) {
    var row = document.createElement('div');
    row.className = 'change-row';
    row.setAttribute('data-change-type', ev.type);

    var date = document.createElement('span');
    date.className = 'change-date';
    date.textContent = ev.date;
    row.appendChild(date);

    var type = document.createElement('span');
    type.className = 'change-type change-type-' + ev.type;
    type.textContent = CHANGE_LABELS[ev.type] || ev.type;
    row.appendChild(type);

    var link = document.createElement('a');
    link.className = 'change-cve';
    link.href = '#/cve/' + ev.cve;
    link.textContent = ev.cve;
    row.appendChild(link);

    var what = document.createElement('span');
    what.className = 'change-what';
    what.textContent = describeChange(ev);
    row.appendChild(what);

    if (watches && watches.length) {
        var via = document.createElement('span');
        via.className = 'change-via';
        via.textContent = 'watching ' + watches.map(function(w) { return watchLabel(w.type, w.id); }).join(', ');
        row.appendChild(via);
    }
    return row;
}

function renderFeedMessage(body, text, isError) {
    var el = document.createElement('div');
    el.className = 'result-message' + (isError ? ' result-error' : '');
    if (isError) el.setAttribute('role', 'alert');
    el.textContent = text;
    body.appendChild(el);
}

function feedLoadMessage(body, res) {
    if (res.missing) {
        renderFeedMessage(body, 'No change log has been published yet. Changes appear here after the next data run.', false);
    } else {
        renderFeedMessage(body, 'Could not read the change log (' + res.error + '). The rest of the site is unaffected.', true);
    }
}

// Route: #/changes or #/changes/<event type>
async function showChangesPage(typeFilter, gen) {
    showPage('page-feed');
    document.getElementById('feed-title').textContent = 'What changed';
    var body = document.getElementById('feed-body');
    body.textContent = '';
    var res = await loadChanges();
    if (!isCurrentRender(gen)) return;
    body.textContent = '';
    if (!res.log) { feedLoadMessage(body, res); return; }

    var want = CHANGE_TYPES.indexOf(typeFilter) !== -1 ? typeFilter : '';
    var controls = document.createElement('div');
    controls.className = 'feed-controls';
    var label = document.createElement('label');
    label.textContent = 'Type ';
    var select = document.createElement('select');
    select.id = 'changes-type-filter';
    var opts = [''].concat(CHANGE_TYPES);
    for (var i = 0; i < opts.length; i++) {
        var o = document.createElement('option');
        o.value = opts[i];
        o.textContent = opts[i] ? CHANGE_LABELS[opts[i]] : 'All types';
        if (opts[i] === want) o.selected = true;
        select.appendChild(o);
    }
    select.addEventListener('change', function() {
        window.location.hash = select.value ? '#/changes/' + select.value : '#/changes';
    });
    label.appendChild(select);
    controls.appendChild(label);
    body.appendChild(controls);

    var events = want ? res.log.events.filter(function(e) { return e.type === want; }) : res.log.events;
    var summary = document.createElement('div');
    summary.className = 'feed-summary';
    summary.textContent = events.length + ' change' + (events.length === 1 ? '' : 's') + ' in the last 30 days' +
        (res.log.since ? ' (log started ' + res.log.since + ')' : '');
    body.appendChild(summary);

    var list = document.createElement('div');
    list.className = 'change-list';
    list.id = 'change-list';
    for (var j = 0; j < events.length; j++) list.appendChild(renderChangeRow(events[j]));
    body.appendChild(list);
}

// Route: #/watching
async function showWatchingPage(gen) {
    showPage('page-feed');
    document.getElementById('feed-title').textContent = 'Watching';
    var body = document.getElementById('feed-body');
    body.textContent = '';
    var watchlist = loadWatchlist();

    var listHead = document.createElement('div');
    listHead.className = 'feed-summary';
    listHead.textContent = watchlist.length
        ? 'Watching ' + watchlist.length + ' entit' + (watchlist.length === 1 ? 'y' : 'ies') + ' in this browser'
        : 'You are not watching anything yet. Use the Watch button on a CVE, CWE, technique, or APT group page, or on a CVE’s KEV vendor and product.';
    body.appendChild(listHead);

    var chips = document.createElement('div');
    chips.className = 'watch-list';
    chips.id = 'watch-list';
    watchlist.forEach(function(w) {
        var chip = document.createElement('span');
        chip.className = 'watch-chip';
        chip.setAttribute('data-watch-type', w.type);
        var name = document.createElement(w.type.indexOf('kev_') === 0 ? 'span' : 'a');
        if (w.type.indexOf('kev_') !== 0) name.href = '#/' + w.type + '/' + encodeURIComponent(w.id);
        name.textContent = watchLabel(w.type, w.id);
        chip.appendChild(name);
        var rm = document.createElement('button');
        rm.className = 'watch-remove';
        rm.title = 'Stop watching';
        rm.textContent = '✕';
        rm.addEventListener('click', function() {
            toggleWatch(w.type, w.id);
            updateWatchSummary();
            showWatchingPage(nextRenderGeneration());
        });
        chip.appendChild(rm);
        chips.appendChild(chip);
    });
    body.appendChild(chips);
    if (!watchlist.length) return;

    var res = await loadChanges();
    if (!isCurrentRender(gen)) return;
    if (!res.log) { feedLoadMessage(body, res); return; }
    var matched = matchWatchEvents(res.log.events, watchlist);
    var summary = document.createElement('div');
    summary.className = 'feed-summary';
    summary.textContent = matched.length + ' change' + (matched.length === 1 ? '' : 's') + ' for your watchlist in the last 30 days';
    body.appendChild(summary);
    var list = document.createElement('div');
    list.className = 'change-list';
    list.id = 'change-list';
    matched.forEach(function(m) { list.appendChild(renderChangeRow(m.event, m.watches)); });
    body.appendChild(list);
}

// Landing line: "3 changes for your watchlist this week". Silent when
// nothing is watched or the log cannot be read.
async function updateWatchSummary() {
    var el = document.getElementById('watch-summary');
    if (!el) return;
    var watchlist = loadWatchlist();
    var count = document.getElementById('watch-count');
    if (count) count.textContent = watchlist.length ? ' (' + watchlist.length + ')' : '';
    el.textContent = '';
    if (!watchlist.length) return;
    var res = await loadChanges();
    if (!res.log) return;
    var today = new Date().toISOString().slice(0, 10);
    var cutoff = daysBefore(today, WATCH_RECENT_DAYS - 1);
    var recent = res.log.events.filter(function(e) { return e.date >= cutoff; });
    var n = matchWatchEvents(recent, watchlist).length;
    var link = document.createElement('a');
    link.href = '#/watching';
    link.textContent = n + ' change' + (n === 1 ? '' : 's') + ' for your watchlist this week';
    el.appendChild(link);
}
