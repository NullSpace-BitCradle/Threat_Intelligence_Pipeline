// ── Data freshness (I16) ───────────────────────────────────────
// Reads data/freshness.json (written by the pipeline on each successful
// step) and shows "Data as of <date>" on every page, with a per-source
// breakdown on expand. Any source past its threshold raises an amber banner
// naming it. A missing or malformed file renders nothing: the site looks
// exactly as it did before this file existed.

var FRESHNESS_URL = 'data/freshness.json';
// Fallbacks when an entry has no stale_after_hours of its own.
var FRESHNESS_DAILY_STALE_HOURS = 36;
var FRESHNESS_WEEKLY_STALE_HOURS = 192;

function freshnessThresholdHours(entry) {
    var explicit = entry.stale_after_hours;
    if (typeof explicit === 'number' && isFinite(explicit) && explicit > 0) return explicit;
    var cadence = entry.cadence_hours;
    if (typeof cadence === 'number' && cadence > 24) return FRESHNESS_WEEKLY_STALE_HOURS;
    return FRESHNESS_DAILY_STALE_HOURS;
}

// Source entries: readable ones newest first, then any whose last_success
// cannot be read (when: null). The canary counts an unreadable time as
// stale, so the site does too instead of dropping the entry. Times must
// carry a zone: Z or an offset such as +00:00.
var FRESHNESS_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function parseFreshnessTime(value) {
    if (typeof value !== 'string' || !FRESHNESS_TIME_RE.test(value)) return null;
    var when = new Date(value);
    return isNaN(when.getTime()) ? null : when;
}

function parseFreshness(doc) {
    var out = [];
    var sources = doc && typeof doc === 'object' ? doc.sources : null;
    if (!sources || typeof sources !== 'object' || Array.isArray(sources)) return out;
    Object.keys(sources).forEach(function(key) {
        var entry = sources[key];
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) entry = {};
        out.push({
            key: key,
            label: typeof entry.label === 'string' && entry.label ? entry.label : key,
            when: parseFreshnessTime(entry.last_success),
            cadence: (typeof entry.cadence_hours === 'number' && entry.cadence_hours > 24) ? 'weekly' : 'daily',
            threshold: freshnessThresholdHours(entry)
        });
    });
    out.sort(function(a, b) {
        if (!a.when || !b.when) return (a.when ? -1 : 0) + (b.when ? 1 : 0);
        return b.when - a.when;
    });
    return out;
}

function formatFreshnessUtc(date) {
    return date.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

function formatFreshnessAge(hours) {
    if (hours < 1) return 'under an hour ago';
    if (hours < 48) return Math.floor(hours) + ' hours ago';
    return Math.floor(hours / 24) + ' days ago';
}

function renderFreshness(entries, now) {
    if (!entries.length) return;
    var stale = [];

    var details = document.createElement('details');
    details.className = 'data-freshness';
    details.id = 'data-freshness';
    var summary = document.createElement('summary');
    summary.textContent = entries[0].when
        ? 'Data as of ' + formatFreshnessUtc(entries[0].when)
        : 'Data age unknown';
    summary.title = 'Most recent successful update. Expand for each source.';
    details.appendChild(summary);

    var list = document.createElement('ul');
    list.className = 'data-freshness-list';
    entries.forEach(function(e) {
        var hours = e.when ? (now - e.when) / 3600000 : null;
        var isStale = hours === null || hours > e.threshold;
        if (isStale) stale.push({ entry: e, hours: hours });
        var li = document.createElement('li');
        li.dataset.source = e.key;
        if (isStale) li.className = 'is-stale';
        var name = document.createElement('span');
        name.className = 'data-freshness-source';
        name.textContent = e.label;
        li.appendChild(name);
        li.appendChild(document.createTextNode(e.when
            ? ' ' + formatFreshnessUtc(e.when) + ' (' + formatFreshnessAge(Math.max(hours, 0)) + ', ' + e.cadence + ')'
            : ' unknown (update time unreadable, ' + e.cadence + ')'
        ));
        list.appendChild(li);
    });
    details.appendChild(list);
    document.body.appendChild(details);

    if (stale.length) {
        var banner = document.createElement('div');
        banner.className = 'stale-banner';
        banner.id = 'stale-banner';
        banner.setAttribute('role', 'status');
        banner.textContent = 'Stale data: ' + stale.map(function(s) {
            if (!s.entry.when) return s.entry.label + ' update time unreadable';
            return s.entry.label + ' last updated ' + formatFreshnessUtc(s.entry.when) +
                ' (' + formatFreshnessAge(s.hours) + '; expected ' + s.entry.cadence + ')';
        }).join('; ') + '. Recent data runs may have failed.';
        document.body.insertBefore(banner, document.body.firstChild);
        // The results layout is sized to the viewport; take the banner's
        // height out of it so the page does not grow a second scrollbar.
        var fit = function() {
            document.documentElement.style.setProperty('--stale-banner-h', banner.offsetHeight + 'px');
        };
        fit();
        window.addEventListener('resize', fit);
    }
}

async function initFreshness() {
    try {
        var res = await fetch(FRESHNESS_URL, { cache: 'no-cache' });
        if (!res.ok) return;
        renderFreshness(parseFreshness(await res.json()), new Date());
    } catch (e) {
        // Missing, unreachable or malformed: render the site as before.
    }
}

initFreshness();
