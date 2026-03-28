/**
 * TIP App — Router, search, landing page, theme, mode detection.
 */

// ── Page Management ────────────────────────────────────────────

function showPage(pageId) {
    var pages = document.querySelectorAll('#page-landing, #page-results, #page-search-results');
    for (var i = 0; i < pages.length; i++) {
        pages[i].classList.add('hidden');
        if (pages[i].id === 'page-landing') pages[i].style.display = '';
    }
    var page = document.getElementById(pageId);
    if (page) {
        page.classList.remove('hidden');
        if (pageId === 'page-landing') page.style.display = 'flex';
    }
}

// ── Router ─────────────────────────────────────────────────────

function handleRoute() {
    var hash = window.location.hash;

    if (!hash || hash === '#/' || hash === '#') {
        showPage('page-landing');
        document.getElementById('landing-search').focus();
        return;
    }

    // Route: #/<type>/<id>
    var match = hash.match(/^#\/(\w+)\/(.+)$/);
    if (match) {
        var id = decodeURIComponent(match[2]);
        showPage('page-results');
        document.getElementById('results-search').value = id;
        renderResultPage(id);
        return;
    }

    // Route: #/search/<query>
    var searchMatch = hash.match(/^#\/search\/(.+)$/);
    if (searchMatch) {
        var query = decodeURIComponent(searchMatch[1]);
        showSearchResultsPage(query);
        return;
    }

    showPage('page-landing');
}

window.addEventListener('hashchange', handleRoute);

// ── Search Controller ──────────────────────────────────────────

function setupSearch(inputId, dropdownId) {
    var input = document.getElementById(inputId);
    var dropdown = document.getElementById(dropdownId);
    if (!input || !dropdown) return;

    var debounceTimer;

    input.addEventListener('input', function() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(function() {
            var query = input.value.trim();
            if (query.length < 2) {
                dropdown.classList.remove('open');
                dropdown.textContent = '';
                return;
            }
            var grouped = searchEntities(query);
            renderSearchDropdown(grouped, dropdown, query);
        }, 150);
    });

    input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            dropdown.classList.remove('open');
            var query = input.value.trim();
            if (!query) return;
            navigateToEntity(query);
        }
        if (e.key === 'Escape') {
            dropdown.classList.remove('open');
        }
    });

    document.addEventListener('click', function(e) {
        if (!input.contains(e.target) && !dropdown.contains(e.target)) {
            dropdown.classList.remove('open');
        }
    });
}

function navigateToEntity(query) {
    // Try exact ID match first
    var entity = getEntity(query);
    if (entity) {
        window.location.hash = '#/' + entity.type + '/' + entity.id;
        return;
    }

    // Try search
    var grouped = searchEntities(query);
    var allResults = [];
    for (var type in grouped) {
        allResults = allResults.concat(grouped[type]);
    }

    // Check for exact name match (case-insensitive) — prefer that over multi-result page
    var q = query.toLowerCase();
    for (var i = 0; i < allResults.length; i++) {
        if (allResults[i].id.toLowerCase() === q ||
            (allResults[i].name && allResults[i].name.toLowerCase() === q)) {
            window.location.hash = '#/' + allResults[i].type + '/' + allResults[i].id;
            return;
        }
    }

    if (allResults.length === 1) {
        window.location.hash = '#/' + allResults[0].type + '/' + allResults[0].id;
        return;
    }

    if (allResults.length > 1) {
        window.location.hash = '#/search/' + encodeURIComponent(query);
        return;
    }

    showNotification('No results found for "' + query + '"');
}

function renderSearchDropdown(grouped, dropdown, query) {
    dropdown.textContent = '';
    var types = Object.keys(grouped);

    if (types.length === 0) {
        var empty = document.createElement('div');
        Object.assign(empty.style, { padding: '12px 16px', color: 'var(--text-muted)', fontSize: '13px' });
        empty.textContent = 'No results for "' + query + '"';
        dropdown.appendChild(empty);
        dropdown.classList.add('open');
        return;
    }

    for (var t = 0; t < types.length; t++) {
        var type = types[t];
        var cfg = TYPE_CONFIG[type] || { color: '#888', label: type, relLabel: type };

        var header = document.createElement('div');
        header.className = 'search-group-header';
        header.textContent = cfg.relLabel || cfg.label;
        dropdown.appendChild(header);

        for (var r = 0; r < grouped[type].length; r++) {
            var result = grouped[type][r];
            var row = document.createElement('div');
            row.className = 'search-result-row';
            (function(res) {
                row.addEventListener('click', function() {
                    dropdown.classList.remove('open');
                    window.location.hash = '#/' + res.type + '/' + res.id;
                });
            })(result);

            var dot = document.createElement('span');
            dot.className = 'type-dot';
            dot.style.background = cfg.color;
            row.appendChild(dot);

            var idSpan = document.createElement('span');
            idSpan.className = 'search-result-id';
            idSpan.textContent = result.id;
            row.appendChild(idSpan);

            if (result.name && result.name !== result.id) {
                var nameSpan = document.createElement('span');
                nameSpan.className = 'search-result-name';
                nameSpan.textContent = result.name.length > 50 ? result.name.slice(0, 47) + '...' : result.name;
                row.appendChild(nameSpan);
            }

            dropdown.appendChild(row);
        }
    }
    dropdown.classList.add('open');
}

function showSearchResultsPage(query) {
    showPage('page-search-results');
    document.getElementById('sr-search').value = query;

    var body = document.getElementById('search-results-body');
    body.textContent = '';

    var title = document.createElement('div');
    title.className = 'search-results-title';
    title.textContent = 'Results for "' + query + '"';
    body.appendChild(title);

    var grouped = searchEntities(query);
    var types = Object.keys(grouped);

    for (var t = 0; t < types.length; t++) {
        var type = types[t];
        var results = grouped[type];
        var cfg = TYPE_CONFIG[type] || { label: type, relLabel: type };

        var group = document.createElement('div');
        group.className = 'search-results-group';

        var groupHeader = document.createElement('div');
        groupHeader.className = 'search-results-group-header';
        groupHeader.textContent = (cfg.relLabel || cfg.label) + ' (' + results.length + ')';
        group.appendChild(groupHeader);

        var list = document.createElement('div');
        list.className = 'entity-card-list';

        for (var r = 0; r < results.length; r++) {
            var result = results[r];
            var card = document.createElement('div');
            card.className = 'entity-card';
            (function(res) {
                card.addEventListener('click', function() {
                    window.location.hash = '#/' + res.type + '/' + res.id;
                });
            })(result);

            var left = document.createElement('div');
            var idSpan = document.createElement('div');
            idSpan.className = 'entity-card-id';
            idSpan.textContent = result.id;
            left.appendChild(idSpan);

            if (result.name && result.name !== result.id) {
                var nameSpan = document.createElement('div');
                nameSpan.className = 'entity-card-name';
                nameSpan.textContent = result.name;
                left.appendChild(nameSpan);
            }
            card.appendChild(left);
            list.appendChild(card);
        }

        group.appendChild(list);
        body.appendChild(group);
    }

    if (types.length === 0) {
        var noResults = document.createElement('div');
        Object.assign(noResults.style, { color: 'var(--text-muted)', padding: '20px' });
        noResults.textContent = 'No results found.';
        body.appendChild(noResults);
    }
}

// ── Landing Page Setup ─────────────────────────────────────────

async function initLanding() {
    await loadIndices();

    // Hint chips
    var chips = document.getElementById('hint-chips');
    var examples = ['CVE-2024-37079', 'T1059.001', 'APT29', 'CWE-79', 'CAPEC-126', 'File Analysis'];
    for (var i = 0; i < examples.length; i++) {
        var chip = document.createElement('span');
        chip.className = 'hint-chip';
        chip.textContent = examples[i];
        (function(ex) {
            chip.addEventListener('click', function() { navigateToEntity(ex); });
        })(examples[i]);
        chips.appendChild(chip);
    }

    // Stats bar
    var statsBar = document.getElementById('stats-bar');
    var entityCount = getEntityCount();
    var aptEntities = getEntitiesByType('apt_group');
    var techEntities = getEntitiesByType('technique');

    var stats = [
        { value: entityCount, label: 'entities indexed' },
        { value: aptEntities.length, label: 'APT groups' },
        { value: techEntities.length, label: 'ATT&CK techniques' }
    ];

    for (var s = 0; s < stats.length; s++) {
        var span = document.createElement('span');
        var strong = document.createElement('strong');
        strong.textContent = stats[s].value.toLocaleString();
        span.appendChild(strong);
        span.appendChild(document.createTextNode(' ' + stats[s].label));
        statsBar.appendChild(span);
    }

    // Quick access — load KEV data for recent entries
    try {
        var kevRes = await fetch('data/kev_db.json');
        if (kevRes.ok) {
            var kevData = await kevRes.json();
            var entries = Object.entries(kevData)
                .sort(function(a, b) { return (b[1].dateAdded || '').localeCompare(a[1].dateAdded || ''); })
                .slice(0, 3);

            var grid = document.getElementById('quick-grid');
            for (var k = 0; k < entries.length; k++) {
                var cveId = entries[k][0];
                var kev = entries[k][1];

                var card = document.createElement('div');
                card.className = 'quick-card';
                (function(id) {
                    card.addEventListener('click', function() { navigateToEntity(id); });
                })(cveId);

                var cardTitle = document.createElement('div');
                cardTitle.className = 'quick-card-title';
                var sevDot = document.createElement('span');
                sevDot.className = 'severity-dot';
                sevDot.style.background = 'var(--severity-critical)';
                cardTitle.appendChild(sevDot);
                cardTitle.appendChild(document.createTextNode(cveId));
                card.appendChild(cardTitle);

                var meta = document.createElement('div');
                meta.className = 'quick-card-meta';
                meta.textContent = (kev.vendorProject || '') + ' ' + (kev.product || '') + ' \u00B7 Added ' + (kev.dateAdded || '');
                card.appendChild(meta);

                grid.appendChild(card);
            }
        }
    } catch (e) {
        console.log('KEV data not available for quick access');
    }
}

// ── Theme Toggle ───────────────────────────────────────────────

function setupTheme() {
    var saved = localStorage.getItem('tip-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);

    function toggleTheme() {
        var current = document.documentElement.getAttribute('data-theme');
        var next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('tip-theme', next);
        updateThemeIcons(next);
    }

    function updateThemeIcons(theme) {
        var icon = theme === 'dark' ? '\u263E' : '\u2606';
        var btns = document.querySelectorAll('#btn-theme, #btn-theme-sr');
        for (var i = 0; i < btns.length; i++) btns[i].textContent = icon;
    }

    document.getElementById('btn-theme').addEventListener('click', toggleTheme);
    var btnSr = document.getElementById('btn-theme-sr');
    if (btnSr) btnSr.addEventListener('click', toggleTheme);

    updateThemeIcons(document.documentElement.getAttribute('data-theme') || 'dark');
}

// ── Investigation Tray ─────────────────────────────────────────

var pinnedEntities = JSON.parse(localStorage.getItem('tip-pinned') || '[]');

function setupInvestigation() {
    var pinBtn = document.getElementById('btn-pin');
    var trayBtn = document.getElementById('btn-investigation');
    var tray = document.getElementById('investigation-tray');

    pinBtn.addEventListener('click', function() {
        var hash = window.location.hash;
        var match = hash.match(/^#\/(\w+)\/(.+)$/);
        if (!match) return;
        var id = decodeURIComponent(match[2]);
        var idx = pinnedEntities.indexOf(id);
        if (idx >= 0) {
            pinnedEntities.splice(idx, 1);
        } else {
            pinnedEntities.push(id);
        }
        localStorage.setItem('tip-pinned', JSON.stringify(pinnedEntities));
        updatePinCount();
    });

    trayBtn.addEventListener('click', function() {
        tray.classList.toggle('open');
        renderInvestigationTray();
    });

    document.addEventListener('click', function(e) {
        if (!trayBtn.contains(e.target) && !tray.contains(e.target)) {
            tray.classList.remove('open');
        }
    });

    updatePinCount();
}

function updatePinCount() {
    document.getElementById('pin-count').textContent = pinnedEntities.length;
}

function renderInvestigationTray() {
    var tray = document.getElementById('investigation-tray');
    tray.textContent = '';

    if (pinnedEntities.length === 0) {
        var empty = document.createElement('div');
        Object.assign(empty.style, { padding: '16px', color: 'var(--text-muted)', fontSize: '13px' });
        empty.textContent = 'No pinned entities';
        tray.appendChild(empty);
        return;
    }

    for (var i = 0; i < pinnedEntities.length; i++) {
        var id = pinnedEntities[i];
        var entity = getEntity(id);
        var item = document.createElement('div');
        item.className = 'investigation-item';

        var label = document.createElement('span');
        label.textContent = id + (entity && entity.name !== id ? ' \u2014 ' + entity.name : '');
        label.style.cursor = 'pointer';
        (function(entityId, ent) {
            label.addEventListener('click', function() {
                tray.classList.remove('open');
                if (ent) window.location.hash = '#/' + ent.type + '/' + entityId;
            });
        })(id, entity);
        item.appendChild(label);

        var removeBtn = document.createElement('button');
        removeBtn.className = 'icon-btn';
        Object.assign(removeBtn.style, { width: '24px', height: '24px', fontSize: '12px' });
        removeBtn.textContent = '\u2715';
        (function(entityId) {
            removeBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                var idx = pinnedEntities.indexOf(entityId);
                if (idx >= 0) pinnedEntities.splice(idx, 1);
                localStorage.setItem('tip-pinned', JSON.stringify(pinnedEntities));
                updatePinCount();
                renderInvestigationTray();
            });
        })(id);
        item.appendChild(removeBtn);

        tray.appendChild(item);
    }

    // Export action
    var actions = document.createElement('div');
    actions.className = 'investigation-actions';
    var exportBtn = document.createElement('button');
    exportBtn.className = 'icon-btn';
    Object.assign(exportBtn.style, { width: 'auto', padding: '4px 12px', fontSize: '12px' });
    exportBtn.textContent = 'Export JSON';
    exportBtn.addEventListener('click', function() {
        var data = pinnedEntities.map(function(id) { return getEntity(id); }).filter(Boolean);
        var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'tip-investigation.json';
        a.click();
    });
    actions.appendChild(exportBtn);
    tray.appendChild(actions);
}

// ── Notification ───────────────────────────────────────────────

function showNotification(message) {
    var el = document.createElement('div');
    el.className = 'tip-notify';
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(function() { el.style.opacity = '0'; }, 2000);
    setTimeout(function() { el.remove(); }, 2500);
}

// ── Mode Detection ─────────────────────────────────────────────

function detectMode() {
    var controller = new AbortController();
    setTimeout(function() { controller.abort(); }, 500);
    fetch('/health', { signal: controller.signal })
        .then(function(r) { return r.ok ? r.json() : Promise.reject(); })
        .catch(function() { console.log('TIP: Static mode'); });
}

// ── Navigation Helpers ─────────────────────────────────────────

function setupBrandLinks() {
    document.getElementById('brand-home').addEventListener('click', function() {
        window.location.hash = '#/';
    });
    var brandSr = document.getElementById('brand-home-sr');
    if (brandSr) brandSr.addEventListener('click', function() {
        window.location.hash = '#/';
    });
}

// ── Init ───────────────────────────────────────────────────────

async function init() {
    setupTheme();
    setupSearch('landing-search', 'landing-dropdown');
    setupSearch('results-search', 'results-dropdown');
    setupSearch('sr-search', 'sr-dropdown');
    setupBrandLinks();
    setupInvestigation();
    detectMode();
    await initLanding();
    handleRoute();
}

init();
