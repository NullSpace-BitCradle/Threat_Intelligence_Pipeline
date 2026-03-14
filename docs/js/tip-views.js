// ===== TIP VIEWS: Theme, Navigation, KEV, APT, Mode Detection =====
// All data comes from our own pre-built JSON files, not user input.

// --- Theme Toggle ---
(function() {
    var saved = localStorage.getItem('tip-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);

    document.getElementById('themeToggle').addEventListener('click', function() {
        var current = document.documentElement.getAttribute('data-theme');
        var next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('tip-theme', next);
        document.getElementById('themeIcon').textContent = next === 'dark' ? '\u263E' : '\u2606';
    });

    var theme = document.documentElement.getAttribute('data-theme');
    document.getElementById('themeIcon').textContent = theme === 'dark' ? '\u263E' : '\u2606';
})();

// --- View Navigation ---
document.querySelectorAll('.tip-nav-tab').forEach(function(tab) {
    tab.addEventListener('click', function() {
        var viewId = this.getAttribute('data-view');

        document.querySelectorAll('.tip-nav-tab').forEach(function(t) { t.classList.remove('active'); });
        this.classList.add('active');

        document.querySelectorAll('.tip-view').forEach(function(v) { v.classList.remove('active'); });
        document.getElementById('view-' + viewId).classList.add('active');

        if (viewId === 'analysis' && typeof chart !== 'undefined') {
            setTimeout(function() { chart.resize(); }, 100);
        }
    });
});

// --- Static Mode Detection ---
(function() {
    var controller = new AbortController();
    setTimeout(function() { controller.abort(); }, 500);

    fetch('/health', { signal: controller.signal })
        .then(function(r) { return r.ok ? r.json() : Promise.reject(); })
        .then(function() { console.log('TIP: Local server mode detected'); })
        .catch(function() { console.log('TIP: Static mode'); });
})();

// --- Safe DOM helper ---
function createEl(tag, attrs, textContent) {
    var el = document.createElement(tag);
    if (attrs) {
        Object.keys(attrs).forEach(function(key) {
            if (key === 'style' && typeof attrs[key] === 'object') {
                Object.assign(el.style, attrs[key]);
            } else if (key === 'className') {
                el.className = attrs[key];
            } else {
                el.setAttribute(key, attrs[key]);
            }
        });
    }
    if (textContent) el.textContent = textContent;
    return el;
}

// --- KEV View ---
async function loadKEVView() {
    try {
        var response = await fetch('data/kev_db.json');
        if (!response.ok) return;
        var kevData = await response.json();
        var entries = Object.entries(kevData);

        document.getElementById('kev-total').textContent = entries.length;
        var ransomwareCount = entries.filter(function(e) { return e[1].knownRansomwareCampaignUse === 'Known'; }).length;
        document.getElementById('kev-ransomware').textContent = ransomwareCount;

        var tbody = document.getElementById('kev-tbody');
        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

        entries.forEach(function(entry) {
            var cveId = entry[0];
            var v = entry[1];
            var tr = document.createElement('tr');

            var tdCve = document.createElement('td');
            var link = document.createElement('a');
            link.href = '#';
            link.textContent = cveId;
            link.style.color = 'var(--link)';
            link.addEventListener('click', function(e) { e.preventDefault(); analyzeCVE(cveId); });
            tdCve.appendChild(link);
            tr.appendChild(tdCve);

            var tdVendor = document.createElement('td');
            tdVendor.textContent = v.vendorProject || '';
            tr.appendChild(tdVendor);

            var tdProduct = document.createElement('td');
            tdProduct.textContent = v.product || '';
            tr.appendChild(tdProduct);

            var tdDate = document.createElement('td');
            tdDate.textContent = v.dateAdded || '';
            tr.appendChild(tdDate);

            var tdDue = document.createElement('td');
            tdDue.textContent = v.dueDate || '';
            tr.appendChild(tdDue);

            var tdRansomware = document.createElement('td');
            if (v.knownRansomwareCampaignUse === 'Known') {
                var badge = document.createElement('span');
                badge.className = 'tip-badge tip-badge-critical';
                badge.textContent = 'Known';
                tdRansomware.appendChild(badge);
            } else {
                tdRansomware.textContent = 'Unknown';
                tdRansomware.style.color = 'var(--text-muted)';
            }
            tr.appendChild(tdRansomware);

            tbody.appendChild(tr);
        });

        document.getElementById('kev-search').addEventListener('input', function() {
            var q = this.value.toLowerCase();
            tbody.querySelectorAll('tr').forEach(function(row) {
                row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
            });
        });
    } catch(e) {
        console.log('KEV data not available yet');
    }
}

// --- APT Groups View ---
async function loadAPTView() {
    try {
        var response = await fetch('data/groups_db.json');
        if (!response.ok) return;
        var data = await response.json();
        var groups = data.groups || {};
        var grid = document.getElementById('apt-grid');
        while (grid.firstChild) grid.removeChild(grid.firstChild);

        var sortedEntries = Object.entries(groups).sort(function(a, b) {
            return a[1].name.localeCompare(b[1].name);
        });

        sortedEntries.forEach(function(entry) {
            var id = entry[0];
            var g = entry[1];

            var card = createEl('div', { className: 'tip-card' });

            // Header
            var header = document.createElement('div');
            header.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start';

            var nameBlock = document.createElement('div');
            var nameEl = document.createElement('div');
            nameEl.style.cssText = 'font-weight:700;font-size:15px;color:var(--text-primary)';
            nameEl.textContent = g.name;
            nameBlock.appendChild(nameEl);

            var idEl = document.createElement('div');
            idEl.style.cssText = 'font-size:12px;color:var(--text-muted);margin-top:2px';
            idEl.textContent = id;
            nameBlock.appendChild(idEl);
            header.appendChild(nameBlock);

            var badge = createEl('span', { className: 'tip-badge tip-badge-apt' }, g.techniques.length + ' techniques');
            header.appendChild(badge);
            card.appendChild(header);

            // Aliases
            if (g.aliases && g.aliases.length > 1) {
                var aliasRow = document.createElement('div');
                aliasRow.style.cssText = 'margin-top:8px;display:flex;flex-wrap:wrap;gap:4px';
                g.aliases.slice(1).forEach(function(alias) {
                    var tag = document.createElement('span');
                    tag.style.cssText = 'font-size:11px;padding:1px 6px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:3px;color:var(--text-secondary)';
                    tag.textContent = alias;
                    aliasRow.appendChild(tag);
                });
                card.appendChild(aliasRow);
            }

            // Description
            if (g.description) {
                var descEl = document.createElement('div');
                descEl.style.cssText = 'margin-top:8px;font-size:12px;color:var(--text-secondary);line-height:1.5;max-height:60px;overflow:hidden';
                descEl.textContent = g.description.length > 200 ? g.description.substring(0, 200) + '...' : g.description;
                card.appendChild(descEl);
            }

            grid.appendChild(card);
        });

        document.getElementById('apt-search').addEventListener('input', function() {
            var q = this.value.toLowerCase();
            grid.querySelectorAll('.tip-card').forEach(function(card) {
                card.style.display = card.textContent.toLowerCase().includes(q) ? '' : 'none';
            });
        });
    } catch(e) {
        console.log('Groups data not available yet');
    }
}

// --- Helper: jump to analysis view with a CVE ---
function analyzeCVE(cveId) {
    document.getElementById('cves').innerText = cveId;
    document.querySelector('[data-view="analysis"]').click();
    if (typeof process === 'function') process();
}

// --- Load on DOM ready ---
document.addEventListener('DOMContentLoaded', function() {
    loadKEVView();
    loadAPTView();
});
