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
            link.href = 'https://nvd.nist.gov/vuln/detail/' + cveId;
            link.target = '_blank';
            link.rel = 'noopener';
            link.textContent = cveId;
            link.style.color = 'var(--link)';
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

        var kevSearch = document.getElementById('kev-search');
        kevSearch.oninput = function() {
            var q = this.value.toLowerCase();
            tbody.querySelectorAll('tr').forEach(function(row) {
                row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
            });
        };
    } catch(e) {
        console.log('KEV data not available yet');
    }
}

// --- Markdown link renderer (safe DOM methods) ---
function renderMarkdownLinks(text, container) {
    var mdLinkRe = /\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g;
    var lastIndex = 0;
    var match;
    while ((match = mdLinkRe.exec(text)) !== null) {
        if (match.index > lastIndex) {
            container.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
        }
        var a = document.createElement('a');
        a.href = match[2];
        a.target = '_blank';
        a.rel = 'noopener';
        a.style.color = 'var(--link)';
        a.textContent = match[1];
        container.appendChild(a);
        lastIndex = mdLinkRe.lastIndex;
    }
    if (lastIndex < text.length) {
        container.appendChild(document.createTextNode(text.slice(lastIndex)));
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
            card.style.cursor = 'pointer';
            card.style.transition = 'border-color 0.15s';

            // Header
            var header = document.createElement('div');
            header.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start';

            var nameBlock = document.createElement('div');
            var nameEl = document.createElement('span');
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

            // Aliases (compact)
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

            // Short description (collapsed view)
            var shortDesc = document.createElement('div');
            shortDesc.style.cssText = 'margin-top:8px;font-size:12px;color:var(--text-secondary);line-height:1.5;max-height:60px;overflow:hidden';
            if (g.description) {
                var truncated = g.description.length > 200 ? g.description.substring(0, 200) + '...' : g.description;
                renderMarkdownLinks(truncated, shortDesc);
            }
            card.appendChild(shortDesc);

            // === Expanded detail panel (hidden by default) ===
            var detail = document.createElement('div');
            detail.style.cssText = 'display:none;margin-top:12px;border-top:1px solid var(--border);padding-top:12px';

            // Full description
            if (g.description) {
                var fullDescLabel = document.createElement('div');
                fullDescLabel.style.cssText = 'font-weight:600;font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px';
                fullDescLabel.textContent = 'Description';
                detail.appendChild(fullDescLabel);

                var fullDesc = document.createElement('div');
                fullDesc.style.cssText = 'font-size:13px;color:var(--text-secondary);line-height:1.6;margin-bottom:12px';
                renderMarkdownLinks(g.description, fullDesc);
                detail.appendChild(fullDesc);
            }

            // Techniques grid
            if (g.techniques && g.techniques.length > 0) {
                var techLabel = document.createElement('div');
                techLabel.style.cssText = 'font-weight:600;font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px';
                techLabel.textContent = 'ATT&CK Techniques';
                detail.appendChild(techLabel);

                var techGrid = document.createElement('div');
                techGrid.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px';
                g.techniques.forEach(function(tid) {
                    var techTag = document.createElement('a');
                    techTag.href = 'https://attack.mitre.org/techniques/' + tid.replace('.', '/') + '/';
                    techTag.target = '_blank';
                    techTag.rel = 'noopener';
                    techTag.style.cssText = 'font-size:11px;padding:2px 6px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:3px;color:var(--link);text-decoration:none;font-family:monospace';
                    techTag.textContent = tid;
                    techGrid.appendChild(techTag);
                });
                detail.appendChild(techGrid);
            }

            // Attack history note
            var historyNote = document.createElement('div');
            historyNote.style.cssText = 'font-size:11px;color:var(--text-muted);font-style:italic;margin-bottom:12px';
            historyNote.textContent = 'Recent confirmed attack campaigns not yet available in dataset.';
            detail.appendChild(historyNote);

            // Action buttons
            var actions = document.createElement('div');
            actions.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap';

            var mitreLink = document.createElement('a');
            mitreLink.href = 'https://attack.mitre.org/groups/' + id + '/';
            mitreLink.target = '_blank';
            mitreLink.rel = 'noopener';
            mitreLink.className = 'tip-btn tip-btn-secondary';
            mitreLink.style.cssText += ';font-size:12px;text-decoration:none';
            mitreLink.textContent = 'View on MITRE ATT&CK';
            actions.appendChild(mitreLink);

            if (g.techniques && g.techniques.length > 0) {
                var analyzeBtn = document.createElement('button');
                analyzeBtn.className = 'tip-btn tip-btn-primary';
                analyzeBtn.style.fontSize = '12px';
                analyzeBtn.textContent = 'Map Techniques';
                analyzeBtn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    // Jump to analysis with this group's techniques
                    // Build fake CVE list — not applicable, so use technique mapping instead
                    Swal.fire({
                        icon: 'info',
                        title: g.name + ' — ' + g.techniques.length + ' Techniques',
                        html: 'Techniques: ' + g.techniques.slice(0, 20).join(', ') + (g.techniques.length > 20 ? '...' : ''),
                        footer: '<a href="https://attack.mitre.org/groups/' + id + '/" target="_blank">View full details on MITRE ATT&CK</a>'
                    });
                });
                actions.appendChild(analyzeBtn);
            }

            detail.appendChild(actions);
            card.appendChild(detail);

            // Toggle expand/collapse on card click
            card.addEventListener('click', function(e) {
                if (e.target.tagName === 'A' || e.target.tagName === 'BUTTON') return;
                var isExpanded = detail.style.display !== 'none';
                detail.style.display = isExpanded ? 'none' : 'block';
                shortDesc.style.display = isExpanded ? '' : 'none';
                card.style.borderColor = isExpanded ? '' : 'var(--accent)';
            });

            grid.appendChild(card);
        });

        var aptSearch = document.getElementById('apt-search');
        aptSearch.oninput = function() {
            var q = this.value.toLowerCase();
            grid.querySelectorAll('.tip-card').forEach(function(card) {
                card.style.display = card.textContent.toLowerCase().includes(q) ? '' : 'none';
            });
        };
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
