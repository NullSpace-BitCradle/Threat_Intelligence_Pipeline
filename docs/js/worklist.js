/**
 * TIP Worklist — triage mode (I28).
 *
 * Paste a list of entity IDs and get one sortable table across the cohort:
 * CVSS, KEV, ransomware use, SSVC exploit status, and remediation due date —
 * the fields that answer "what do I work first?". CVEs are resolved from the
 * shard so the full intelligence is available even outside the curated graph;
 * non-CVE IDs resolve from the entity index. Safe DOM only (no innerHTML).
 */

var WORKLIST_STATE = { rows: [], sortKey: 'cvss', sortDir: -1, kevOnly: false };

var WORKLIST_COLUMNS = [
    { key: 'id', label: 'ID', sortable: true },
    { key: 'type', label: 'Type', sortable: true },
    { key: 'cvss', label: 'CVSS', sortable: true },
    { key: 'kev', label: 'KEV', sortable: true },
    { key: 'ransomware', label: 'Ransomware', sortable: true },
    { key: 'ssvc', label: 'SSVC', sortable: true },
    { key: 'due', label: 'Due', sortable: true },
    { key: 'name', label: 'Name', sortable: false }
];

function parseWorklistIds(raw) {
    var seen = {};
    var out = [];
    var parts = (raw || '').split(/[\s,]+/);
    for (var i = 0; i < parts.length; i++) {
        var id = parts[i].trim();
        if (!id) continue;
        var norm = /^cve-/i.test(id) ? id.toUpperCase() : id;
        if (seen[norm]) continue;
        seen[norm] = true;
        out.push(norm);
    }
    return out;
}

async function resolveWorklistRow(id) {
    var row = {
        id: id, type: '', name: '', cvss: null, severity: '',
        kev: false, ransomware: '', ssvc: '', due: '', found: false
    };
    if (/^CVE-\d{4}-\d+$/i.test(id)) {
        row.type = 'cve';
        var payload = await fetchCveFromShard(id);
        if (payload) {
            row.found = true;
            var desc = payload.DESCRIPTION || '';
            row.name = desc ? (desc.split('. ')[0] || '').trim() : id;
            if (payload.CVSS && typeof payload.CVSS === 'object') {
                if (typeof payload.CVSS.score === 'number') row.cvss = payload.CVSS.score;
                row.severity = payload.CVSS.severity || '';
            }
            if (payload.KEV && typeof payload.KEV === 'object' && payload.KEV.inKEV) {
                row.kev = true;
                row.ransomware = payload.KEV.knownRansomwareCampaignUse || '';
                row.due = payload.KEV.dueDate || '';
            }
            if (payload.VULNRICHMENT && typeof payload.VULNRICHMENT === 'object') {
                row.ssvc = payload.VULNRICHMENT.ssvcExploitStatus || '';
            }
        }
        return row;
    }
    var ent = getEntity(id);
    if (ent) {
        row.found = true;
        row.type = ent.type || '';
        row.name = ent.name || id;
        if (typeof ent.cvss_score === 'number') row.cvss = ent.cvss_score;
        row.severity = ent.severity || '';
        row.kev = !!ent.kev;
    }
    return row;
}

function sortWorklistRows(rows) {
    var key = WORKLIST_STATE.sortKey;
    var dir = WORKLIST_STATE.sortDir;
    var sorted = rows.slice();
    sorted.sort(function(a, b) {
        var av = a[key];
        var bv = b[key];
        if (key === 'cvss') { av = (av === null ? -1 : av); bv = (bv === null ? -1 : bv); }
        else if (key === 'kev') { av = av ? 1 : 0; bv = bv ? 1 : 0; }
        else { av = String(av || '').toLowerCase(); bv = String(bv || '').toLowerCase(); }
        if (av < bv) return -1 * dir;
        if (av > bv) return 1 * dir;
        return a.id.localeCompare(b.id);
    });
    return sorted;
}

function renderWorklistTable(container) {
    container.textContent = '';
    var rows = WORKLIST_STATE.rows;
    if (WORKLIST_STATE.kevOnly) rows = rows.filter(function(r) { return r.kev; });
    rows = sortWorklistRows(rows);

    var summary = document.createElement('div');
    summary.className = 'worklist-summary';
    var kevCount = WORKLIST_STATE.rows.filter(function(r) { return r.kev; }).length;
    var ransCount = WORKLIST_STATE.rows.filter(function(r) { return r.ransomware === 'Known'; }).length;
    summary.textContent = WORKLIST_STATE.rows.length + ' entities · ' + kevCount + ' in KEV · ' + ransCount + ' ransomware-linked';
    container.appendChild(summary);

    var table = document.createElement('table');
    table.className = 'worklist-table';

    var thead = document.createElement('thead');
    var htr = document.createElement('tr');
    for (var c = 0; c < WORKLIST_COLUMNS.length; c++) {
        (function(col) {
            var th = document.createElement('th');
            th.textContent = col.label;
            if (col.sortable) {
                th.classList.add('sortable');
                if (WORKLIST_STATE.sortKey === col.key) {
                    th.textContent = col.label + (WORKLIST_STATE.sortDir === -1 ? ' ▼' : ' ▲');
                }
                th.addEventListener('click', function() {
                    if (WORKLIST_STATE.sortKey === col.key) {
                        WORKLIST_STATE.sortDir *= -1;
                    } else {
                        WORKLIST_STATE.sortKey = col.key;
                        WORKLIST_STATE.sortDir = (col.key === 'cvss') ? -1 : 1;
                    }
                    renderWorklistTable(container);
                });
            }
            htr.appendChild(th);
        })(WORKLIST_COLUMNS[c]);
    }
    thead.appendChild(htr);
    table.appendChild(thead);

    var sevPalette = { CRITICAL: '#d63031', HIGH: '#e17055', MEDIUM: '#fdcb6e', LOW: '#74b9ff', NONE: '#888' };
    var tbody = document.createElement('tbody');
    for (var r = 0; r < rows.length; r++) {
        (function(row) {
            var tr = document.createElement('tr');
            if (row.found) {
                tr.classList.add('clickable');
                tr.addEventListener('click', function() { navigateToEntity(row.id); });
            } else {
                tr.classList.add('not-found');
            }
            appendCell(tr, row.id);
            appendCell(tr, row.type);
            var cvssCell = document.createElement('td');
            if (typeof row.cvss === 'number') {
                cvssCell.textContent = row.cvss.toFixed(1) + (row.severity ? ' ' + row.severity : '');
                cvssCell.style.color = sevPalette[(row.severity || '').toUpperCase()] || 'inherit';
                cvssCell.style.fontWeight = '600';
            } else {
                cvssCell.textContent = row.found ? '—' : 'not found';
            }
            tr.appendChild(cvssCell);
            appendCell(tr, row.kev ? 'KEV' : '');
            var ransCell = document.createElement('td');
            ransCell.textContent = row.ransomware === 'Known' ? '⚠ Known' : (row.ransomware || '');
            if (row.ransomware === 'Known') ransCell.style.color = '#b71c1c';
            tr.appendChild(ransCell);
            appendCell(tr, row.ssvc ? String(row.ssvc).toUpperCase() : '');
            appendCell(tr, row.due);
            appendCell(tr, row.name);
            tbody.appendChild(tr);
        })(rows[r]);
    }
    table.appendChild(tbody);
    container.appendChild(table);
}

function appendCell(tr, text) {
    var td = document.createElement('td');
    td.textContent = text == null ? '' : String(text);
    tr.appendChild(td);
}

async function buildWorklist(raw, tableContainer, statusEl) {
    var ids = parseWorklistIds(raw);
    if (ids.length === 0) {
        statusEl.textContent = 'Paste one or more IDs (CVE-…, T…, CWE-…, APT…) to build a worklist.';
        tableContainer.textContent = '';
        WORKLIST_STATE.rows = [];
        return;
    }
    statusEl.textContent = 'Resolving ' + ids.length + ' entities…';
    tableContainer.textContent = '';
    var rows = await Promise.all(ids.map(resolveWorklistRow));
    WORKLIST_STATE.rows = rows;
    statusEl.textContent = '';
    // Reflect the resolved cohort in the URL so the worklist is shareable.
    window.location.hash = '#/list/' + encodeURIComponent(ids.join(','));
    renderWorklistTable(tableContainer);
}

function showWorklistPage(idsCsv) {
    showPage('page-worklist');
    var input = document.getElementById('worklist-input');
    var buildBtn = document.getElementById('worklist-build');
    var kevToggle = document.getElementById('worklist-kev-only');
    var status = document.getElementById('worklist-status');
    var tableContainer = document.getElementById('worklist-table');

    if (idsCsv) input.value = parseWorklistIds(idsCsv).join('\n');

    // Wire once (guard against duplicate listeners on re-entry).
    if (!buildBtn.dataset.wired) {
        buildBtn.dataset.wired = '1';
        buildBtn.addEventListener('click', function() {
            buildWorklist(input.value, tableContainer, status);
        });
        kevToggle.addEventListener('change', function() {
            WORKLIST_STATE.kevOnly = kevToggle.checked;
            renderWorklistTable(tableContainer);
        });
    }

    if (idsCsv) {
        buildWorklist(idsCsv, tableContainer, status);
    } else {
        status.textContent = 'Paste IDs and build a worklist.';
        tableContainer.textContent = '';
    }
}
