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

// Each distinct CVE year in the cohort costs one shard download (up to tens
// of MB decompressed on the main thread), so the cohort is capped.
var WORKLIST_MAX_IDS = 25;

var WORKLIST_COLUMNS = [
    { key: 'id', label: 'ID', sortable: true },
    { key: 'type', label: 'Type', sortable: true },
    { key: 'cvss', label: 'CVSS', sortable: true },
    { key: 'epss', label: 'EPSS', sortable: true },
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
        id: id, type: '', name: '', cvss: null, severity: '', epss: null, epssInfo: null,
        kev: false, ransomware: '', ssvc: '', due: '', found: false
    };
    if (/^CVE-\d{4}-\d+$/i.test(id)) {
        row.type = 'cve';
        var payload;
        try {
            payload = await fetchCveFromShard(id);
        } catch (err) {
            row.loadError = (err && err.message) ? err.message : String(err);
            return row;
        }
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
            var ent = getEntity(id);
            row.epssInfo = pickEpss(id, payload.EPSS || (ent && ent.epss));
            if (row.epssInfo) row.epss = row.epssInfo.score;
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
        if (key === 'cvss' || key === 'epss') { av = (av === null ? -1 : av); bv = (bv === null ? -1 : bv); }
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
                        WORKLIST_STATE.sortDir = (col.key === 'cvss' || col.key === 'epss') ? -1 : 1;
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
                if (row.loadError) tr.title = row.loadError;
            }
            appendCell(tr, row.id);
            appendCell(tr, row.type);
            var cvssCell = document.createElement('td');
            if (typeof row.cvss === 'number') {
                cvssCell.textContent = row.cvss.toFixed(1) + (row.severity ? ' ' + row.severity : '');
                cvssCell.style.color = sevPalette[(row.severity || '').toUpperCase()] || 'inherit';
                cvssCell.style.fontWeight = '600';
            } else {
                cvssCell.textContent = row.found ? '-' : (row.loadError ? 'load failed' : 'not found');
            }
            tr.appendChild(cvssCell);
            var epssCell = document.createElement('td');
            epssCell.className = 'worklist-epss';
            if (row.epssInfo) {
                // Visible age: the score, its score date (MM-DD), and a
                // "weekly" marker when it came from the shard, not the daily file.
                epssCell.textContent = row.epssInfo.score + ' · ' + row.epssInfo.date.slice(5) +
                    (row.epssInfo.cadence === 'weekly' ? ' weekly' : '');
                epssCell.title = epssTitle(row.epssInfo);
            }
            tr.appendChild(epssCell);
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

function worklistCapNotice(total) {
    if (total <= WORKLIST_MAX_IDS) return '';
    return 'Showing the first ' + WORKLIST_MAX_IDS + ' of ' + total +
        ' IDs; the worklist is capped at ' + WORKLIST_MAX_IDS + '.';
}

async function buildWorklist(raw, tableContainer, statusEl, gen) {
    if (gen === undefined) gen = nextRenderGeneration();
    var allIds = parseWorklistIds(raw);
    if (allIds.length === 0) {
        statusEl.textContent = 'Paste one or more IDs (CVE-..., T..., CWE-..., APT...) to build a worklist, up to ' + WORKLIST_MAX_IDS + '.';
        tableContainer.textContent = '';
        WORKLIST_STATE.rows = [];
        return;
    }
    var ids = allIds.slice(0, WORKLIST_MAX_IDS);
    var capNotice = worklistCapNotice(allIds.length);
    statusEl.textContent = (capNotice ? capNotice + ' ' : '') + 'Resolving ' + ids.length + ' entities...';
    tableContainer.textContent = '';
    await loadEpssCurated();
    var rows = await Promise.all(ids.map(resolveWorklistRow));
    // The user navigated away or started another build while this one ran:
    // drop the result instead of overwriting the page or the URL.
    if (!isCurrentRender(gen)) return;
    WORKLIST_STATE.rows = rows;
    var failed = rows.filter(function(r) { return r.loadError; }).length;
    var parts = [];
    if (capNotice) parts.push(capNotice);
    if (failed) parts.push(failed + ' ID' + (failed === 1 ? '' : 's') + ' could not be loaded (network or shard error); reload to retry.');
    statusEl.textContent = parts.join(' ');
    statusEl.classList.toggle('worklist-status-error', failed > 0);
    // Reflect the resolved cohort in the URL so the worklist is shareable.
    // pushState keeps the history entry but does not fire hashchange, so the
    // router does not re-enter showWorklistPage and build the list twice.
    var newHash = '#/list/' + encodeURIComponent(ids.join(','));
    if (window.location.hash !== newHash) {
        history.pushState(null, '', newHash);
    }
    renderWorklistTable(tableContainer);
}

function showWorklistPage(idsCsv, gen) {
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
        input.placeholder = 'Paste up to ' + WORKLIST_MAX_IDS + ' IDs: CVE-2023-44487, T1499, CWE-79, APT29 (comma, space, or newline separated)';
        kevToggle.addEventListener('change', function() {
            WORKLIST_STATE.kevOnly = kevToggle.checked;
            renderWorklistTable(tableContainer);
        });
    }

    status.classList.remove('worklist-status-error');
    if (idsCsv) {
        buildWorklist(idsCsv, tableContainer, status, gen);
    } else {
        status.textContent = 'Paste up to ' + WORKLIST_MAX_IDS + ' IDs and build a worklist.';
        tableContainer.textContent = '';
    }
}
