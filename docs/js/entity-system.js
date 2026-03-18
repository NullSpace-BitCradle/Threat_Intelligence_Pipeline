/**
 * TIP Entity System — Search, Detail Panel, Investigation State
 * Standalone module: no dependency on global.js or tip-views.js
 * Uses CSS variable theming and safe DOM methods throughout.
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

// ── Search Results Dropdown ─────────────────────────────────────

function renderSearchResults(grouped, container) {
    container.textContent = '';
    const types = Object.keys(grouped);
    if (types.length === 0) {
        const empty = document.createElement('div');
        Object.assign(empty.style, {
            padding: '12px 16px', color: 'var(--text-muted)', fontSize: '13px'
        });
        empty.textContent = 'No results';
        container.appendChild(empty);
        showDropdown(container);
        return;
    }

    for (const type of types) {
        const cfg = TYPE_CONFIG[type] || { color: '#888', label: type.toUpperCase(), relLabel: type };
        const header = document.createElement('div');
        Object.assign(header.style, {
            padding: '6px 16px', fontSize: '11px', fontWeight: '600',
            textTransform: 'uppercase', color: 'var(--text-muted)',
            background: 'var(--bg-secondary)', letterSpacing: '0.5px'
        });
        const badge = document.createElement('span');
        Object.assign(badge.style, {
            display: 'inline-block', padding: '1px 6px', borderRadius: '3px',
            background: cfg.color, color: '#000', fontSize: '10px', fontWeight: '700',
            marginRight: '6px'
        });
        badge.textContent = cfg.label;
        header.appendChild(badge);
        header.appendChild(document.createTextNode(cfg.relLabel));
        container.appendChild(header);

        for (const result of grouped[type]) {
            const row = document.createElement('div');
            Object.assign(row.style, {
                padding: '8px 16px', cursor: 'pointer', display: 'flex',
                alignItems: 'center', gap: '8px', fontSize: '13px',
                color: 'var(--text-primary)', transition: 'background 0.1s'
            });
            row.addEventListener('mouseenter', () => { row.style.background = 'var(--bg-secondary)'; });
            row.addEventListener('mouseleave', () => { row.style.background = 'none'; });

            const dot = document.createElement('span');
            Object.assign(dot.style, {
                width: '8px', height: '8px', borderRadius: '50%',
                background: cfg.color, flexShrink: '0'
            });
            row.appendChild(dot);

            const idSpan = document.createElement('span');
            idSpan.style.fontWeight = '600';
            idSpan.textContent = result.id;
            row.appendChild(idSpan);

            if (result.name) {
                const nameSpan = document.createElement('span');
                nameSpan.style.color = 'var(--text-secondary)';
                const name = result.name.length > 50 ? result.name.slice(0, 47) + '...' : result.name;
                nameSpan.textContent = name;
                row.appendChild(nameSpan);
            }

            row.addEventListener('click', () => {
                hideDropdown(container);
                showEntityDetail(result.id);
            });
            container.appendChild(row);
        }
    }
    showDropdown(container);
}

function showDropdown(container) {
    Object.assign(container.style, {
        display: 'block', position: 'absolute', top: '100%', left: '0',
        width: '100%', minWidth: '320px', maxHeight: '400px', overflowY: 'auto',
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: '0 0 6px 6px', boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
        zIndex: '250'
    });
}

function hideDropdown(container) {
    container.style.display = 'none';
    container.textContent = '';
}

// ── Entity Detail Panel ─────────────────────────────────────────

function showEntityDetail(entityId) {
    if (!entityIndex || !entityIndex.entities[entityId]) return;
    const entity = entityIndex.entities[entityId];
    const cfg = TYPE_CONFIG[entity.type] || { color: '#888', label: entity.type || '?', relLabel: '' };

    let panel = document.getElementById('entity-panel');
    if (!panel) {
        panel = document.createElement('div');
        panel.id = 'entity-panel';
        document.body.appendChild(panel);
    }
    Object.assign(panel.style, {
        position: 'fixed', right: '0', top: '48px', width: '400px',
        height: 'calc(100vh - 48px)', zIndex: '200', overflowY: 'auto',
        background: 'var(--bg-card)', borderLeft: '1px solid var(--border)',
        boxShadow: '-4px 0 16px rgba(0,0,0,0.2)', padding: '0',
        fontFamily: 'inherit', transition: 'transform 0.2s ease'
    });
    panel.textContent = '';

    // Close button
    const closeBtn = document.createElement('button');
    Object.assign(closeBtn.style, {
        position: 'absolute', top: '12px', right: '12px', background: 'none',
        border: 'none', color: 'var(--text-muted)', fontSize: '20px',
        cursor: 'pointer', lineHeight: '1', padding: '4px'
    });
    closeBtn.textContent = '\u2715';
    closeBtn.addEventListener('click', hideEntityDetail);
    panel.appendChild(closeBtn);

    const content = document.createElement('div');
    content.style.padding = '20px';
    panel.appendChild(content);

    // Header
    const headerDiv = document.createElement('div');
    headerDiv.style.marginBottom = '16px';
    const badge = document.createElement('span');
    Object.assign(badge.style, {
        display: 'inline-block', padding: '2px 8px', borderRadius: '4px',
        background: cfg.color, color: '#000', fontSize: '11px',
        fontWeight: '700', marginBottom: '8px'
    });
    badge.textContent = cfg.label;
    headerDiv.appendChild(badge);

    const idEl = document.createElement('div');
    Object.assign(idEl.style, {
        fontSize: '16px', fontWeight: '700', color: 'var(--text-primary)',
        marginTop: '4px', wordBreak: 'break-all'
    });
    idEl.textContent = entityId;
    headerDiv.appendChild(idEl);

    if (entity.name) {
        const nameEl = document.createElement('div');
        Object.assign(nameEl.style, {
            fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px'
        });
        nameEl.textContent = entity.name;
        headerDiv.appendChild(nameEl);
    }

    if (entity.first_seen || entity.last_seen) {
        const dateEl = document.createElement('div');
        dateEl.style.cssText = 'font-size:12px;color:var(--text-muted);margin-top:4px';
        const from = entity.first_seen || '?';
        const to = entity.last_seen || 'ongoing';
        dateEl.textContent = from + ' \u2014 ' + to;
        headerDiv.appendChild(dateEl);
    }
    content.appendChild(headerDiv);

    // Phase
    if (entity.phase) {
        const phaseEl = document.createElement('div');
        Object.assign(phaseEl.style, {
            fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase',
            letterSpacing: '0.5px', marginBottom: '16px', padding: '4px 8px',
            background: 'var(--bg-secondary)', borderRadius: '4px', display: 'inline-block'
        });
        phaseEl.textContent = entity.phase;
        content.appendChild(phaseEl);
    }

    // Relationships
    if (entity.rels) {
        for (const [relType, relData] of Object.entries(entity.rels)) {
            // Skip kev boolean (v1.0 backward compat — kev is now top-level)
            if (relType === 'kev') continue;
            const relCfg = TYPE_CONFIG[relType] || { color: '#888', label: relType, relLabel: relType };
            const section = document.createElement('div');
            section.style.marginBottom = '16px';

            const secHeader = document.createElement('div');
            Object.assign(secHeader.style, {
                fontSize: '12px', fontWeight: '600', color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.5px',
                marginBottom: '6px', paddingBottom: '4px',
                borderBottom: '1px solid var(--border)'
            });
            secHeader.textContent = relCfg.relLabel;
            section.appendChild(secHeader);

            // Backward compat: v1.0 = array, v1.5 = {ids, source, tier}
            const ids = Array.isArray(relData) ? relData : (relData.ids || []);
            const limit = 10;
            const visible = ids.slice(0, limit);
            const overflow = ids.slice(limit);

            for (const rid of visible) {
                section.appendChild(createEntityLink(rid, relCfg.color));
            }

            if (overflow.length > 0) {
                const toggle = document.createElement('button');
                Object.assign(toggle.style, {
                    background: 'none', border: 'none', color: 'var(--accent)',
                    fontSize: '12px', cursor: 'pointer', padding: '4px 0', marginTop: '4px'
                });
                toggle.textContent = 'Show ' + overflow.length + ' more';
                let expanded = false;
                const overflowContainer = document.createElement('div');
                overflowContainer.style.display = 'none';
                for (const rid of overflow) {
                    overflowContainer.appendChild(createEntityLink(rid, relCfg.color));
                }
                toggle.addEventListener('click', () => {
                    expanded = !expanded;
                    overflowContainer.style.display = expanded ? 'block' : 'none';
                    toggle.textContent = expanded ? 'Show less' : 'Show ' + overflow.length + ' more';
                });
                section.appendChild(toggle);
                section.appendChild(overflowContainer);
            }
            content.appendChild(section);
        }
    }

    // Campaign timeline (APT groups only)
    if (entity.type === 'apt_group' && entity.rels && entity.rels.campaign) {
        const campaignData = entity.rels.campaign;
        const campaignIds = Array.isArray(campaignData) ? campaignData : (campaignData.ids || []);

        if (campaignIds.length > 0) {
            const timelineSection = document.createElement('div');
            timelineSection.style.marginBottom = '16px';

            const timelineHeader = document.createElement('div');
            Object.assign(timelineHeader.style, {
                fontSize: '12px', fontWeight: '600', color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.5px',
                marginBottom: '8px', paddingBottom: '4px',
                borderBottom: '1px solid var(--border)'
            });
            timelineHeader.textContent = 'Campaigns';
            timelineSection.appendChild(timelineHeader);

            const timeline = document.createElement('div');
            Object.assign(timeline.style, {
                position: 'relative', paddingLeft: '16px',
                borderLeft: '2px solid var(--border)'
            });

            const campaigns = campaignIds
                .map(cid => entityIndex.entities[cid])
                .filter(Boolean)
                .sort((a, b) => (b.first_seen || '').localeCompare(a.first_seen || ''));

            const colors = ['#ff6b6b', '#feca57', '#45b7d1', '#96ceb4', '#e056a0'];

            campaigns.forEach((camp, i) => {
                const entry = document.createElement('div');
                entry.style.marginBottom = '12px';
                entry.style.position = 'relative';

                const dot = document.createElement('div');
                Object.assign(dot.style, {
                    position: 'absolute', left: '-21px', top: '2px',
                    width: '10px', height: '10px', borderRadius: '50%',
                    background: colors[i % colors.length],
                    border: '2px solid var(--bg-card)'
                });
                entry.appendChild(dot);

                const nameEl = document.createElement('div');
                Object.assign(nameEl.style, {
                    fontSize: '12px', fontWeight: '600', color: 'var(--accent)',
                    cursor: 'pointer'
                });
                nameEl.textContent = camp.name || camp.id;
                nameEl.addEventListener('click', () => showEntityDetail(camp.id));
                entry.appendChild(nameEl);

                if (camp.first_seen || camp.last_seen) {
                    const dateEl = document.createElement('div');
                    dateEl.style.cssText = 'font-size:10px;color:var(--text-muted);margin-top:2px';
                    const from = camp.first_seen || '?';
                    const to = camp.last_seen || 'ongoing';
                    dateEl.textContent = from + ' \u2014 ' + to;
                    entry.appendChild(dateEl);
                }

                const techRels = camp.rels && camp.rels.technique;
                const techIds = Array.isArray(techRels) ? techRels : (techRels && techRels.ids || []);
                if (techIds.length > 0) {
                    const techRow = document.createElement('div');
                    techRow.style.cssText = 'display:flex;flex-wrap:wrap;gap:3px;margin-top:4px';
                    techIds.slice(0, 3).forEach(tid => {
                        const tag = document.createElement('span');
                        tag.style.cssText = 'font-size:9px;padding:1px 4px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:2px;color:var(--text-secondary);font-family:monospace;cursor:pointer';
                        tag.textContent = tid;
                        tag.addEventListener('click', (e) => { e.stopPropagation(); showEntityDetail(tid); });
                        techRow.appendChild(tag);
                    });
                    if (techIds.length > 3) {
                        const more = document.createElement('span');
                        more.style.cssText = 'font-size:9px;padding:1px 4px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:2px;color:var(--text-muted);font-family:monospace';
                        more.textContent = '+' + (techIds.length - 3);
                        techRow.appendChild(more);
                    }
                    entry.appendChild(techRow);
                }

                timeline.appendChild(entry);
            });

            timelineSection.appendChild(timeline);
            content.appendChild(timelineSection);
        }
    }

    // Provenance section
    if (entity.prov) {
        const provSection = document.createElement('div');
        provSection.style.cssText = 'margin-top:16px;padding-top:12px;border-top:2px solid var(--border)';

        const provHeader = document.createElement('div');
        provHeader.style.cssText = 'font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px';
        provHeader.textContent = 'Provenance';
        provSection.appendChild(provHeader);

        const TIER_COLORS = {
            official: { bg: '#1a3d1a', text: '#4ade80', label: 'OFFICIAL' },
            authoritative: { bg: '#1a2d4d', text: '#60a5fa', label: 'AUTHORITATIVE' },
            derived: { bg: '#3d2e0a', text: '#fbbf24', label: 'DERIVED' }
        };

        const entityLine = createProvLine(
            'Entity source', entity.prov.source,
            TIER_COLORS[entity.prov.tier] || TIER_COLORS.derived
        );
        provSection.appendChild(entityLine);

        if (entity.rels) {
            for (const [relType, relData] of Object.entries(entity.rels)) {
                if (!relData || Array.isArray(relData) || !relData.source) continue;
                const relCfg = TYPE_CONFIG[relType] || { relLabel: relType };
                const line = createProvLine(
                    relCfg.relLabel, relData.source,
                    TIER_COLORS[relData.tier] || TIER_COLORS.derived
                );
                provSection.appendChild(line);
            }
        }

        if (entity.kev) {
            const kevLine = createProvLine(
                'KEV Status', 'CISA KEV Catalog',
                TIER_COLORS.authoritative
            );
            provSection.appendChild(kevLine);
        }

        content.appendChild(provSection);
    }

    // Actions
    const actions = document.createElement('div');
    Object.assign(actions.style, {
        marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column', gap: '8px'
    });

    const pinned = getInvestigation();
    const isPinned = pinned.includes(entityId);
    const pinBtn = document.createElement('button');
    stylePrimaryButton(pinBtn);
    pinBtn.textContent = isPinned ? 'Unpin from Investigation' : 'Pin to Investigation';
    pinBtn.addEventListener('click', () => {
        if (getInvestigation().includes(entityId)) {
            unpinEntity(entityId);
            pinBtn.textContent = 'Pin to Investigation';
        } else {
            pinEntity(entityId);
            pinBtn.textContent = 'Unpin from Investigation';
        }
    });
    actions.appendChild(pinBtn);

    const extLink = buildExternalLink(entityId, entity.type);
    if (extLink) actions.appendChild(extLink);

    content.appendChild(actions);
}

function createEntityLink(entityId, dotColor) {
    const row = document.createElement('div');
    Object.assign(row.style, {
        padding: '4px 0', cursor: 'pointer', display: 'flex',
        alignItems: 'center', gap: '6px', fontSize: '13px',
        color: 'var(--accent)'
    });
    row.addEventListener('mouseenter', () => { row.style.opacity = '0.7'; });
    row.addEventListener('mouseleave', () => { row.style.opacity = '1'; });

    const dot = document.createElement('span');
    Object.assign(dot.style, {
        width: '6px', height: '6px', borderRadius: '50%',
        background: dotColor, flexShrink: '0'
    });
    row.appendChild(dot);

    const label = document.createElement('span');
    label.textContent = entityId;
    row.appendChild(label);

    row.addEventListener('click', () => showEntityDetail(entityId));
    return row;
}

function createProvLine(label, source, tierStyle) {
    const line = document.createElement('div');
    line.style.cssText = 'display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:4px';

    const dot = document.createElement('span');
    dot.style.cssText = 'width:8px;height:8px;border-radius:50%;flex-shrink:0;background:' + tierStyle.text;
    line.appendChild(dot);

    const labelEl = document.createElement('span');
    labelEl.style.color = 'var(--text-muted)';
    labelEl.textContent = label + ':';
    line.appendChild(labelEl);

    const sourceEl = document.createElement('span');
    sourceEl.style.cssText = 'color:' + tierStyle.text + ';font-weight:600';
    sourceEl.textContent = source;
    line.appendChild(sourceEl);

    const badge = document.createElement('span');
    badge.style.cssText = 'background:' + tierStyle.bg + ';color:' + tierStyle.text + ';padding:1px 6px;border-radius:3px;font-size:9px;font-weight:600';
    badge.textContent = tierStyle.label;
    line.appendChild(badge);

    return line;
}

function buildExternalLink(entityId, type) {
    let url = null;
    let text = null;
    if (type === 'cve') {
        url = 'https://nvd.nist.gov/vuln/detail/' + entityId;
        text = 'View on NVD';
    } else if (type === 'technique') {
        url = 'https://attack.mitre.org/techniques/' + entityId.replace(/\./g, '/') + '/';
        text = 'View on MITRE ATT&CK';
    } else if (type === 'apt_group') {
        url = 'https://attack.mitre.org/groups/' + entityId + '/';
        text = 'View on MITRE ATT&CK';
    } else if (type === 'cwe') {
        const num = entityId.replace(/\D/g, '');
        url = 'https://cwe.mitre.org/data/definitions/' + num + '.html';
        text = 'View on MITRE CWE';
    } else if (type === 'campaign') {
        url = 'https://attack.mitre.org/campaigns/' + entityId + '/';
        text = 'View on MITRE ATT&CK';
    }
    if (!url) return null;

    const a = document.createElement('a');
    Object.assign(a.style, {
        color: 'var(--accent)', fontSize: '13px', textDecoration: 'none',
        padding: '6px 0', display: 'inline-block'
    });
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = text + ' \u2197';
    return a;
}

function stylePrimaryButton(btn) {
    Object.assign(btn.style, {
        padding: '8px 16px', borderRadius: '6px', border: '1px solid var(--border)',
        background: 'var(--bg-secondary)', color: 'var(--text-primary)',
        fontSize: '13px', cursor: 'pointer', fontWeight: '500'
    });
    btn.addEventListener('mouseenter', () => { btn.style.borderColor = 'var(--accent)'; });
    btn.addEventListener('mouseleave', () => { btn.style.borderColor = 'var(--border)'; });
}

function hideEntityDetail() {
    const panel = document.getElementById('entity-panel');
    if (panel) panel.remove();
}

// ── Investigation State ─────────────────────────────────────────

function getInvestigation() {
    try {
        return JSON.parse(localStorage.getItem('tip-investigation')) || [];
    } catch { return []; }
}

function saveInvestigation(ids) {
    localStorage.setItem('tip-investigation', JSON.stringify(ids));
    updateInvestigationCount();
}

function pinEntity(entityId) {
    const ids = getInvestigation();
    if (!ids.includes(entityId)) {
        ids.push(entityId);
        saveInvestigation(ids);
    }
}

function unpinEntity(entityId) {
    const ids = getInvestigation().filter(id => id !== entityId);
    saveInvestigation(ids);
}

function updateInvestigationCount() {
    const toggle = document.getElementById('investigation-toggle');
    if (!toggle) return;
    const count = getInvestigation().length;
    let badge = toggle.querySelector('.inv-count');
    if (!badge) {
        badge = document.createElement('span');
        badge.className = 'inv-count';
        Object.assign(badge.style, {
            marginLeft: '4px', padding: '0 5px', borderRadius: '8px',
            background: 'var(--accent)', color: '#000', fontSize: '11px', fontWeight: '700'
        });
        toggle.appendChild(badge);
    }
    badge.textContent = count;
    badge.style.display = count > 0 ? 'inline-block' : 'none';
}

function showInvestigationTray() {
    let tray = document.getElementById('investigation-tray');
    if (tray) { tray.remove(); return; }

    const toggle = document.getElementById('investigation-toggle');
    tray = document.createElement('div');
    tray.id = 'investigation-tray';
    Object.assign(tray.style, {
        position: 'absolute', top: '100%', right: '0', width: '300px',
        maxHeight: '400px', overflowY: 'auto', background: 'var(--bg-card)',
        border: '1px solid var(--border)', borderRadius: '0 0 6px 6px',
        boxShadow: '0 8px 24px rgba(0,0,0,0.3)', zIndex: '250', padding: '8px 0'
    });

    const ids = getInvestigation();
    if (ids.length === 0) {
        const empty = document.createElement('div');
        Object.assign(empty.style, { padding: '16px', color: 'var(--text-muted)', fontSize: '13px', textAlign: 'center' });
        empty.textContent = 'No pinned entities';
        tray.appendChild(empty);
    } else {
        for (const id of ids) {
            const row = document.createElement('div');
            Object.assign(row.style, {
                padding: '6px 12px', display: 'flex', alignItems: 'center',
                justifyContent: 'space-between', fontSize: '13px'
            });
            const link = document.createElement('span');
            link.style.cursor = 'pointer';
            link.style.color = 'var(--accent)';
            link.textContent = id;
            link.addEventListener('click', () => { tray.remove(); showEntityDetail(id); });
            row.appendChild(link);

            const removeBtn = document.createElement('button');
            Object.assign(removeBtn.style, {
                background: 'none', border: 'none', color: 'var(--text-muted)',
                cursor: 'pointer', fontSize: '14px', padding: '2px 4px'
            });
            removeBtn.textContent = '\u2715';
            removeBtn.addEventListener('click', () => { unpinEntity(id); tray.remove(); showInvestigationTray(); });
            row.appendChild(removeBtn);
            tray.appendChild(row);
        }
    }

    // Footer actions
    const footer = document.createElement('div');
    Object.assign(footer.style, {
        padding: '8px 12px', borderTop: '1px solid var(--border)',
        display: 'flex', gap: '8px', justifyContent: 'flex-end'
    });

    const exportBtn = document.createElement('button');
    stylePrimaryButton(exportBtn);
    exportBtn.textContent = 'Export';
    exportBtn.style.fontSize = '12px';
    exportBtn.style.padding = '4px 12px';
    exportBtn.addEventListener('click', exportInvestigation);
    footer.appendChild(exportBtn);

    const importBtn = document.createElement('button');
    stylePrimaryButton(importBtn);
    importBtn.textContent = 'Import';
    importBtn.style.fontSize = '12px';
    importBtn.style.padding = '4px 12px';
    importBtn.addEventListener('click', () => {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        input.addEventListener('change', () => { if (input.files[0]) importInvestigation(input.files[0]); });
        input.click();
    });
    footer.appendChild(importBtn);
    tray.appendChild(footer);

    if (toggle && toggle.parentElement) {
        toggle.parentElement.style.position = 'relative';
        toggle.parentElement.appendChild(tray);
    } else {
        document.body.appendChild(tray);
    }
}

function exportInvestigation() {
    const ids = getInvestigation();
    const entities = {};
    for (const id of ids) {
        if (entityIndex && entityIndex.entities[id]) {
            entities[id] = entityIndex.entities[id];
        }
    }
    const data = { exported: new Date().toISOString(), entities };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const date = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = 'tip-investigation-' + date + '.json';
    a.click();
    URL.revokeObjectURL(url);
}

function importInvestigation(file) {
    const reader = new FileReader();
    reader.onload = function () {
        try {
            const data = JSON.parse(reader.result);
            const ids = Object.keys(data.entities || {});
            if (ids.length > 0) {
                saveInvestigation(ids);
            }
        } catch (e) {
            console.error('Invalid investigation file:', e);
        }
    };
    reader.readAsText(file);
}

// ── Initialization ──────────────────────────────────────────────

function initEntitySystem() {
    const searchInput = document.getElementById('global-search');
    const resultsContainer = document.getElementById('search-results');
    if (!searchInput || !resultsContainer) return;

    resultsContainer.style.display = 'none';
    searchInput.parentElement.style.position = 'relative';

    searchInput.addEventListener('focus', async () => {
        if (!entityIndex && !indicesLoading) {
            resultsContainer.textContent = '';
            const loading = document.createElement('div');
            Object.assign(loading.style, { padding: '12px 16px', color: 'var(--text-muted)', fontSize: '13px' });
            loading.textContent = 'Loading...';
            resultsContainer.appendChild(loading);
            showDropdown(resultsContainer);
            await loadIndices();
            if (!searchInput.value.trim()) hideDropdown(resultsContainer);
            else renderSearchResults(searchEntities(searchInput.value), resultsContainer);
        }
    });

    let debounce = null;
    searchInput.addEventListener('input', () => {
        clearTimeout(debounce);
        debounce = setTimeout(() => {
            const q = searchInput.value.trim();
            if (!q) { hideDropdown(resultsContainer); return; }
            if (!entityIndex) return;
            renderSearchResults(searchEntities(q), resultsContainer);
        }, 150);
    });

    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { hideDropdown(resultsContainer); searchInput.blur(); }
    });

    document.addEventListener('click', (e) => {
        if (!searchInput.contains(e.target) && !resultsContainer.contains(e.target)) {
            hideDropdown(resultsContainer);
        }
    });

    // Investigation toggle
    const invToggle = document.getElementById('investigation-toggle');
    if (invToggle) {
        invToggle.addEventListener('click', showInvestigationTray);
    }
    updateInvestigationCount();
}

document.addEventListener('DOMContentLoaded', initEntitySystem);
