/**
 * TIP Results — renders entity detail pages (header, summary, tabs, tab content).
 * Uses safe DOM methods throughout (textContent, createElement). No innerHTML.
 */

async function renderResultPage(entityId) {
    const entity = getEntity(entityId);
    const main = document.getElementById('result-main');
    const graphPanel = document.getElementById('result-graph');

    if (!entity) {
        main.textContent = '';
        var msg = document.createElement('div');
        Object.assign(msg.style, { padding: '40px', textAlign: 'center', color: 'var(--text-muted)' });
        msg.textContent = 'Entity not found: ' + entityId;
        main.appendChild(msg);
        graphPanel.textContent = '';
        return;
    }

    const related = getRelatedEntities(entityId);
    const detail = await fetchEntityDetail(entityId);

    main.textContent = '';
    renderEntityHeader(main, entity, related);
    renderSummaryCards(main, entity, related);
    renderDetailTabs(main, entity, related, detail);
    renderGraphPanel(graphPanel, entityId, related);
}

function renderEntityHeader(container, entity, related) {
    const header = document.createElement('div');
    header.className = 'entity-header';

    // Entity ID (with optional external source link)
    const idEl = document.createElement('div');
    idEl.className = 'entity-id';
    const externalUrl = typeof buildExternalLink === 'function' ? buildExternalLink(entity) : null;
    if (externalUrl) {
        const idLink = document.createElement('a');
        idLink.href = externalUrl;
        idLink.target = '_blank';
        idLink.rel = 'noopener noreferrer';
        idLink.textContent = entity.id;
        idLink.title = 'View on source site';
        idLink.style.color = 'inherit';
        idLink.style.textDecoration = 'none';
        idLink.style.borderBottom = '1px dotted var(--text-muted)';
        idEl.appendChild(idLink);
    } else {
        idEl.textContent = entity.id;
    }
    header.appendChild(idEl);

    // Description block. Prefer the full description; fall back to the
    // short display name. Only render when distinct from the entity ID.
    const descText = entity.description || (entity.name !== entity.id ? entity.name : '');
    if (descText) {
        const desc = document.createElement('div');
        desc.className = 'entity-desc';
        desc.textContent = descText;
        header.appendChild(desc);
    }

    // Badge row
    const badges = document.createElement('div');
    badges.className = 'badge-row';

    // Type badge
    const typeBadge = document.createElement('span');
    typeBadge.className = 'badge';
    typeBadge.style.background = (GRAPH_COLORS[entity.type] || '#888') + '25';
    typeBadge.style.color = GRAPH_COLORS[entity.type] || 'var(--text-secondary)';
    typeBadge.textContent = (TYPE_CONFIG[entity.type] || {}).label || entity.type;
    badges.appendChild(typeBadge);

    // Severity / CVSS badge (CVE entities only)
    if (entity.type === 'cve' && typeof entity.cvss_score === 'number') {
        const sev = (entity.severity || '').toUpperCase();
        const palette = {
            CRITICAL: '#d63031',
            HIGH:     '#e17055',
            MEDIUM:   '#fdcb6e',
            LOW:      '#74b9ff',
            NONE:     '#888'
        };
        const color = palette[sev] || '#888';
        const sevBadge = document.createElement('span');
        sevBadge.className = 'badge';
        sevBadge.style.background = color + '25';
        sevBadge.style.color = color;
        const sevLabel = sev ? sev + ' ' : '';
        sevBadge.textContent = sevLabel + 'CVSS ' + entity.cvss_score.toFixed(1);
        if (entity.cvss_vector) sevBadge.title = entity.cvss_vector;
        badges.appendChild(sevBadge);
    }

    // Provenance badge
    if (entity.prov && entity.prov.tier) {
        const provBadge = document.createElement('span');
        provBadge.className = 'badge prov-' + entity.prov.tier;
        provBadge.textContent = entity.prov.tier;
        badges.appendChild(provBadge);
    }

    // Relationship count badges
    for (const [relType, relData] of Object.entries(related)) {
        if (relData.ids.length === 0) continue;
        const relCfg = TYPE_CONFIG[relType] || {};
        const badge = document.createElement('span');
        badge.className = 'badge';
        badge.style.background = (GRAPH_COLORS[relType] || '#888') + '20';
        badge.style.color = GRAPH_COLORS[relType] || 'var(--text-secondary)';
        badge.textContent = relData.ids.length + ' ' + (relCfg.label || relType);
        badges.appendChild(badge);
    }

    header.appendChild(badges);
    container.appendChild(header);
}

function renderSummaryCards(container, entity, related) {
    const grid = document.createElement('div');
    grid.className = 'summary-grid';
    const cards = [];

    for (const [relType, relData] of Object.entries(related)) {
        if (relData.ids.length === 0) continue;
        const relCfg = TYPE_CONFIG[relType] || { label: relType, relLabel: relType };
        cards.push({
            label: relCfg.relLabel || relCfg.label,
            value: String(relData.ids.length),
            detail: relData.source || '',
            color: GRAPH_COLORS[relType] || 'var(--text-primary)'
        });
    }

    if (entity.first_seen || entity.last_seen) {
        cards.push({
            label: 'Timeline',
            value: entity.first_seen || '?',
            detail: entity.last_seen ? 'to ' + entity.last_seen : 'ongoing',
            color: 'var(--text-primary)'
        });
    }

    if (entity.type === 'cve' && (entity.published || entity.last_modified)) {
        const pubShort = (entity.published || '').slice(0, 10);
        const modShort = (entity.last_modified || '').slice(0, 10);
        cards.push({
            label: 'Disclosed',
            value: pubShort || '?',
            detail: modShort && modShort !== pubShort ? 'modified ' + modShort : '',
            color: 'var(--text-primary)'
        });
    }

    if (entity.type === 'cve' && Array.isArray(entity.references) && entity.references.length > 0) {
        cards.push({
            label: 'References',
            value: String(entity.references.length),
            detail: 'NVD-linked URLs',
            color: 'var(--text-primary)'
        });
    }

    for (const card of cards) {
        const el = document.createElement('div');
        el.className = 'summary-card';

        const labelEl = document.createElement('div');
        labelEl.className = 'summary-card-label';
        labelEl.textContent = card.label;
        el.appendChild(labelEl);

        const valueEl = document.createElement('div');
        valueEl.className = 'summary-card-value';
        valueEl.style.color = card.color;
        valueEl.textContent = card.value;
        el.appendChild(valueEl);

        const detailEl = document.createElement('div');
        detailEl.className = 'summary-card-detail';
        detailEl.textContent = card.detail;
        el.appendChild(detailEl);

        grid.appendChild(el);
    }

    if (cards.length > 0) container.appendChild(grid);
}

function renderDetailTabs(container, entity, related, detail) {
    const tabTypes = Object.entries(related).filter(([, r]) => r.ids.length > 0);

    // Tab bar
    const tabBar = document.createElement('div');
    tabBar.className = 'detail-tabs';

    // Tab panels container
    const panelContainer = document.createElement('div');

    // Helper to wire tab clicks
    function wireTab(tab, panelId) {
        tab.addEventListener('click', function() {
            tabBar.querySelectorAll('.detail-tab').forEach(function(t) { t.classList.remove('active'); });
            tab.classList.add('active');
            panelContainer.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.remove('active'); });
            document.getElementById(panelId).classList.add('active');
        });
    }

    // ── Overview tab (always first) ──
    var overviewTab = document.createElement('button');
    overviewTab.className = 'detail-tab active';
    overviewTab.textContent = 'Overview';
    wireTab(overviewTab, 'tab-overview');
    tabBar.appendChild(overviewTab);

    var overviewPanel = document.createElement('div');
    overviewPanel.id = 'tab-overview';
    overviewPanel.className = 'tab-panel active';
    renderOverviewContent(overviewPanel, entity, detail);
    panelContainer.appendChild(overviewPanel);

    // ── Framework relationship tabs ──
    tabTypes.forEach(([relType, relData]) => {
        const cfg = TYPE_CONFIG[relType] || { label: relType };

        // Tab button
        const tab = document.createElement('button');
        tab.className = 'detail-tab';

        const tabText = document.createTextNode(cfg.label || relType);
        tab.appendChild(tabText);

        const countSpan = document.createElement('span');
        countSpan.className = 'tab-count';
        countSpan.textContent = ' (' + relData.ids.length + ')';
        tab.appendChild(countSpan);

        wireTab(tab, 'tab-' + relType);
        tabBar.appendChild(tab);

        // Tab panel
        const panel = document.createElement('div');
        panel.id = 'tab-' + relType;
        panel.className = 'tab-panel';

        const list = document.createElement('div');
        list.className = 'entity-card-list';

        for (const relEntity of relData.entities) {
            const card = document.createElement('div');
            card.className = 'entity-card';
            card.addEventListener('click', () => {
                window.location.hash = '#/' + relEntity.type + '/' + relEntity.id;
            });

            const left = document.createElement('div');

            const idSpan = document.createElement('div');
            idSpan.className = 'entity-card-id';
            idSpan.textContent = relEntity.id;
            left.appendChild(idSpan);

            if (relEntity.name && relEntity.name !== relEntity.id) {
                const nameSpan = document.createElement('div');
                nameSpan.className = 'entity-card-name';
                nameSpan.textContent = relEntity.name;
                left.appendChild(nameSpan);
            }

            card.appendChild(left);

            // Provenance badge
            if (relData.tier) {
                const prov = document.createElement('span');
                prov.className = 'prov-badge prov-' + relData.tier;
                prov.textContent = relData.tier;
                card.appendChild(prov);
            }

            list.appendChild(card);
        }

        panel.appendChild(list);
        panelContainer.appendChild(panel);
    });

    container.appendChild(tabBar);
    container.appendChild(panelContainer);
}

function renderMarkdownText(container, text) {
    // Strip (Citation: ...) references
    var cleaned = text.replace(/\(Citation:[^)]*\)/g, '');

    // Parse [text](url) markdown links into segments
    var parts = cleaned.split(/(\[[^\]]+\]\(https?:\/\/[^)]+\))/g);

    for (var i = 0; i < parts.length; i++) {
        var part = parts[i];
        var linkMatch = part.match(/^\[([^\]]+)\]\((https?:\/\/[^)]+)\)$/);
        if (linkMatch) {
            var a = document.createElement('a');
            a.textContent = linkMatch[1];
            a.href = linkMatch[2];
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.style.color = 'var(--accent)';
            a.style.textDecoration = 'none';
            container.appendChild(a);
        } else if (part) {
            container.appendChild(document.createTextNode(part));
        }
    }
}

function renderOverviewContent(panel, entity, detail) {
    var content = document.createElement('div');
    content.className = 'overview-content';

    // Description (from detail DB or entity name)
    var desc = (detail && detail.description) ? detail.description : null;
    if (desc) {
        var descSection = document.createElement('div');
        descSection.className = 'overview-section';

        var descLabel = document.createElement('div');
        descLabel.className = 'overview-label';
        descLabel.textContent = 'Description';
        descSection.appendChild(descLabel);

        var descText = document.createElement('div');
        descText.className = 'overview-text';
        renderMarkdownText(descText, desc);
        descSection.appendChild(descText);

        content.appendChild(descSection);
    }

    // Type-specific fields
    if (entity.type === 'apt_group' && detail && detail.aliases && detail.aliases.length > 0) {
        var aliasSection = document.createElement('div');
        aliasSection.className = 'overview-section';

        var aliasLabel = document.createElement('div');
        aliasLabel.className = 'overview-label';
        aliasLabel.textContent = 'Also Known As';
        aliasSection.appendChild(aliasLabel);

        var aliasList = document.createElement('div');
        aliasList.className = 'overview-aliases';
        for (var i = 0; i < detail.aliases.length; i++) {
            var chip = document.createElement('span');
            chip.className = 'overview-alias-chip';
            chip.textContent = detail.aliases[i];
            aliasList.appendChild(chip);
        }
        aliasSection.appendChild(aliasList);
        content.appendChild(aliasSection);
    }

    if (entity.type === 'technique' && detail && detail.framework) {
        addOverviewField(content, 'Framework', detail.framework.charAt(0).toUpperCase() + detail.framework.slice(1));
    }

    if (entity.type === 'cve' && detail && detail.kev) {
        var kev = detail.kev;
        addOverviewField(content, 'Vendor / Product', (kev.vendorProject || '') + ' ' + (kev.product || ''));
        addOverviewField(content, 'KEV Date Added', kev.dateAdded || '');
        addOverviewField(content, 'Remediation Due', kev.dueDate || '');
        addOverviewField(content, 'Ransomware Use', kev.knownRansomwareCampaignUse || 'Unknown');
        if (kev.requiredAction) {
            addOverviewField(content, 'Required Action', kev.requiredAction);
        }
    }

    if (entity.type === 'cwe' && detail && detail.parents && detail.parents.length > 0) {
        var parentSection = document.createElement('div');
        parentSection.className = 'overview-section';

        var parentLabel = document.createElement('div');
        parentLabel.className = 'overview-label';
        parentLabel.textContent = 'Parent Weaknesses';
        parentSection.appendChild(parentLabel);

        for (var p = 0; p < detail.parents.length; p++) {
            var parentLink = document.createElement('span');
            parentLink.className = 'overview-entity-link';
            parentLink.textContent = detail.parents[p];
            (function(pid) {
                parentLink.addEventListener('click', function() {
                    navigateToEntity(pid);
                });
            })(detail.parents[p]);
            parentSection.appendChild(parentLink);
        }
        content.appendChild(parentSection);
    }

    if ((entity.type === 'campaign') && (entity.first_seen || entity.last_seen)) {
        addOverviewField(content, 'First Seen', entity.first_seen || 'Unknown');
        addOverviewField(content, 'Last Seen', entity.last_seen || 'Ongoing');
    }

    // Campaign timeline for APT group entities: list related campaigns
    // sorted by first_seen, showing date range and technique count.
    if (entity.type === 'apt_group') {
        const relatedCampaigns = [];
        const groupRels = (getRelatedEntities(entity.id) || {});
        const campaignRel = groupRels.campaign || { entities: [] };
        for (const camp of (campaignRel.entities || [])) {
            if (!camp) continue;
            const campRels = getRelatedEntities(camp.id) || {};
            relatedCampaigns.push({
                id: camp.id,
                name: camp.name || camp.id,
                first_seen: camp.first_seen || '',
                last_seen: camp.last_seen || '',
                technique_count: (campRels.technique && campRels.technique.ids)
                    ? campRels.technique.ids.length : 0
            });
        }
        if (relatedCampaigns.length > 0) {
            relatedCampaigns.sort(function(a, b) {
                return (a.first_seen || '').localeCompare(b.first_seen || '');
            });

            const timelineSection = document.createElement('div');
            timelineSection.className = 'overview-section';

            const timelineLabel = document.createElement('div');
            timelineLabel.className = 'overview-label';
            timelineLabel.textContent = 'Campaign Timeline';
            timelineSection.appendChild(timelineLabel);

            const timeline = document.createElement('div');
            timeline.className = 'campaign-timeline';

            for (const camp of relatedCampaigns) {
                const entry = document.createElement('div');
                entry.className = 'campaign-timeline-entry';
                entry.style.padding = '8px 0';
                entry.style.borderLeft = '2px solid var(--accent)';
                entry.style.paddingLeft = '12px';
                entry.style.marginBottom = '6px';
                entry.style.cursor = 'pointer';
                entry.addEventListener('click', (function(id) {
                    return function() { navigateToEntity(id); };
                })(camp.id));

                const idLine = document.createElement('div');
                idLine.style.fontWeight = '600';
                idLine.style.color = 'var(--accent)';
                idLine.textContent = camp.id + ' - ' + camp.name;
                entry.appendChild(idLine);

                const metaLine = document.createElement('div');
                metaLine.style.fontSize = '0.85em';
                metaLine.style.color = 'var(--text-muted)';
                const range = (camp.first_seen || '?') +
                    (camp.last_seen ? ' to ' + camp.last_seen : ' (ongoing)');
                const techPart = camp.technique_count > 0
                    ? ' | ' + camp.technique_count + ' techniques'
                    : '';
                metaLine.textContent = range + techPart;
                entry.appendChild(metaLine);

                timeline.appendChild(entry);
            }
            timelineSection.appendChild(timeline);
            content.appendChild(timelineSection);
        }
    }

    // Provenance
    if (entity.prov) {
        var provSection = document.createElement('div');
        provSection.className = 'overview-section';

        var provLabel = document.createElement('div');
        provLabel.className = 'overview-label';
        provLabel.textContent = 'Data Source';
        provSection.appendChild(provLabel);

        var provText = document.createElement('div');
        provText.className = 'overview-text';
        provText.textContent = (entity.prov.source || 'Unknown') + ' (' + (entity.prov.tier || 'unknown') + ' tier)';
        provSection.appendChild(provText);

        content.appendChild(provSection);
    }

    // If no detail at all, show a minimal message
    if (content.children.length === 0) {
        var noDetail = document.createElement('div');
        Object.assign(noDetail.style, { color: 'var(--text-muted)', fontSize: '13px', padding: '12px 0' });
        noDetail.textContent = 'No additional detail available for this entity.';
        content.appendChild(noDetail);
    }

    panel.appendChild(content);
}

function addOverviewField(container, label, value) {
    if (!value || !value.trim()) return;
    var section = document.createElement('div');
    section.className = 'overview-field';

    var labelEl = document.createElement('span');
    labelEl.className = 'overview-field-label';
    labelEl.textContent = label;
    section.appendChild(labelEl);

    var valueEl = document.createElement('span');
    valueEl.className = 'overview-field-value';
    valueEl.textContent = value;
    section.appendChild(valueEl);

    container.appendChild(section);
}

function renderGraphPanel(panel, entityId, related) {
    panel.textContent = '';

    // Graph header
    const header = document.createElement('div');
    header.className = 'graph-header';
    header.textContent = 'Relationship Map';
    panel.appendChild(header);

    // Graph container
    const graphEl = document.createElement('div');
    graphEl.className = 'graph-container';
    panel.appendChild(graphEl);

    // Render the D3 graph
    renderGraph(graphEl, entityId);

    // Related entities lists
    for (const [relType, relData] of Object.entries(related)) {
        if (relData.ids.length === 0) continue;
        const cfg = TYPE_CONFIG[relType] || { label: relType, relLabel: relType };
        const color = GRAPH_COLORS[relType] || '#888';

        const section = document.createElement('div');
        section.className = 'related-section';

        const label = document.createElement('div');
        label.className = 'related-label';
        label.textContent = cfg.relLabel || cfg.label;
        section.appendChild(label);

        const MAX_VISIBLE = 5;
        const idsToShow = relData.ids.slice(0, MAX_VISIBLE);

        for (const relId of idsToShow) {
            const relEntity = getEntity(relId);
            if (!relEntity) continue;

            const item = document.createElement('div');
            item.className = 'related-item';
            item.addEventListener('click', () => {
                window.location.hash = '#/' + relEntity.type + '/' + relId;
            });

            const dot = document.createElement('div');
            dot.className = 'related-dot';
            dot.style.background = color;
            item.appendChild(dot);

            const idSpan = document.createElement('span');
            idSpan.className = 'related-id';
            idSpan.textContent = relId;
            item.appendChild(idSpan);

            if (relEntity.name && relEntity.name !== relId) {
                const nameSpan = document.createElement('span');
                nameSpan.className = 'related-name';
                nameSpan.textContent = relEntity.name;
                item.appendChild(nameSpan);
            }

            section.appendChild(item);
        }

        if (relData.ids.length > MAX_VISIBLE) {
            const more = document.createElement('div');
            more.className = 'related-more';
            more.textContent = '+ ' + (relData.ids.length - MAX_VISIBLE) + ' more';
            section.appendChild(more);
        }

        panel.appendChild(section);
    }
}
