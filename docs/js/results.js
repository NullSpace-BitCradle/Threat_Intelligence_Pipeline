/**
 * TIP Results — renders entity detail pages (header, summary, tabs, tab content).
 * Uses safe DOM methods throughout (textContent, createElement). No innerHTML.
 */

function renderResultPage(entityId) {
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

    main.textContent = '';
    renderEntityHeader(main, entity, related);
    renderSummaryCards(main, entity, related);
    renderDetailTabs(main, entity, related);
    renderGraphPanel(graphPanel, entityId, related);
}

function renderEntityHeader(container, entity, related) {
    const header = document.createElement('div');
    header.className = 'entity-header';

    // Entity ID
    const idEl = document.createElement('div');
    idEl.className = 'entity-id';
    idEl.textContent = entity.id;
    header.appendChild(idEl);

    // Description / name
    if (entity.name && entity.name !== entity.id) {
        const desc = document.createElement('div');
        desc.className = 'entity-desc';
        desc.textContent = entity.name;
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

function renderDetailTabs(container, entity, related) {
    const tabTypes = Object.entries(related).filter(([, r]) => r.ids.length > 0);

    if (tabTypes.length === 0) {
        const empty = document.createElement('div');
        Object.assign(empty.style, { color: 'var(--text-muted)', fontSize: '14px', padding: '20px 0' });
        empty.textContent = 'No framework relationships found for this entity.';
        container.appendChild(empty);
        return;
    }

    // Tab bar
    const tabBar = document.createElement('div');
    tabBar.className = 'detail-tabs';

    // Tab panels container
    const panelContainer = document.createElement('div');

    tabTypes.forEach(([relType, relData], index) => {
        const cfg = TYPE_CONFIG[relType] || { label: relType };

        // Tab button
        const tab = document.createElement('button');
        tab.className = 'detail-tab' + (index === 0 ? ' active' : '');

        const tabText = document.createTextNode(cfg.label || relType);
        tab.appendChild(tabText);

        const countSpan = document.createElement('span');
        countSpan.className = 'tab-count';
        countSpan.textContent = ' (' + relData.ids.length + ')';
        tab.appendChild(countSpan);

        tab.addEventListener('click', () => {
            tabBar.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            panelContainer.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            document.getElementById('tab-' + relType).classList.add('active');
        });
        tabBar.appendChild(tab);

        // Tab panel
        const panel = document.createElement('div');
        panel.id = 'tab-' + relType;
        panel.className = 'tab-panel' + (index === 0 ? ' active' : '');

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
