/**
 * TIP Relationship Graph — D3 force-directed layout
 * Renders entity connections in the right panel.
 */

const GRAPH_COLORS = {
    cve: '#ef4444',
    cwe: '#6366f1',
    capec: '#8b5cf6',
    technique: '#f97316',
    apt_group: '#a855f7',
    defend: '#14b8a6',
    owasp: '#f59e0b',
    campaign: '#e056a0'
};

const GRAPH_NODE_SIZES = {
    center: 26,
    primary: 16,
    secondary: 12
};

function renderGraph(container, entityId, overrideEntity, overrideRelated) {
    // Clear previous graph
    while (container.firstChild) container.removeChild(container.firstChild);

    // Accept a pre-synthesized entity and related map so shard-sourced CVE
    // detail pages can render a graph even though the CVE is not in the
    // curated entity_index. Fall back to index lookups otherwise.
    const entity = overrideEntity || getEntity(entityId);
    if (!entity) return;

    const related = overrideRelated || getRelatedEntities(entityId);
    const nodes = [];
    const links = [];
    const nodeSet = new Set();

    // Center node
    nodes.push({
        id: entityId,
        name: entity.name || entityId,
        type: entity.type,
        r: GRAPH_NODE_SIZES.center,
        isCenter: true
    });
    nodeSet.add(entityId);

    // Related nodes (limit per type to prevent clutter)
    const MAX_PER_TYPE = 8;
    for (const [relType, relData] of Object.entries(related)) {
        const ids = relData.ids.slice(0, MAX_PER_TYPE);
        for (const relId of ids) {
            if (nodeSet.has(relId)) continue;
            const relEntity = getEntity(relId);
            // When the related target is not in entity_index, synthesize a
            // minimal node from the rel_type label so the graph still
            // renders the shape of the relationship set.
            const effectiveEntity = relEntity || { name: relId, type: relType };
            nodeSet.add(relId);
            nodes.push({
                id: relId,
                name: effectiveEntity.name || relId,
                type: effectiveEntity.type || relType,
                r: GRAPH_NODE_SIZES.primary
            });
            links.push({ source: entityId, target: relId });
        }
    }

    if (nodes.length <= 1) {
        var msg = document.createElement('div');
        Object.assign(msg.style, {
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            height: '100%', color: 'var(--text-muted)', fontSize: '13px'
        });
        msg.textContent = 'No relationships found';
        container.appendChild(msg);
        return;
    }

    const width = container.clientWidth;
    const height = container.clientHeight || 300;

    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .attr('viewBox', [0, 0, width, height]);

    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(80))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.r + 4));

    const link = svg.append('g')
        .selectAll('line')
        .data(links)
        .join('line')
        .attr('stroke', 'var(--border)')
        .attr('stroke-width', 1)
        .attr('stroke-opacity', 0.6);

    const node = svg.append('g')
        .selectAll('g')
        .data(nodes)
        .join('g')
        .style('cursor', 'pointer')
        .on('click', (event, d) => {
            if (!d.isCenter) {
                window.location.hash = '#/' + d.type + '/' + d.id;
            }
        });

    node.append('circle')
        .attr('r', d => d.r)
        .attr('fill', d => GRAPH_COLORS[d.type] || '#888')
        .attr('fill-opacity', d => d.isCenter ? 1 : 0.85)
        .attr('stroke', d => d.isCenter ? 'var(--text-primary)' : 'none')
        .attr('stroke-width', d => d.isCenter ? 2 : 0);

    node.append('text')
        .text(d => {
            const label = d.id.length > 12 ? d.id.slice(0, 10) + '..' : d.id;
            return label;
        })
        .attr('text-anchor', 'middle')
        .attr('dy', d => d.r + 14)
        .attr('font-size', '9px')
        .attr('fill', 'var(--text-muted)')
        .attr('font-family', 'var(--font-mono)');

    // Tooltip on hover
    node.append('title')
        .text(d => d.id + (d.name !== d.id ? ' \u2014 ' + d.name : ''));

    simulation.on('tick', () => {
        // Keep nodes within bounds
        nodes.forEach(d => {
            d.x = Math.max(d.r, Math.min(width - d.r, d.x));
            d.y = Math.max(d.r, Math.min(height - d.r, d.y));
        });

        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
    });

    // Stop simulation after settling
    simulation.on('end', () => simulation.stop());
}
