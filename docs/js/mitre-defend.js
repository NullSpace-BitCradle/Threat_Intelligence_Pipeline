// ===== MITRE D3FEND FUNCTIONS =====

/**
 * Render a D3FEND matrix with BIG group headers + nested sub-groups + leaf tiles.
 */
async function renderDefendMatrix(scoreTable = {}) {
    // fetch
    let raw;
    try { 
        raw = await fetch('https://d3fend.mitre.org/api/matrix.json').then(r => r.json()); 
    }
    catch(e){ 
        console.error('D3FEND fetch failed', e); 
        return; 
    }

    // Helpers
    const labelOf = n => n?.['rdfs:label'] || n?.name || (n?.['@id']||'').split(':').pop();
    const kidsOf  = n => Array.isArray(n?.children) ? n.children : [];

    // Detect the top-level columns
    const top = Array.isArray(raw) ? raw : (Array.isArray(raw?.tactics) ? raw.tactics : (Array.isArray(raw?.columns) ? raw.columns : []));
    if (!top.length) return;

    // Keep official column order
    const ORDER = ["Model","Harden","Detect","Isolate","Deceive","Evict","Restore"];
    top.sort((a,b)=> ORDER.indexOf(labelOf(a)) - ORDER.indexOf(labelOf(b)));

    // Build a hierarchical view:
    const toGroups = (nodes) => {
        const out = [];
        nodes.forEach(n => {
            const hasChildren = kidsOf(n).length > 0;
            const id = n['d3f:d3fend-id'];

            if (hasChildren) {
                // treat as a (sub)group even if it also has an ID
                out.push({
                    type: 'group',
                    title: labelOf(n),
                    items: toGroups(kidsOf(n))
                });
            } else if (id) {
                out.push({ type:'tech', id, title: labelOf(n) });
            }
        });
        return out;
    };

    const columns = top.map(col => ({
        tactic: labelOf(col),
        groups: toGroups(kidsOf(col))
    }));

    // Enhanced heat palette with more gradual transitions - lighter colors
    const max = Math.max(...Object.values(scoreTable), 1);
    const heat = v => {
        if (!v) return 'transparent';
        const t = Math.min(v/max, 1);
        
        // Multi-step gradient: light yellow → light orange → light red → medium red
        if (t <= 0.25) {
            const localT = t / 0.25;
            return `hsl(${60 - 5*localT}, ${70 + 10*localT}%, ${95 - 5*localT}%)`;
        } else if (t <= 0.5) {
            const localT = (t - 0.25) / 0.25;
            return `hsl(${55 - 15*localT}, 80%, ${90 - 10*localT}%)`;
        } else if (t <= 0.75) {
            const localT = (t - 0.5) / 0.25;
            return `hsl(${40 - 10*localT}, 85%, ${80 - 10*localT}%)`;
        } else {
            const localT = (t - 0.75) / 0.25;
            return `hsl(${30 - 10*localT}, ${85 - 5*localT}%, ${70 - 10*localT}%)`;
        }
    };

    // Calculate statistics
    const totalTechniques = Object.keys(scoreTable).length;
    const totalHits = Object.values(scoreTable).reduce((sum, score) => sum + score, 0);

    // render
    const host = document.getElementById('defend_matrix');
    if (!host) return;
    host.innerHTML = '';

    // Add summary legend at the top
    const summaryDiv = document.createElement('div');
    summaryDiv.style.cssText = `
        width: 100%;
        margin-bottom: 16px; 
        padding: 12px; 
        background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%); 
        border-radius: 8px; 
        border-left: 4px solid #2196f3;
        font-family: 'Roboto', sans-serif;
        display: block;
    `;
    summaryDiv.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
            <div>
                <h4 style="margin: 0; color: #1565c0; font-weight: 600;">🛡️ MITRE D3FEND Matrix</h4>
                <p style="margin: 4px 0 0 0; color: #424242; font-size: 14px;">Defensive countermeasures mapped to your CVE analysis</p>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 14px; color: #424242;">
                    <strong>${totalTechniques}</strong> techniques affected • <strong>${totalHits}</strong> total hits
                </div>
                <div style="margin-top: 8px;">
                    <span id="defend-selected-count" style="font-size: 12px; color: #1565c0; font-weight: 500;">0 selected</span>
                    <button id="defend-generate-subgraph" class="btn btn-primary btn-sm" style="margin-left: 8px; font-size: 11px; padding: 4px 8px;" disabled>Generate Sub-graph</button>
                    <button id="defend-clear-selection" class="btn btn-outline-secondary btn-sm" style="margin-left: 4px; font-size: 11px; padding: 4px 8px;">Clear Selection</button>
                </div>
            </div>
        </div>
    `;
    host.appendChild(summaryDiv);

    // Matrix container directly after summary
    const matrixContainer = document.createElement('div');
    matrixContainer.style.cssText = `
        display: flex;
        align-items: flex-start;
        gap: var(--col-gap);
        overflow-x: auto;
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 8px;
        padding: 16px 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    `;

    // Helper function to count subcategories with hits vs total
    const countSubcategoriesWithHits = (group) => {
        let totalSubcategories = 0;
        let subcategoriesWithHits = 0;
        
        for (const item of group.items) {
            if (item.type === 'tech') {
                totalSubcategories++;
                if (scoreTable[item.id] && scoreTable[item.id] > 0) {
                    subcategoriesWithHits++;
                }
            } else if (item.type === 'group') {
                totalSubcategories++;
                if (groupHasHits(item)) {
                    subcategoriesWithHits++;
                }
            }
        }
        
        return { total: totalSubcategories, withHits: subcategoriesWithHits };
    };

    // Helper function to check if a group has any hits
    const groupHasHits = (group) => {
        for (const item of group.items) {
            if (item.type === 'tech') {
                if (scoreTable[item.id] && scoreTable[item.id] > 0) {
                    return true;
                }
            } else if (item.type === 'group') {
                if (groupHasHits(item)) {
                    return true;
                }
            }
        }
        return false;
    };

    const renderGroup = (wrap, group, depth=0) => {
        const hasHits = groupHasHits(group);
        const subcategoryStats = countSubcategoriesWithHits(group);
        
        // group header avec bouton expand/collapse
        const gh = document.createElement('div');
        gh.className = `d3f-group d-depth-${Math.min(depth,3)}`;
        gh.style.cssText = `
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background: ${hasHits ? 'linear-gradient(135deg, #f1f3f4 0%, #e8eaed 100%)' : 'transparent'};
            border: ${hasHits ? '1px solid #ced4da' : '1px solid #e9ecef'};
            border-left: ${hasHits ? '4px solid #0d6efd' : '4px solid #dee2e6'};
        `;
        
        const leftSection = document.createElement('div');
        leftSection.style.cssText = `
            display: flex;
            flex-direction: column;
            flex: 1;
        `;
        
        const groupTitle = document.createElement('span');
        groupTitle.textContent = group.title;
        groupTitle.style.cssText = `
            font-weight: 700;
            font-size: 12px;
        `;
        leftSection.appendChild(groupTitle);
        
        // Afficher le ratio des sous-catégories impactées en texte coloré
        if (subcategoryStats.total > 0 && subcategoryStats.withHits > 0) {
            const ratioText = document.createElement('span');
            ratioText.textContent = `${subcategoryStats.withHits}/${subcategoryStats.total} affected`;
            ratioText.style.cssText = `
                color: #28a745;
                font-size: 10px;
                font-weight: 500;
                margin-top: 2px;
            `;
            leftSection.appendChild(ratioText);
        }
        
        gh.appendChild(leftSection);
        
        const expandBtn = document.createElement('button');
        expandBtn.innerHTML = hasHits ? '▼' : '▶';
        expandBtn.className = 'expand-btn';
        expandBtn.style.cssText = `
            background: none;
            border: none;
            color: inherit;
            font-size: 12px;
            cursor: pointer;
            padding: 2px 6px;
            border-radius: 3px;
            transition: transform 0.2s ease;
        `;
        gh.appendChild(expandBtn);
        
        wrap.appendChild(gh);

        // container pour les éléments enfants
        const childrenContainer = document.createElement('div');
        childrenContainer.className = 'children-container';
        childrenContainer.style.display = hasHits ? 'block' : 'none'; // déplié si hits
        
        // children 
        group.items.forEach(item => {
            if (item.type === 'tech') {
                const hits = scoreTable[item.id] || 0;
                const tile = document.createElement('div');
                tile.className = 'd3f-tile' + (hits ? '' : ' empty');
                tile.dataset.score = hits;
                tile.dataset.techId = item.id;
                tile.style.setProperty('--bg', heat(hits));
                
                // Enhanced tooltip
                const percentage = max > 0 ? Math.round((hits / max) * 100) : 0;
                tile.title = `${item.id} - ${item.title}\n${hits || 'No'} hits (${percentage}% of max)\nClick to select/deselect`;

                const label = document.createElement('span');
                label.textContent = item.title;
                tile.appendChild(label);

                // Add selection functionality
                tile.style.cursor = 'pointer';
                tile.style.transition = 'all 0.2s ease';
                
                tile.addEventListener('click', (e) => {
                    e.stopPropagation();
                    toggleDefendTechSelection(item.id, tile);
                });

                // indent tiles to match group depth (keeps the visual hierarchy)
                if (depth > 0) tile.style.marginLeft = `${Math.min(depth,2)*16}px`;

                childrenContainer.appendChild(tile);
            } else {
                renderGroup(childrenContainer, item, depth+1);
            }
        });
        
        wrap.appendChild(childrenContainer);
        
        // Gestionnaire de clic pour expand/collapse
        gh.onclick = (e) => {
            e.stopPropagation();
            const isExpanded = childrenContainer.style.display !== 'none';
            
            if (isExpanded) {
                childrenContainer.style.display = 'none';
                expandBtn.innerHTML = '▶';
                expandBtn.style.transform = 'rotate(0deg)';
            } else {
                childrenContainer.style.display = 'block';
                expandBtn.innerHTML = '▼';
                expandBtn.style.transform = 'rotate(0deg)';
            }
        };
    };

    columns.forEach(col => {
        // column wrapper
        const wrap = document.createElement('div');
        wrap.className = 'd3f-col';

        // tactic header 
        const head = document.createElement('div');
        head.className = 'd3f-head';
        head.textContent = col.tactic;
        
        // Add tactic description on hover
        const tacticDescriptions = {
            'Model': 'Modeling and analysis of system behavior',
            'Harden': 'Techniques to strengthen system defenses',
            'Detect': 'Identification of threats and anomalies',
            'Isolate': 'Containment and quarantine measures',
            'Deceive': 'Deception and misdirection tactics',
            'Evict': 'Removal of threats from the system',
            'Restore': 'Recovery and restoration procedures'
        };
        
        head.title = tacticDescriptions[col.tactic] || 'Defensive tactic';
        wrap.appendChild(head);

        // groups
        col.groups.forEach(g => renderGroup(wrap, g, 0));

        matrixContainer.appendChild(wrap);
    });

    host.appendChild(matrixContainer);
    
    // Add event listeners for buttons after matrix is created
    setupDefendMatrixEventListeners();
}

// D3FEND selection management
let selectedDefendTechs = new Set();

function toggleDefendTechSelection(techId, tileElement) {
    if (selectedDefendTechs.has(techId)) {
        // Deselect
        selectedDefendTechs.delete(techId);
        tileElement.style.border = '';
        tileElement.style.boxShadow = '';
        tileElement.style.transform = '';
    } else {
        // Select
        selectedDefendTechs.add(techId);
        tileElement.style.border = '2px solid #2196f3';
        tileElement.style.boxShadow = '0 0 8px rgba(33, 150, 243, 0.5)';
        tileElement.style.transform = 'scale(1.05)';
    }
    
    updateDefendSelectionUI();
}

function updateDefendSelectionUI() {
    const countElement = document.getElementById('defend-selected-count');
    const generateBtn = document.getElementById('defend-generate-subgraph');
    
    if (countElement) {
        const count = selectedDefendTechs.size;
        countElement.textContent = `${count} selected`;
    }
    
    if (generateBtn) {
        generateBtn.disabled = selectedDefendTechs.size === 0;
    }
}

function clearDefendSelection() {
    // Clear visual selection
    document.querySelectorAll('.d3f-tile').forEach(tile => {
        tile.style.border = '';
        tile.style.boxShadow = '';
        tile.style.transform = '';
    });
    
    // Clear selection set
    selectedDefendTechs.clear();
    updateDefendSelectionUI();
}

function setupDefendMatrixEventListeners() {
    const generateBtn = document.getElementById('defend-generate-subgraph');
    const clearBtn = document.getElementById('defend-clear-selection');
    
    if (generateBtn) {
        generateBtn.addEventListener('click', async () => {
            if (selectedDefendTechs.size > 0) {
                await defend_selection(Array.from(selectedDefendTechs));
                // Only show modal if we have data
                try {
                    const chartOption = modal_chart.getOption();
                    const hasData = chartOption && 
                                    chartOption.series && 
                                    chartOption.series[0] && 
                                    chartOption.series[0].data && 
                                    chartOption.series[0].data.length > 0;
                    
                    if (hasData) {
                        show_modal();
                    }
                } catch (error) {
                    console.error('Error checking chart data:', error);
                }
            }
        });
    }
    
    if (clearBtn) {
        clearBtn.addEventListener('click', clearDefendSelection);
    }
}
