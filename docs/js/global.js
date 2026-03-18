// ===== GLOBAL VARIABLES AND INITIALIZATION =====
var data_cleaned = [];
const fullScreenIcon = 'image://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAsTAAALEwEAmpwYAAACvUlEQVR4nO3dTW7TUBQF4MeP2AJjkAAJKIxYAIvINqL4nHrsFUEpqFL52wRsggmCYgQtIAU94QGqSFLa93xukvNJHuf43Loe+MpOyczMzMzMzMzMbEORnFc+jgA8n81m92qdw+7u7gOSr0ge1z6ftAEDmQ9H3zTNToX8jwCcjHUepfMrBzIH8LJC/ndjnkPp/OqBnEwmkyulsk+n0+tj5vdAVvBALv4XdpgKA/DeV8j5htGTvF96IE3TPCb5zf+yzn7f+Exyn+Td0sP4ayg7JN8A+L7x95C0ZajuQx4gGHkf8gDByPuQBwhG3oc8QDDyPuQBgpH3IQ8QjLwPeYBg5H3IAwQj70MeIBh5H/IAwcj7kAcIRt6HPEAw8j7kAYKR9yEPEIy8D3mAYOR9DA+QFgX4lLYMyQ+L+gDwpXqAvMS2ZCD7acsAeLKkj73qAfJG4fC8+/SP9zW3DaNq2/ZWvhIW9HFzlBD5mXReYiP5Y9gCPKyxkLAu2ra9A+Dt0MdPAK+bpnk4epC8xFZykW3ddV13reu6q+ocZmZmZmZmZmZmZmZmZmZmdkp+oO8lhwB9ALidV11I/sqHbO0lCGkf+YcWLcrVeANcdPI+SB4sWZ18kbYM1X0A+LokQJ+2DNR9yNfvg5H3IQ8QjLwPeYBg5H3IAwQj70MeIBh5H/IAwcj7kAcIRt6HPEAw8j7kAYKR9yEPEIy8D3mAYOR9yAMEI+9DHiAYeR/yAMHI+5AHCEbehzxAMPI+VgUocPQAntZ8T0h+J8vwEp2j2ueTNmAg83zk10DVGMrw7ZB/PQP3QM5QwkHpgQzfLxxlGBt1hfDPcdx13eVS2fPOVH5jjwdygYGklC55IEGuEADPUmHDe778L+scJXzMG4GlB+Kb+v8Poh++0nYjVZK/AJd/Y8ULPdfjpm5mZmZmZmZmqZ7frkDXeF36/ksAAAAASUVORK5CYII=';
var chart = echarts.init(document.getElementById('container'), null, {
    renderer: 'svg'
});
var modal_chart = echarts.init(document.getElementById('subgraph'), null, {
    renderer: 'svg'
});
window.addEventListener('resize', modal_chart.resize);
window.addEventListener('resize', chart.resize);
document.getElementById('modal').addEventListener('shown.bs.modal', function () {
    modal_chart.resize();
});
var chart_nodes = [];
var chart_links = [];
var selected_techniques = [];
var selected_defend_techniques = [];

// ===== UTILITY FUNCTIONS =====

// Avoid Copy/Paste formatting in contenteditable div
document.querySelector('[contenteditable]').addEventListener('paste', function (event) {
    event.preventDefault();
    document.execCommand('inserttext', false, event.clipboardData.getData('text/plain'));
});

document.querySelector("#layer_type").addEventListener('change', function () {
    adapt();
});

document.addEventListener('DOMContentLoaded', function () {
    check_param();

    var contentEditableElements = document.querySelectorAll('[contenteditable]');

    // Function to check if the element is empty and clear it
    function checkAndClear(element) {
        if (!element.textContent.trim().length) {
            element.innerHTML = '';
        }
    }

    contentEditableElements.forEach(function (element) {
        checkAndClear(element);

        element.addEventListener('focusout', function () {
            checkAndClear(element);
        });
    });
});

// ===== URL PARAMETER HANDLING =====

async function adapt() {
    var layer_type = document.getElementById('layer_type').value
    var cves = document.getElementById('cves').innerText.trim().replace(/\n/g, ',');
    var cves_gzip = await compress(cves, 'gzip');
    var cves_b64 = btoa(String.fromCharCode.apply(null, new Uint8Array(cves_gzip)));
    history.pushState({}, '', `?layer=${layer_type}&input=${cves_b64}`);
}

async function check_param() {
    var url_params = new URLSearchParams(window.location.search);
    var cves_param = url_params.get('input');
    var layer_param = url_params.get('layer');
    if (layer_param) {
        document.getElementById('layer_type').value = layer_param;
    }
    if (cves_param) {
        var cves_b64 = atob(cves_param);
        var cves_gzip = new Uint8Array(cves_b64.split('').map(c => c.charCodeAt(0)));
        var cves = await decompress(cves_gzip, 'gzip');
        document.getElementById('cves').innerText = cves.replace(/,/g, '\n');

        await process(true);
    }
}

// ===== COMPRESSION UTILITIES =====

// Gzip compression
function compress(string, encoding) {
    const byteArray = new TextEncoder().encode(string);
    const cs = new CompressionStream(encoding);
    const writer = cs.writable.getWriter();
    writer.write(byteArray);
    writer.close();
    return new Response(cs.readable).arrayBuffer();
}

// Gzip decompression
function decompress(byteArray, encoding) {
    const cs = new DecompressionStream(encoding);
    const writer = cs.writable.getWriter();
    writer.write(byteArray);
    writer.close();
    return new Response(cs.readable).arrayBuffer().then(function (arrayBuffer) {
        return new TextDecoder().decode(arrayBuffer);
    });
}

// Resilient fetch helper: try multiple URLs, fallback to local
async function fetchWithFallback(urls, parseAsText = false) {
    for (const url of urls) {
        try {
            const response = await fetch(url);
            if (!response || !response.ok) continue;
            return parseAsText ? await response.text() : await response.json();
        } catch (e) {
            // try next
        }
    }
    throw new Error('All data sources failed: ' + urls.join(' | '));
}

// ===== MAIN PROCESSING FUNCTION =====

async function process(page_load = false) {
    // clear all data are not CVE-XXXX-XXXX format
    var cvesElement = document.getElementById('cves');

    var cves = document.getElementById('cves').innerText.trim();
    var cvesArray = cves.split('\n').map(cve => cve.trim()).filter(cve => /^CVE-\d{4}-\d{4,}$/.test(cve));
    cves = cvesArray.join('\n');
    cvesElement.innerText = cves;

    if (!cves) {
        if (page_load) { // Do not show the alert if it's not a page load
            chart.hideLoading();
            return;
        }
        Swal.fire({
            icon: 'warning',
            title: 'No CVEs found',
            text: 'Please enter some CVEs.',
        });
        chart.hideLoading();
        return;
    }

    chart.showLoading();
    const defendScore = {};
    const modeSelect = document.getElementById('layer_type').value;
    const wantDefend = (modeSelect === 'enterprise-defend');   // true / false
    const attackDomain = (modeSelect === 'enterprise-defend')
        ? 'enterprise'
        : modeSelect;

    let techniquesAssoc = {}, cweDataRaw, capecDataRaw, defendText = '';
    try {
        cweDataRaw = await fetchWithFallback([
            'data/cwe_db.json'
        ]);
        capecDataRaw = await fetchWithFallback([
            'data/capec_db.json'
        ]);
        if (wantDefend) {
            defendText = await fetchWithFallback([
                'data/defend_db.jsonl'
            ], true);
        }
    } catch (error) {
        console.error(error);
        Swal.fire({
            icon: 'error',
            title: 'An error occurred',
            text: 'Failed to fetch required databases',
        });
        chart.hideLoading();
        return;
    }
    // Techniques association is optional (only needed for mobile/ICS domain mapping)
    try {
        techniquesAssoc = await fetchWithFallback(['data/techniques_association.json']);
    } catch (e) {
        console.log('Techniques association file not available, cross-domain mapping disabled');
    }

    let defendList = {};
    if (defendText) {
        try {
            // Try parsing as a single JSON object first (current format)
            defendList = JSON.parse(defendText);
        } catch (_) {
            // Fallback: try JSONL (one JSON object per line)
            defendText.split('\n').forEach(line => {
                if (line.trim()) {
                    try {
                        Object.assign(defendList, JSON.parse(line));
                    } catch (e) {
                        console.warn('Skipping invalid JSONL line in defend_db:', e.message);
                    }
                }
            });
        }
    }

    data_cleaned = new Set();
    var cves_not_found = [];

    // Group by year
    var cves_list = cvesArray.reduce((acc, cve) => {
        const year = cve.split('-')[1];
        (acc[year] = acc[year] || []).push(cve);
        return acc;
    }, {});

    var data = [];

    for (var [year, yearCves] of Object.entries(cves_list)) {
        var database;
        try {
            var responseText = await fetchWithFallback([
                `database/CVE-${year}.jsonl`
            ], true);
            database = {};
            responseText.split('\n').forEach(line => {
                if (line.trim()) {
                    try {
                        const lineData = JSON.parse(line);
                        // Format: {"CVE-ID": {"CWE": [...], ...}}
                        Object.assign(database, lineData);
                    } catch (parseError) {
                        console.error('Error parsing JSON line:', line, parseError);
                    }
                }
            });
        } catch (error) {
            console.error(error);
            Swal.fire({
                icon: 'error',
                title: 'An error occurred',
                text: 'Failed to fetch the database for year ' + year,
            });
            continue; // Skip this year if there is an error
        }

        yearCves.forEach(cve => {
            var cveData = database[cve];
            if (!cveData) {
                cves_not_found.push(cve);
                return;
            }

            cveData.CWE.forEach(cwe => {
                // Handle both "CWE-287" and "287" formats
                var cweId = cwe;
                var cweNumber = cwe;
                
                if (cwe.startsWith('CWE-')) {
                    cweNumber = cwe.substring(4); // Remove "CWE-" prefix for lookup
                    cweId = cwe; // Keep full ID for display
                } else {
                    cweNumber = cwe;
                    cweId = 'CWE-' + cwe;
                }
                
                data.push({ source: cve, target: cweId, value: 1 });
                var relatedCapecs = cweDataRaw[cweNumber]?.RelatedAttackPatterns || [];
                relatedCapecs.forEach(capec => {
                    data.push({ source: cweId, target: 'CAPEC-' + capec, value: 1 });
                    
                    // Check if CAPEC data and techniques exist
                    var techniquesString = capecDataRaw[capec]?.techniques;
                    if (!techniquesString) {
                        return; // Skip if no techniques data
                    }
                    
                    var lines = techniquesString.split("NAME:ATTACK:ENTRY ");
                    var relatedTechniques = new Set();
                    
                    for (var i = 1; i < lines.length; i++) {
                        var technique_id = lines[i].split(":")[1];
                        
                        // Handle different ATT&CK domains
                        if (attackDomain === "ics") {
                            technique_id = techniquesAssoc[technique_id]?.ics;
                        } else if (attackDomain === "mobile") {
                            technique_id = techniquesAssoc[technique_id]?.mobile;
                        }
                        // For enterprise, use the technique_id as-is
                        
                        if (technique_id) {
                            relatedTechniques.add(technique_id);
                        }
                    }
                    
                    relatedTechniques.forEach(technique => {
                        data.push({ source: 'CAPEC-' + capec, target: 'T' + technique, value: 1 });
                    });
                    
                    relatedTechniques.forEach(technique => {
                        const atkKey = 'T' + technique;
                        const defTechniques = defendList[atkKey]?.defensive_techniques || [];
                        defTechniques.forEach(d => {
                            data.push({ source: atkKey, target: 'D3F-' + d.id, value: 1 });
                        });
                    });
                });
            })
            
            // Process OWASP categories
            if (cveData.OWASP && cveData.OWASP.length > 0) {
                cveData.OWASP.forEach(owasp => {
                    data.push({ source: cve, target: 'OWASP-' + owasp, value: 1 });
                });
            }
        })
    }

    data.forEach(l => {
        if (l.target.startsWith('D3F-')) {
            const id = l.target.slice(4);
            defendScore[id] = (defendScore[id] || 0) + 1;
        }
    });

    data.forEach(node => {
        key = node.source;
        if (!data_cleaned.has(key)) {
            data_cleaned.add(key);
        } else {
            var existingNode = Array.from(data_cleaned).find(n => n.source === node.source && n.target === node.target);
            if (existingNode) {
                existingNode.value++;
            }
        }
    });

    var chartNodes = new Set();
    data.forEach(link => {
        chartNodes.add(link.source);
        chartNodes.add(link.target);
    });
    var chartLinks = Array.from(data);

    chart_nodes = Array.from(chartNodes).map(node => {
        let nodeStyle = { name: node };
        
        // Add styling based on node type
        if (node.startsWith('CVE-')) {
            nodeStyle.itemStyle = { color: '#ff6b6b' }; // Red for CVEs
        } else if (node.startsWith('CWE-')) {
            nodeStyle.itemStyle = { color: '#4ecdc4' }; // Teal for CWEs
        } else if (node.startsWith('CAPEC-')) {
            nodeStyle.itemStyle = { color: '#45b7d1' }; // Blue for CAPEC
        } else if (node.startsWith('T')) {
            nodeStyle.itemStyle = { color: '#96ceb4' }; // Green for Techniques
        } else if (node.startsWith('D3F-')) {
            nodeStyle.itemStyle = { color: '#feca57' }; // Yellow for D3FEND
        } else if (node.startsWith('OWASP-')) {
            nodeStyle.itemStyle = { color: '#ff9ff3' }; // Pink for OWASP
        }
        
        return nodeStyle;
    })
    chart_links = data

    var option = {
        tooltip: {
            trigger: 'item',
            triggerOn: 'mousemove',
            textStyle: {
                fontSize: 12
            },
            formatter: function (params) {
                if (params.dataType === 'node') {
                    let nodeName = params.data.name;
                    let nodeValue = params.value || 'N/A';
                    let incomingNodes = data
                        .filter(link => link.target === nodeName)
                        .map(link => link.source)
                        .join('<br/>- ');
                    let outgoingNodes = data
                        .filter(link => link.source === nodeName)
                        .map(link => link.target)
                        .join('<br/>- ');

                    var ret = `<b>${nodeName} (${nodeValue})</b><hr class="hr-tooltip" />`;
                    if (incomingNodes) {
                        ret += `<u>From:</u><br>- ${incomingNodes}<br>`;
                    }
                    if (outgoingNodes) {
                        ret += `<u>To:</u><br>- ${outgoingNodes}`;
                    }
                    return ret;
                } else {
                    return `${params.data.source} → ${params.data.target}: ${params.data.value}`;
                }
            }
        },
        animation: false,
        toolbox: {
            show: true,
            feature: {
                saveAsImage: {
                    show: true,
                    title: 'Save as image',
                    type: 'png',
                    name: 'Threat Intelligence Pipeline - CVEs Data Flow',
                    backgroundColor: '#fff',
                },
                restore: {
                    show: true,
                    title: 'Restore',
                },
                myFullScreen: {
                    show: true,
                    title: 'Fullscreen',
                    icon: fullScreenIcon,
                    onclick: function () {
                        if (document.fullscreenElement) {
                            document.exitFullscreen();
                        } else {
                            document.getElementById('container').requestFullscreen();
                        }
                    }
                }
            }
        },
        series: {
            type: 'sankey',
            emphasis: {
                focus: 'trajectory',
            },
            nodeAlign: 'center',
            nodeWidth: 24,
            nodeGap: 10,
            layoutIterations: 64,
            label: {
                fontSize: 13,
                fontWeight: 500,
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
                textBorderColor: 'transparent',
            },
            data: chart_nodes,
            links: chart_links,
            lineStyle: {
                color: 'source',
                curveness: 0.5
            }
        }
    }

    if (option && typeof option === 'object') {
        // Scale container height based on node count
        var nodeCount = chart_nodes.length;
        var minHeight = 450;
        var dynamicHeight = Math.max(minHeight, nodeCount * 28);
        document.getElementById('container').style.height = dynamicHeight + 'px';
        chart.resize();
        chart.setOption(option);
    }
    var cvesUrlEncoded = btoa(String.fromCharCode.apply(null, new Uint8Array(await compress(cvesArray.join(','), 'gzip'))));
    history.pushState({}, '', `?layer=${document.getElementById('layer_type').value}&input=${cvesUrlEncoded}`);

    await create_mitre_layer();

    if (cves_not_found.length > 0) {
        Swal.fire({
            icon: 'warning',
            title: 'Some CVEs not found',
            text: 'The following CVEs were not found in the database: ' + cves_not_found.join(', '),
        });
    }

    // Entity system: click Sankey nodes to show entity detail
    chart.off('click');
    chart.on('click', function(params) {
        if (params.dataType === 'node' && typeof showEntityDetail === 'function') {
            var name = params.data.name;
            // Strip D3F- prefix for D3FEND IDs in entity system
            if (name.startsWith('D3F-')) name = name.slice(4);
            // Strip OWASP- prefix for OWASP IDs in entity system
            if (name.startsWith('OWASP-')) name = name.slice(6);
            showEntityDetail(name);
        }
    });

    chart.hideLoading();

    await print_mitre();

    // Update statistics
    updateAttackStats();

    if (wantDefend) {
        document.getElementById('defend_matrix').style.display = '';
        var defendEmpty = document.getElementById('defend-empty');
        if (defendEmpty) defendEmpty.style.display = 'none';
        renderDefendMatrix(defendScore);
    }

    // Update OWASP stats and display
    updateOwaspStats();

    // Update analysis summary cards
    updateAnalysisSummary(cvesArray, chart_nodes);
}

// ===== UTILITY FUNCTIONS =====

async function example() {
    document.getElementById('cves').innerText = 'CVE-2024-37079\nCVE-2018-17924';
    await process();
    await print_mitre();
}

// Function to display the selected techniques executed by iframe
// See L-5642 and from L-9336 in main.js
async function mitre_selection(techniques, selection = false, technique_id = null) {
    var selected = new Set();
    techniques.forEach(function (element) {
        var technique = element.split('^')[0];
        selected.add(technique);
    });
    selected_techniques = Array.from(selected);
    show_selected(selection, technique_id);
}

// Function to handle D3FEND technique selection
async function defend_selection(techniques) {
    selected_defend_techniques = techniques;
    show_defend_selected();
}

async function show_defend_selected() {
    var data_link = new Set();
    var nodes = new Set();

    // Get attack techniques and links that lead to selected D3FEND techniques
    selected_defend_techniques.forEach(defendTech => {
        const defendKey = 'D3F-' + defendTech;
        
        chart_links.forEach(link => {
            if (link.target === defendKey) {
                data_link.add(link);
                // Get the attack technique that leads to this defense
                const attackTech = link.source;
                
                // Get all links for this attack technique (backward tracing)
                chart_links.forEach(innerLink => {
                    if (innerLink.target === attackTech) {
                        data_link.add(innerLink);
                        
                        // Get CAPEC links
                        if (innerLink.source.startsWith('CAPEC-')) {
                            chart_links.forEach(capecLink => {
                                if (capecLink.target === innerLink.source) {
                                    data_link.add(capecLink);
                                    
                                    // Get CWE links
                                    if (capecLink.source.startsWith('CWE-')) {
                                        chart_links.forEach(cweLink => {
                                            if (cweLink.target === capecLink.source) {
                                                data_link.add(cweLink);
                                            }
                                        });
                                    }
                                }
                            });
                        }
                    }
                });
            }
        });
    });

    // Get all nodes from links
    data_link.forEach(link => {
        nodes.add(link.source);
        nodes.add(link.target);
    });

    var option = {
        tooltip: {
            trigger: 'item',
            triggerOn: 'mousemove',
            textStyle: {
                fontSize: 12
            },
            formatter: function (params) {
                if (params.dataType === 'node') {
                    let nodeName = params.data.name;
                    let nodeValue = params.value || 'N/A';
                    let incomingNodes = Array.from(data_link)
                        .filter(link => link.target === nodeName)
                        .map(link => link.source)
                        .join('<br/>- ');
                    let outgoingNodes = Array.from(data_link)
                        .filter(link => link.source === nodeName)
                        .map(link => link.target)
                        .join('<br/>- ');
                    var ret = `<b>${nodeName} (${nodeValue})</b><hr class="hr-tooltip" />`;
                    if (incomingNodes) {
                        ret += `<u>From:</u><br>- ${incomingNodes}<br>`;
                    }
                    if (outgoingNodes) {
                        ret += `<u>To:</u><br>- ${outgoingNodes}`;
                    }
                    return ret;
                } else {
                    return `${params.data.source} → ${params.data.target}: ${params.data.value}`;
                }
            }
        },
        animation: false,
        toolbox: {
            show: true,
            feature: {
                saveAsImage: {
                    show: true,
                    title: 'Save as image',
                    type: 'png',
                    backgroundColor: '#fff',
                },
                restore: {
                    show: true,
                    title: 'Restore',
                },
                myFullScreen: {
                    show: true,
                    title: 'Fullscreen',
                    icon: fullScreenIcon,
                    onclick: function () {
                        if (document.fullscreenElement) {
                            document.exitFullscreen();
                        } else {
                            document.getElementById('subgraph').requestFullscreen();
                        }
                    }
                }
            }
        },
        series: {
            type: 'sankey',
            emphasis: {
                focus: 'trajectory',
            },
            nodeAlign: 'center',
            nodeWidth: 24,
            nodeGap: 10,
            layoutIterations: 64,
            label: {
                fontSize: 13,
                fontWeight: 500,
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
                textBorderColor: 'transparent',
            },
            data: [],
            links: [],
            lineStyle: {
                color: 'source',
                curveness: 0.5
            }
        }
    }

    // If no data found, show a warning 
    if (nodes.size === 0 || data_link.size === 0) {
        new Notify({
            status: 'error',
            title: 'Error!',
            text: 'No D3FEND techniques selected !',
            effect: 'fade',
            speed: 300,
            customClass: null,
            customIcon: null,
            showIcon: true,
            showCloseButton: true,
            autoclose: true,
            autotimeout: 3000,
            gap: 20,
            distance: 20,
            type: 1,
            position: 'right top'
        });
        // Set empty option to ensure chart is properly initialized
        option.series.data = [];
        option.series.links = [];
        modal_chart.setOption(option);
    } else {
        option.series.data = Array.from(nodes).map(node => ({ name: node }));
        option.series.links = Array.from(data_link);
        modal_chart.setOption(option);
    }
}

async function show_selected(selection, technique_id) {
    var data_link = new Set();
    var nodes = new Set();

    var option = {
        tooltip: {
            trigger: 'item',
            triggerOn: 'mousemove',
            textStyle: {
                fontSize: 12
            },
            formatter: function (params) {
                if (params.dataType === 'node') {
                    let nodeName = params.data.name;
                    let nodeValue = params.value || 'N/A';
                    let incomingNodes = chart_links
                        .filter(link => link.target === nodeName)
                        .map(link => link.source)
                        .join('<br/>- ');
                    let outgoingNodes = chart_links
                        .filter(link => link.source === nodeName)
                        .map(link => link.target)
                        .join('<br/>- ');
                    var ret = `<b>${nodeName} (${nodeValue})</b><hr class="hr-tooltip" />`;
                    if (incomingNodes) {
                        ret += `<u>From:</u><br>- ${incomingNodes}<br>`;
                    }
                    if (outgoingNodes) {
                        ret += `<u>To:</u><br>- ${outgoingNodes}`;
                    }
                    return ret;
                } else {
                    return `${params.data.source} → ${params.data.target}: ${params.data.value}`;
                }
            }
        },
        animation: false,
        toolbox: {
            show: true,
            feature: {
                saveAsImage: {
                    show: true,
                    title: 'Save as image',
                    type: 'png',
                    backgroundColor: '#fff',
                },
                restore: {
                    show: true,
                    title: 'Restore',
                },
                myFullScreen: {
                    show: true,
                    title: 'Fullscreen',
                    icon: fullScreenIcon,
                    onclick: function () {
                        if (document.fullscreenElement) {
                            document.exitFullscreen();
                        } else {
                            document.getElementById('subgraph').requestFullscreen();
                        }
                    }
                }
            }
        },
        series: {
            type: 'sankey',
            emphasis: {
                focus: 'trajectory',
            },
            nodeAlign: 'center',
            nodeWidth: 24,
            nodeGap: 10,
            layoutIterations: 64,
            label: {
                fontSize: 13,
                fontWeight: 500,
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
                textBorderColor: 'transparent',
            },
            data: [],
            links: [],
            lineStyle: {
                color: 'source',
                curveness: 0.5
            }
        }
    }
    if (option && typeof option === 'object') {
        modal_chart.setOption(option);
    }

    // Get CAPEC and CWE data from Technoques
    selected_techniques.forEach(technique => {
        const capecs = new Set();
        const cwes = new Set();

        chart_links.forEach(element => {
            if (element.target === technique) {
                data_link.add(element);
                if (element.source.startsWith('CAPEC-')) {
                    capecs.add(element.source);
                }
            }
        });

        capecs.forEach(capec => {
            chart_links.forEach(element => {
                if (element.target === capec) {
                    data_link.add(element);
                    if (element.source.startsWith('CWE-')) {
                        cwes.add(element.source);
                    }
                }
            });
        });

        cwes.forEach(cwe => {
            chart_links.forEach(element => {
                if (element.target === cwe) {
                    data_link.add(element);
                }
            });
        });
    });

    // Get all nodes from links
    data_link.forEach(link => {
        nodes.add(link.source);
        nodes.add(link.target);
    });

    // If no data found, show a warning 
    if (nodes.size === 0 || data_link.size === 0) {
        if (selection && technique_id) {
            new Notify({
                status: 'error',
                title: 'Error!',
                text: 'No technique selected !',
                effect: 'fade',
                speed: 300,
                customClass: null,
                customIcon: null,
                showIcon: true,
                showCloseButton: true,
                autoclose: true,
                autotimeout: 3000,
                gap: 20,
                distance: 20,
                type: 1,
                position: 'right top'
            })
        }
        modal_chart.setOption({
            series: {
                data: [],
                links: []
            }
        });
    } else {
        modal_chart.setOption({
            series: {
                data: Array.from(nodes).map(node => ({ name: node })),
                links: Array.from(data_link)
            }
        });
    }
}

async function show_modal() {
    var modal = new bootstrap.Modal(document.getElementById('modal'));
    
    // Check if modal chart has been initialized and has data
    try {
        const chartOption = modal_chart.getOption();
        const hasData = chartOption && 
                        chartOption.series && 
                        chartOption.series[0] && 
                        chartOption.series[0].data && 
                        chartOption.series[0].data.length > 0;
        
        if (!hasData) {
            Swal.fire({
                icon: 'warning',
                title: 'No data selected',
                text: 'Please select some techniques first.',
            });
            return;
        }
    } catch (error) {
        console.error('Error checking modal chart data:', error);
        Swal.fire({
            icon: 'warning',
            title: 'No data available',
            text: 'Please select some techniques first.',
        });
        return;
    }
    
    modal.show();
}

async function share() {
    // copy url to clipboard
    var url = window.location.href;
    navigator.clipboard.writeText(url).then(function () {
        new Notify({
            status: 'success',
            title: 'Success!',
            text: 'URL copied to clipboard',
            effect: 'fade',
            speed: 300,
            customClass: null,
            customIcon: null,
            showIcon: true,
            showCloseButton: true,
            autoclose: true,
            autotimeout: 3000,
            gap: 20,
            distance: 20,
            type: 1,
            position: 'right top'
        });
    }, function (err) {
        console.error('Failed to copy: ', err);
        new Notify({
            status: 'error',
            title: 'Error!',
            text: 'Failed to copy URL to clipboard',
            effect: 'fade',
            speed: 300,
            customClass: null,
            customIcon: null,
            showIcon: true,
            showCloseButton: true,
            autoclose: true,
            autotimeout: 3000,
            gap: 20,
            distance: 20,
            type: 1,
            position: 'right top'
        });
    });
}

async function fullscreen() {
    // check if fullscreen mode is available
    if (document.fullscreenEnabled ||
        document.webkitFullscreenEnabled ||
        document.mozFullScreenEnabled ||
        document.msFullscreenEnabled) {
        // check if fullscreen mode is active
        if (document.fullscreenElement ||
            document.webkitFullscreenElement ||
            document.mozFullScreenElement ||
            document.msFullscreenElement) {
            // exit fullscreen mode
            if (document.exitFullscreen) {
                document.exitFullscreen();
            } else if (document.webkitExitFullscreen) {
                document.webkitExitFullscreen();
            } else if (document.mozCancelFullScreen) {
                document.mozCancelFullScreen();
            } else if (document.msExitFullscreen) {
                document.msExitFullscreen();
            }
        } else {
            // enter fullscreen mode
            if (document.documentElement.requestFullscreen) {
                document.documentElement.requestFullscreen();
            } else if (document.documentElement.webkitRequestFullscreen) {
                document.documentElement.webkitRequestFullscreen();
            } else if (document.documentElement.mozRequestFullScreen) {
                document.documentElement.mozRequestFullScreen();
            } else if (document.documentElement.msRequestFullscreen) {
                document.documentElement.msRequestFullscreen();
            }
        }
    }
    else {
        new Notify({
            status: 'error',
            title: 'Error!',
            text: 'Fullscreen mode is not supported by this browser',
            effect: 'fade',
            speed: 300,
            customClass: null,
            customIcon: null,
            showIcon: true,
            showCloseButton: true,
            autoclose: true,
            autotimeout: 3000,
            gap: 20,
            distance: 20,
            type: 1,
            position: 'right top'
        });
    }
}

// ===== OWASP VISUALIZATION FUNCTIONS =====

function updateOwaspStats() {
    // Count OWASP nodes in the chart
    const owaspNodes = chart_nodes.filter(n => n.name && n.name.startsWith('OWASP-'));
    
    if (owaspNodes.length > 0) {
        // Show OWASP summary banner in analysis view
        document.getElementById('owasp-summary').style.display = '';
        document.getElementById('owasp-categories-count').textContent = owaspNodes.length;

        // Hide the empty state in OWASP view
        var owaspEmpty = document.getElementById('owasp-empty');
        if (owaspEmpty) owaspEmpty.style.display = 'none';

        // Collect OWASP data for the matrix
        const owaspData = {};
        owaspNodes.forEach(node => {
            const owaspId = node.name;
            const links = chart_links.filter(link => link.target === owaspId);
            owaspData[owaspId] = {
                count: links.length,
                sources: links.map(link => link.source)
            };
        });

        // Render the OWASP matrix
        renderOwaspMatrix(owaspData);
    } else {
        document.getElementById('owasp-summary').style.display = 'none';
    }
}

function renderOwaspMatrix(owaspData) {
    const matrixContainer = document.getElementById('owasp_matrix');
    const legendContainer = document.getElementById('owasp-legend');
    
    // Validate DOM elements exist
    if (!matrixContainer || !legendContainer) {
        console.error('OWASP matrix containers not found in DOM');
        return;
    }
    
    if (!owaspData || Object.keys(owaspData).length === 0) {
        matrixContainer.style.display = 'none';
        legendContainer.style.display = 'none';
        return;
    }
    
    // Show the containers
    matrixContainer.style.display = '';
    legendContainer.style.display = '';
    
    // OWASP category information
    const owaspCategories = {
        'A01:2021': { name: 'Broken Access Control', icon: '🔓', color: '#ff6b6b' },
        'A02:2021': { name: 'Cryptographic Failures', icon: '🔐', color: '#4ecdc4' },
        'A03:2021': { name: 'Injection', icon: '💉', color: '#45b7d1' },
        'A04:2021': { name: 'Insecure Design', icon: '📐', color: '#96ceb4' },
        'A05:2021': { name: 'Security Misconfiguration', icon: '⚙️', color: '#ffeaa7' },
        'A06:2021': { name: 'Vulnerable and Outdated Components', icon: '📦', color: '#dfe6e9' },
        'A07:2021': { name: 'Identification and Authentication Failures', icon: '🔑', color: '#74b9ff' },
        'A08:2021': { name: 'Software and Data Integrity Failures', icon: '✅', color: '#a29bfe' },
        'A09:2021': { name: 'Security Logging and Monitoring Failures', icon: '📊', color: '#fd79a8' },
        'A10:2021': { name: 'Server-Side Request Forgery', icon: '🌐', color: '#fdcb6e' }
    };
    
    // Build HTML for the matrix
    let html = '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; padding: 16px;">';
    
    // Sort OWASP categories by ID
    const sortedOwaspIds = Object.keys(owaspData).sort();
    
    sortedOwaspIds.forEach(owaspId => {
        const categoryId = owaspId.replace('OWASP-', '');
        const categoryInfo = owaspCategories[categoryId];
        const data = owaspData[owaspId];
        
        if (!categoryInfo) return;
        
        html += `
            <div style="
                border: 2px solid ${categoryInfo.color};
                border-radius: 8px;
                padding: 16px;
                background: linear-gradient(135deg, ${categoryInfo.color}15 0%, ${categoryInfo.color}05 100%);
                transition: transform 0.2s, box-shadow 0.2s;
                cursor: pointer;
            " onmouseover="this.style.transform='translateY(-4px)'; this.style.boxShadow='0 4px 12px rgba(0,0,0,0.1)';"
               onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='none';">
                <div style="display: flex; align-items: center; margin-bottom: 12px;">
                    <span style="font-size: 32px; margin-right: 12px;">${categoryInfo.icon}</span>
                    <div style="flex: 1;">
                        <div style="font-weight: 600; color: #2d3436; font-size: 14px;">${categoryId}</div>
                        <div style="font-weight: 700; color: #2d3436; font-size: 16px; margin-top: 4px;">${categoryInfo.name}</div>
                    </div>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 12px; padding-top: 12px; border-top: 1px solid ${categoryInfo.color}40;">
                    <span style="color: #636e72; font-size: 14px;">Affected CVEs:</span>
                    <span style="
                        background: ${categoryInfo.color};
                        color: white;
                        padding: 4px 12px;
                        border-radius: 12px;
                        font-weight: 700;
                        font-size: 14px;
                    ">${data.count}</span>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    
    matrixContainer.innerHTML = html;
}

// ===== ANALYSIS SUMMARY CARDS =====

function updateAnalysisSummary(cvesArray, nodes) {
    var summary = document.getElementById('analysis-summary');
    if (!summary) return;

    var techniqueNodes = nodes.filter(function(n) { return n.name && n.name.startsWith('T'); });

    document.getElementById('stat-cve-count').textContent = cvesArray.length;
    document.getElementById('stat-technique-count').textContent = techniqueNodes.length;

    summary.style.display = '';
}
