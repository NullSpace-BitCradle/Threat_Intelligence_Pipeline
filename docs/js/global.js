// ===== GLOBAL VARIABLES AND INITIALIZATION =====
var data_cleaned = [];
const fullScreenIcon = 'image://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAsTAAALEwEAmpwYAAACvUlEQVR4nO3dTW7TUBQF4MeP2AJjkAAJKIxYAIvINqL4nHrsFUEpqFL52wRsggmCYgQtIAU94QGqSFLa93xukvNJHuf43Loe+MpOyczMzMzMzMzMbEORnFc+jgA8n81m92qdw+7u7gOSr0ge1z6ftAEDmQ9H3zTNToX8jwCcjHUepfMrBzIH8LJC/ndjnkPp/OqBnEwmkyulsk+n0+tj5vdAVvBALv4XdpgKA/DeV8j5htGTvF96IE3TPCb5zf+yzn7f+Exyn+Td0sP4ayg7JN8A+L7x95C0ZajuQx4gGHkf8gDByPuQBwhG3oc8QDDyPuQBgpH3IQ8QjLwPeYBg5H3IAwQj70MeIBh5H/IAwcj7kAcIRt6HPEAw8j7kAYKR9yEPEIy8D3mAYOR9DA+QFgX4lLYMyQ+L+gDwpXqAvMS2ZCD7acsAeLKkj73qAfJG4fC8+/SP9zW3DaNq2/ZWvhIW9HFzlBD5mXReYiP5Y9gCPKyxkLAu2ra9A+Dt0MdPAK+bpnk4epC8xFZykW3ddV13reu6q+ocZmZmZmZmZmZmZmZmZmZmdkp+oO8lhwB9ALidV11I/sqHbO0lCGkf+YcWLcrVeANcdPI+SB4sWZ18kbYM1X0A+LokQJ+2DNR9yNfvg5H3IQ8QjLwPeYBg5H3IAwQj70MeIBh5H/IAwcj7kAcIRt6HPEAw8j7kAYKR9yEPEIy8D3mAYOR9yAMEI+9DHiAYeR/yAMHI+5AHCEbehzxAMPI+VgUocPQAntZ8T0h+J8vwEp2j2ueTNmAg83zk10DVGMrw7ZB/PQP3QM5QwkHpgQzfLxxlGBt1hfDPcdx13eVS2fPOVH5jjwdygYGklC55IEGuEADPUmHDe778L+scJXzMG4GlB+Kb+v8Poh++0nYjVZK/AJd/Y8ULPdfjpm5mZmZmZmZmqZ7frkDXeF36/ksAAAAASUVORK5CYII=';
var chart = echarts.init(document.getElementById('container'), null, {
    renderer: 'canvas',
    useDirtyRect: false
});
var modal_chart = echarts.init(document.getElementById('subgraph'), null, {
    renderer: 'canvas',
    useDirtyRect: false
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
    // Masquer l'onglet D3FEND par défaut
    document.getElementById('defend-tab').style.display = 'none';

    // Gestionnaire d'événements pour les onglets
    document.getElementById('attack-tab').addEventListener('shown.bs.tab', function (e) {
        // Redimensionner l'iframe si elle existe
        const iframe = document.getElementById('mitre');
        if (iframe) {
            iframe.style.height = '800px';
            iframe.style.width = '100%';
        }
    });

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

    let techniquesAssoc, cweDataRaw, capecDataRaw, defendText = '';
    try {
        techniquesAssoc = await fetchWithFallback([
            'https://raw.githubusercontent.com/NullSpace-BitCradle/Threat_Intelligence_Pipeline/refs/heads/main/resources/techniques_association.json',
            'https://raw.githubusercontent.com/Galeax/ThreatIntelligencePipeline/refs/heads/main/resources/techniques_association.json',
            'https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/techniques_association.json',
            '/resources/techniques_association.json'
        ]);
        cweDataRaw = await fetchWithFallback([
            'https://raw.githubusercontent.com/NullSpace-BitCradle/Threat_Intelligence_Pipeline/refs/heads/main/resources/cwe_db.json',
            'https://raw.githubusercontent.com/Galeax/ThreatIntelligencePipeline/refs/heads/main/resources/cwe_db.json',
            'https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/cwe_db.json',
            '/resources/cwe_db.json'
        ]);
        capecDataRaw = await fetchWithFallback([
            'https://raw.githubusercontent.com/NullSpace-BitCradle/Threat_Intelligence_Pipeline/refs/heads/main/resources/capec_db.json',
            'https://raw.githubusercontent.com/Galeax/ThreatIntelligencePipeline/refs/heads/main/resources/capec_db.json',
            'https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/capec_db.json',
            '/resources/capec_db.json'
        ]);
        if (wantDefend) {
            defendText = await fetchWithFallback([
                'https://raw.githubusercontent.com/NullSpace-BitCradle/Threat_Intelligence_Pipeline/refs/heads/main/resources/defend_db.jsonl',
                'https://raw.githubusercontent.com/Galeax/ThreatIntelligencePipeline/refs/heads/main/resources/defend_db.jsonl',
                'https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/defend_db.jsonl',
                '/resources/defend_db.jsonl'
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

    const defendList = {};
    defendText.split('\n').forEach(line => {
        if (line.trim()) Object.assign(defendList, JSON.parse(line));
    });

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
                `https://raw.githubusercontent.com/NullSpace-BitCradle/Threat_Intelligence_Pipeline/refs/heads/main/database/CVE-${year}.jsonl`,
                `https://raw.githubusercontent.com/Galeax/ThreatIntelligencePipeline/refs/heads/main/database/CVE-${year}.jsonl`,
                `https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/database/CVE-${year}.jsonl`,
                `/database/CVE-${year}.jsonl`
            ], true);
            database = {};
            responseText.split('\n').forEach(line => {
                if (line.trim()) {
                    try {
                        const lineData = JSON.parse(line);
                        // Le format est maintenant {"CVE-ID": {"CWE": [...], ...}}
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
                data.push({ source: cve, target: 'CWE-' + cwe, value: 1 });
                var relatedCapecs = cweDataRaw[cwe]?.RelatedAttackPatterns || [];
                relatedCapecs.forEach(capec => {
                    data.push({ source: 'CWE-' + cwe, target: 'CAPEC-' + capec, value: 1 });
                    var lines = capecDataRaw[capec]?.techniques.split("NAME:ATTACK:ENTRY ")
                    var relatedTechniques = new Set()
                    for (var i = 1; i < lines.length; i++) {
                        var technique_id = lines[i].split(":")[1];
                        if (modeSelect === "ics") {
                            technique_id = techniquesAssoc[technique_id]?.ics;
                        } else if (modeSelect === "mobile") {
                            technique_id = techniquesAssoc[technique_id]?.mobile;
                        }
                        if (technique_id) {
                            relatedTechniques.add(technique_id);
                        }
                    }
                    relatedTechniques.forEach(technique => {
                        data.push({ source: 'CAPEC-' + capec, target: 'T' + technique, value: 1 });
                    });
                    relatedTechniques.forEach(technique => {
                        const atkKey = 'T' + technique;
                        (defendList[atkKey] || []).forEach(d => {
                            data.push({ source: atkKey, target: 'D3F-' + d.id, value: 1 });
                        });
                    });
                });
            })
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

    chart_nodes = Array.from(chartNodes).map(node => ({ name: node }))
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
        annimation: false,
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
                    title: 'Plein Écran',
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
            nodeWidth: 20,  // Largeur des nœuds pour réduire l'encombrement
            nodeGap: 5,    // Ajustement de l'espace entre les nœuds
            layoutIterations: 64, // Nombre d'itérations pour le calcul de la disposition
            label: {
                fontSize: 12, // Taille de police réduite
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

    chart.hideLoading();

    await print_mitre();

    // Activer l'onglet ATT&CK après génération et mettre à jour les statistiques
    document.getElementById('attack-tab').click();
    updateAttackStats();

    if (wantDefend) {
        document.getElementById('defend_matrix').style.display = '';
        document.getElementById('defend-tab').style.display = '';
        renderDefendMatrix(defendScore);
    } else {
        document.getElementById('defend_matrix').style.display = 'none';
        document.getElementById('defend-tab').style.display = 'none';
    }
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
        annimation: false,
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
                    title: 'Plein Écran',
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
            nodeWidth: 20,
            nodeGap: 5,
            layoutIterations: 64,
            label: {
                fontSize: 12,
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
        annimation: false,
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
                    title: 'Plein Écran',
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
            nodeWidth: 20,  // Largeur des nœuds pour réduire l'encombrement
            nodeGap: 5,    // Ajustement de l'espace entre les nœuds
            layoutIterations: 64, // Nombre d'itérations pour le calcul de la disposition
            label: {
                fontSize: 12, // Taille de police réduite
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
