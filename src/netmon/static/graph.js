// Docker Network Monitor - Graph Visualization

let network = null;
let currentView = 'graph';
let isRefreshing = false;

// View management with persistence
function showView(view, save = true) {
    const graphView = document.getElementById('graph-view');
    const treeView = document.getElementById('tree-view');
    const btnGraph = document.getElementById('btn-graph');
    const btnTree = document.getElementById('btn-tree');

    currentView = view;

    if (view === 'graph') {
        graphView.style.display = 'block';
        treeView.style.display = 'none';
        btnGraph.classList.add('active');
        btnTree.classList.remove('active');
    } else {
        graphView.style.display = 'none';
        treeView.style.display = 'block';
        btnGraph.classList.remove('active');
        btnTree.classList.add('active');
    }

    if (save) {
        localStorage.setItem('netmon-view', view);
    }
}

function restoreView() {
    const savedView = localStorage.getItem('netmon-view');
    if (savedView === 'tree' || savedView === 'graph') {
        showView(savedView, false);
    }
}

// Data loading
async function loadTopology(preservePositions = false) {
    try {
        const response = await fetch('/api/topology');
        const data = await response.json();

        if (data.error) {
            console.error('Error loading topology:', data.error);
            return;
        }

        renderGraph(data, preservePositions);
    } catch (error) {
        console.error('Failed to load topology:', error);
    }
}

async function loadConflicts() {
    try {
        const response = await fetch('/api/conflicts');
        const data = await response.json();

        if (data.error) {
            console.error('Error loading conflicts:', data.error);
            return;
        }

        updateSummary(data.summary);
        renderConflictsList(data.conflicts);
        renderTree(data.tree);
    } catch (error) {
        console.error('Failed to load conflicts:', error);
    }
}

// Manual refresh
async function refreshData() {
    if (isRefreshing) return;

    const btn = document.getElementById('btn-refresh');
    btn.disabled = true;
    btn.textContent = 'Refreshing...';
    isRefreshing = true;

    try {
        await Promise.all([
            loadTopology(true),
            loadConflicts()
        ]);
        updateLastRefreshed();
    } finally {
        btn.disabled = false;
        btn.textContent = 'Refresh';
        isRefreshing = false;
    }
}

function updateLastRefreshed() {
    const el = document.getElementById('last-updated');
    const now = new Date();
    const time = now.toLocaleTimeString();
    el.textContent = `Updated: ${time}`;
}

// Graph rendering
function renderGraph(data, preservePositions = false) {
    const container = document.getElementById('network-graph');

    const nodes = new vis.DataSet(data.nodes);
    const edges = new vis.DataSet(data.edges);

    if (network && preservePositions) {
        // Get current positions before updating
        const positions = network.getPositions();

        // Update node positions from saved state
        nodes.forEach(node => {
            if (positions[node.id]) {
                node.x = positions[node.id].x;
                node.y = positions[node.id].y;
            }
        });

        // Update data without re-running physics
        network.setData({ nodes, edges });
        network.setOptions({ physics: { enabled: false } });

        // Re-enable physics briefly to settle new nodes, then disable
        setTimeout(() => {
            network.setOptions({ physics: { enabled: true } });
            setTimeout(() => {
                network.setOptions({ physics: { enabled: false } });
            }, 1000);
        }, 100);
    } else {
        const options = {
            nodes: {
                font: {
                    size: 14,
                    color: '#ffffff'
                },
                borderWidth: 2,
                shadow: true
            },
            edges: {
                width: 2,
                color: {
                    color: '#0f3460',
                    highlight: '#4a90d9'
                },
                smooth: {
                    type: 'continuous'
                }
            },
            groups: {
                network: {
                    shape: 'box',
                    font: {
                        size: 16,
                        bold: true
                    }
                },
                container: {
                    shape: 'ellipse'
                }
            },
            physics: {
                stabilization: {
                    iterations: 100
                },
                barnesHut: {
                    gravitationalConstant: -3000,
                    centralGravity: 0.3,
                    springLength: 150,
                    springConstant: 0.04
                }
            },
            interaction: {
                hover: true,
                tooltipDelay: 100
            }
        };

        network = new vis.Network(container, { nodes, edges }, options);

        // Disable physics after initial stabilization
        network.once('stabilized', () => {
            network.setOptions({ physics: { enabled: false } });
        });
    }
}

function updateSummary(summary) {
    document.getElementById('network-count').textContent = summary.total_networks;
    document.getElementById('container-count').textContent = summary.total_containers;
    document.getElementById('conflict-count').textContent = summary.total_conflicts;
    document.getElementById('critical-count').textContent = summary.critical_count;
    document.getElementById('high-count').textContent = summary.high_count;
    document.getElementById('warning-count').textContent = summary.warning_count;
}

function renderConflictsList(conflicts) {
    const container = document.getElementById('conflicts-list');
    const noConflicts = document.getElementById('no-conflicts');

    if (conflicts.length === 0) {
        container.style.display = 'none';
        noConflicts.style.display = 'block';
        return;
    }

    container.style.display = 'block';
    noConflicts.style.display = 'none';

    container.innerHTML = conflicts.map((conflict, index) => {
        const remediationHtml = conflict.remediation && conflict.remediation.length > 0
            ? `<div class="conflict-remediation hidden" id="remediation-${index}">
                <div class="remediation-title">Recommended Actions:</div>
                <ol class="remediation-list">
                    ${conflict.remediation.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
                </ol>
               </div>`
            : '';

        const hasRemediation = conflict.remediation && conflict.remediation.length > 0;

        return `
            <div class="conflict-card severity-${conflict.severity}-card">
                <div class="conflict-header" ${hasRemediation ? `onclick="toggleRemediation(${index})"` : ''}>
                    <span class="conflict-severity severity-${conflict.severity}">${conflict.severity.toUpperCase()}</span>
                    <span class="conflict-dns">${escapeHtml(conflict.dns_name)}</span>
                    <span class="conflict-network">on ${escapeHtml(conflict.network)}</span>
                    ${hasRemediation ? '<span class="expand-icon" id="expand-icon-' + index + '">&#9660;</span>' : ''}
                </div>
                <div class="conflict-details">
                    <div class="conflict-containers">${formatConflictingNames(conflict)}</div>
                </div>
                ${remediationHtml}
            </div>
        `;
    }).join('');
}

function toggleRemediation(index) {
    const remediation = document.getElementById(`remediation-${index}`);
    const icon = document.getElementById(`expand-icon-${index}`);
    if (remediation) {
        remediation.classList.toggle('hidden');
        if (icon) {
            icon.innerHTML = remediation.classList.contains('hidden') ? '&#9660;' : '&#9650;';
        }
    }
}

function renderTree(tree) {
    const container = document.getElementById('network-tree');

    container.innerHTML = tree.map(network => {
        const containersHtml = network.containers.map(c => {
            let conflictClass = '';
            let conflictHtml = '';

            if (c.conflicts && c.conflicts.length > 0) {
                const maxSeverity = c.conflicts.reduce((max, conf) => {
                    const order = { critical: 0, high: 1, warning: 2 };
                    return order[conf.severity] < order[max] ? conf.severity : max;
                }, 'warning');

                if (maxSeverity === 'critical') {
                    conflictClass = 'has-conflict-critical';
                } else if (maxSeverity === 'high') {
                    conflictClass = 'has-conflict-high';
                } else {
                    conflictClass = 'has-conflict';
                }

                conflictHtml = c.conflicts.map(conf => {
                    const sourceInfo = conf.source ? ` via ${conf.source}` : '';
                    return `<div class="tree-container-conflict">Conflict: ${escapeHtml(conf.name)}${sourceInfo} (${conf.severity})</div>`;
                }).join('');
            }

            const details = [];
            if (c.ip) details.push(`IP: ${c.ip}`);
            if (c.service) details.push(`Service: ${c.service}`);
            if (c.aliases && c.aliases.length > 0) details.push(`Aliases: ${c.aliases.join(', ')}`);

            return `
                <div class="tree-container ${conflictClass}">
                    <div class="tree-container-name">${escapeHtml(c.name)}</div>
                    ${details.length > 0 ? `<div class="tree-container-details">${escapeHtml(details.join(' | '))}</div>` : ''}
                    ${conflictHtml}
                </div>
            `;
        }).join('');

        return `
            <div class="tree-network">
                <div class="tree-network-header" onclick="toggleNetwork(this)">
                    <span class="icon">&#9660;</span>
                    ${escapeHtml(network.name)}
                    <span style="color: #888; font-weight: normal; margin-left: auto;">(${network.containers.length} containers)</span>
                </div>
                <div class="tree-containers">
                    ${containersHtml}
                </div>
            </div>
        `;
    }).join('');
}

function toggleNetwork(header) {
    header.classList.toggle('collapsed');
    const containers = header.nextElementSibling;
    containers.classList.toggle('hidden');
}

function formatConflictingNames(conflict) {
    if (conflict.conflicting_names && conflict.conflicting_names.length > 0) {
        const items = conflict.conflicting_names.map(cn =>
            `<span class="conflicting-name">${escapeHtml(cn.container)}</span> <span class="conflict-source">(${escapeHtml(cn.source)})</span>`
        );
        return `Conflicting: ${items.join(', ')}`;
    }
    return `Containers: ${escapeHtml(conflict.containers.join(', '))}`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    restoreView();
    loadTopology();
    loadConflicts();
    updateLastRefreshed();
});
