// Docker Network Monitor - Graph Visualization

let network = null;

function showView(view) {
    const graphView = document.getElementById('graph-view');
    const treeView = document.getElementById('tree-view');
    const btnGraph = document.getElementById('btn-graph');
    const btnTree = document.getElementById('btn-tree');

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
}

async function loadTopology() {
    try {
        const response = await fetch('/api/topology');
        const data = await response.json();

        if (data.error) {
            console.error('Error loading topology:', data.error);
            return;
        }

        renderGraph(data);
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
        renderConflictsTable(data.conflicts);
        renderTree(data.tree);
    } catch (error) {
        console.error('Failed to load conflicts:', error);
    }
}

function renderGraph(data) {
    const container = document.getElementById('network-graph');

    const nodes = new vis.DataSet(data.nodes);
    const edges = new vis.DataSet(data.edges);

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

    if (network) {
        network.setData({ nodes, edges });
    } else {
        network = new vis.Network(container, { nodes, edges }, options);
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

function renderConflictsTable(conflicts) {
    const tbody = document.getElementById('conflicts-body');
    const noConflicts = document.getElementById('no-conflicts');
    const table = document.getElementById('conflicts-table');

    if (conflicts.length === 0) {
        table.style.display = 'none';
        noConflicts.style.display = 'block';
        return;
    }

    table.style.display = 'table';
    noConflicts.style.display = 'none';

    tbody.innerHTML = conflicts.map(conflict => `
        <tr>
            <td class="severity-${conflict.severity}">${conflict.severity.toUpperCase()}</td>
            <td>${escapeHtml(conflict.network)}</td>
            <td>${escapeHtml(conflict.dns_name)}</td>
            <td>${escapeHtml(conflict.containers.join(', '))}</td>
        </tr>
    `).join('');
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

                conflictHtml = c.conflicts.map(conf =>
                    `<div class="tree-container-conflict">Conflict: ${escapeHtml(conf.name)} (${conf.severity})</div>`
                ).join('');
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

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadTopology();
    loadConflicts();
});
