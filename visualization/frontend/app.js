// Constants
const API_URL = 'http://localhost:3000/api';

// DOM Elements
const dbSelect = document.getElementById('db-select');
const domainSelect = document.getElementById('domain-select');
const querySelect = document.getElementById('query-select');
const runBtn = document.getElementById('run-btn');
const toggleBtns = document.querySelectorAll('.toggle-btn');
const viewContainers = document.querySelectorAll('.view-container');
const loadingOverlay = document.getElementById('loading');
const recordCountEl = document.getElementById('record-count');
const queryTimeEl = document.getElementById('query-time');
const statusText = document.querySelector('.status-text');
const statusIndicator = document.querySelector('.status-indicator');
const tableHeader = document.getElementById('table-header');
const tableBody = document.getElementById('table-body');

// CY instance
let cy;

// Wait for DOM
document.addEventListener('DOMContentLoaded', () => {
    initCy();
    setupEventListeners();

    // Initial fetch to ensure server is connection and load domains
    checkServer().then(() => loadQueries());
});

// Setup Cytoscape instance
function initCy() {
    cy = cytoscape({
        container: document.getElementById('cy'),
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'color': '#c9d1d9',
                    'font-family': 'Inter, sans-serif',
                    'font-size': '12px',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'background-color': '#1f2a3c',
                    'border-width': 2,
                    'border-color': 'data(borderColor)',
                    'width': 'label',
                    'height': 'label',
                    'padding': '10px',
                    'shape': 'round-rectangle',
                    'text-wrap': 'wrap',
                    'text-max-width': '120px'
                }
            },
            {
                selector: 'node[type="attack"]',
                style: {
                    'border-color': '#f85149',
                    'text-outline-color': '#f85149'
                }
            },
            {
                selector: 'node[type="defense"]',
                style: {
                    'border-color': '#3fb950',
                    'color': '#c9d1d9'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 1.5,
                    'line-color': '#8b949e',
                    'target-arrow-color': '#8b949e',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'opacity': 0.6,
                    'label': 'data(label)',
                    'font-size': '10px',
                    'color': '#8b949e',
                    'text-background-opacity': 1,
                    'text-background-color': '#0d1117',
                    'text-background-padding': '2px',
                    'edge-text-rotation': 'autorotate'
                }
            },
            {
                selector: ':selected',
                style: {
                    'shadow-blur': 15,
                    'shadow-color': 'data(borderColor)',
                    'shadow-opacity': 0.8
                }
            }
        ],
        layout: {
            name: 'cose',
            idealEdgeLength: 100,
            nodeOverlap: 20,
            refresh: 20,
            fit: true,
            padding: 30,
            randomize: false,
            componentSpacing: 100,
            nodeRepulsion: 400000,
            edgeElasticity: 100,
            nestingFactor: 5,
            gravity: 80,
            numIter: 1000,
            initialTemp: 200,
            coolingFactor: 0.95,
            minTemp: 1.0
        }
    });

    // Hover dynamics
    cy.on('mouseover', 'node', function (e) {
        let node = e.target;
        node.style('border-width', '3px');
        document.body.style.cursor = 'pointer';
    });
    cy.on('mouseout', 'node', function (e) {
        let node = e.target;
        node.style('border-width', '2px');
        document.body.style.cursor = 'default';
    });
}

// Event Listeners
function setupEventListeners() {
    runBtn.addEventListener('click', executeQuery);
    domainSelect.addEventListener('change', loadQueries);

    toggleBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            const target = e.target.dataset.target;

            // UI Toggle
            toggleBtns.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');

            // Container Toggle
            viewContainers.forEach(c => c.classList.remove('active'));
            document.getElementById(`${target}-container`).classList.add('active');

            if (target === 'graph' && cy) {
                setTimeout(() => cy.fit(), 50); // Resize fix
            }
        });
    });
}

// Check Backend Server
async function checkServer() {
    try {
        const res = await fetch(`${API_URL}/domains`);
        if (res.ok) {
            setStatus('Server Connected', true);
        } else {
            setStatus('Server Error', false);
        }
    } catch (e) {
        setStatus('Server Disconnected', false);
        console.error(e);
    }
}

// Load queries for the selected domain
async function loadQueries() {
    const domain = domainSelect.value;
    querySelect.innerHTML = '<option>Loading...</option>';
    querySelect.disabled = true;
    runBtn.disabled = true;

    try {
        const res = await fetch(`${API_URL}/domains/${domain}/queries`);
        if (!res.ok) throw new Error("Failed to load queries for domain");

        const queries = await res.json();

        querySelect.innerHTML = '';
        queries.forEach(q => {
            const opt = document.createElement('option');
            opt.value = q.id;
            opt.textContent = q.name;
            querySelect.appendChild(opt);
        });

        querySelect.disabled = false;
        runBtn.disabled = false;

        // Auto-run the first query
        if (queries.length > 0) {
            executeQuery();
        }

    } catch (e) {
        querySelect.innerHTML = '<option>Error loading queries</option>';
        setStatus(`Error: ${e.message}`, false);
    }
}

// Main Execute Function
async function executeQuery() {
    const db = dbSelect.value;
    const domain = domainSelect.value;
    const queryId = querySelect.value;

    if (!queryId) return;

    showLoading(true);
    setStatus(`Fetching from ${db.toUpperCase()}...`, true);

    try {
        // Fetch raw query from backend config
        const qRes = await fetch(`${API_URL}/domains/${domain}/queries/${queryId}`);
        if (!qRes.ok) throw new Error("Could not load query");
        const queryObj = await qRes.json();

        let queryStr = "";
        if (db === 'graphdb') {
            queryStr = queryObj.sparql;
        } else if (db === 'neo4j') {
            queryStr = queryObj.cypher;
        }

        const runStart = performance.now();

        // Execute the query via Node proxy
        const response = await fetch(`${API_URL}/${db}/query`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: queryStr })
        });

        const runEnd = performance.now();

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Execution Failed: ${errorText}`);
        }

        const data = await response.json();

        // Normalize results (GraphDB -> JSON bindings vs Neo4j -> rows)
        const normalizedData = normalizeData(db, data);

        // Update UI
        updateMetrics(normalizedData.length, Math.round(runEnd - runStart));
        setStatus('Ready', true);

        // Render
        renderTable(normalizedData);
        renderGraph(normalizedData);

    } catch (e) {
        setStatus(`Error: ${e.message}`, false);
        console.error(e);
    } finally {
        showLoading(false);
    }
}

// Helper: Normalize query results
function normalizeData(db, rawData) {
    if (db === 'graphdb') {
        const bindings = rawData.results?.bindings || [];
        return bindings.map(b => {
            const row = {};
            Object.keys(b).forEach(k => row[k] = b[k].value);
            return row;
        });
    } else if (db === 'neo4j') {
        return rawData.data || [];
    }
    return [];
}

// Render Table
function renderTable(dataArray) {
    tableHeader.innerHTML = '';
    tableBody.innerHTML = '';

    if (dataArray.length === 0) return;

    // Build headers
    const cols = Object.keys(dataArray[0]);
    cols.forEach(col => {
        const th = document.createElement('th');
        th.textContent = col;
        tableHeader.appendChild(th);
    });

    // Build rows
    dataArray.forEach(rowItem => {
        const tr = document.createElement('tr');
        cols.forEach(col => {
            const td = document.createElement('td');
            td.textContent = rowItem[col] || '—';
            tr.appendChild(td);
        });
        tableBody.appendChild(tr);
    });
}

// Render Graph using Cytoscape
function renderGraph(dataArray) {
    const elements = [];
    const addedNodes = new Set();

    // We assume mostly attackLabel and defensiveLabel exist
    dataArray.forEach(row => {
        let defenseId = null;
        let attackId = null;

        // Extract Defense Node
        if (row.defensiveLabel || row.techniqueLabel) {
            const label = row.defensiveLabel || row.techniqueLabel;
            defenseId = 'def_' + label.replace(/\\s+/g, '_');
            if (!addedNodes.has(defenseId)) {
                elements.push({
                    data: { id: defenseId, label: label, type: 'defense', borderColor: '#3fb950' }
                });
                addedNodes.add(defenseId);
            }
        }

        // Extract Attack Node
        if (row.attackLabel) {
            attackId = 'atk_' + row.attackLabel.replace(/\\s+/g, '_');
            if (!addedNodes.has(attackId)) {
                elements.push({
                    data: { id: attackId, label: row.attackLabel, type: 'attack', borderColor: '#f85149' }
                });
                addedNodes.add(attackId);
            }
        }

        // Extract Tactic (if Q4)
        if (row.tacticLabel) {
            defenseId = 'tac_' + row.tacticLabel.replace(/\\s+/g, '_');
            if (!addedNodes.has(defenseId)) {
                elements.push({
                    data: { id: defenseId, label: row.tacticLabel, type: 'tactic', borderColor: '#d2a8ff' }
                });
                addedNodes.add(defenseId);
            }
        }

        // Draw Edge (Defense -> Attack)
        if (defenseId && attackId) {
            const edgeId = `edge_${defenseId}_${attackId}`;
            elements.push({
                data: { id: edgeId, source: defenseId, target: attackId, label: 'COUNTERS' }
            });
        }
    });

    cy.elements().remove();
    if (elements.length > 0) {
        cy.add(elements);

        // Optional: switch layout if there are too many nodes
        if (elements.length > 200) {
            cy.layout({ name: 'concentric' }).run();
        } else {
            cy.layout({
                name: 'cose',
                nodeRepulsion: 400000,
                edgeElasticity: 100,
                idealEdgeLength: 100
            }).run();
        }
    }
}

// UI Helpers
function showLoading(show) {
    if (show) loadingOverlay.classList.remove('hidden');
    else loadingOverlay.classList.add('hidden');
}

function setStatus(msg, isOk) {
    statusText.textContent = msg;
    statusIndicator.style.backgroundColor = isOk ? 'var(--defense-node)' : 'var(--attack-node)';
    statusIndicator.style.boxShadow = `0 0 8px ${isOk ? 'var(--defense-node)' : 'var(--attack-node)'}`;
}

function updateMetrics(count, time) {
    recordCountEl.textContent = count;
    queryTimeEl.textContent = time;
}
