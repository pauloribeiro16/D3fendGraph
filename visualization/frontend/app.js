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

// Toolbar
const graphSearch = document.getElementById('graph-search');
const graphSearchClear = document.getElementById('graph-search-clear');
const layoutSelect = document.getElementById('layout-select');
const resultLimit = document.getElementById('result-limit');
const limitValue = document.getElementById('limit-value');

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
                    'width': '100px',
                    'height': '100px',
                    'padding': '10px',
                    'shape': 'ellipse',
                    'text-wrap': 'wrap',
                    'text-max-width': '90px'
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
            minTemp: 1.0,
            animate: true
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

    // ── Graph Toolbar ─────────────────────────────────────────────────────────

    // Result limit slider
    if (resultLimit && limitValue) {
        resultLimit.addEventListener('input', () => {
            limitValue.textContent = resultLimit.value;
        });
    }

    // Node search/filter
    if (graphSearch) {
        graphSearch.addEventListener('input', () => {
            const term = graphSearch.value.trim().toLowerCase();
            if (!cy) return;
            if (!term) {
                cy.elements().removeClass('faded');
                cy.elements().style('opacity', 1);
                return;
            }
            cy.nodes().forEach(n => {
                const matches = (n.data('label') || '').toLowerCase().includes(term);
                n.style('opacity', matches ? 1 : 0.08);
            });
            cy.edges().style('opacity', 0.05);
        });

        graphSearchClear && graphSearchClear.addEventListener('click', () => {
            graphSearch.value = '';
            if (cy) {
                cy.elements().style('opacity', 1);
            }
        });
    }

    // Layout switcher
    if (layoutSelect) {
        layoutSelect.addEventListener('change', () => {
            if (!cy) return;
            const name = layoutSelect.value;
            const layoutOptions = {
                cose: { name: 'cose', nodeRepulsion: 400000, idealEdgeLength: 100, animate: true },
                breadthfirst: { name: 'breadthfirst', directed: true, spacingFactor: 1.4 },
                concentric: { name: 'concentric' },
                grid: { name: 'grid' },
                circle: { name: 'circle' }
            };
            cy.layout(layoutOptions[name] || { name }).run();
        });
    }

    // Zoom buttons
    document.getElementById('zoom-in') && document.getElementById('zoom-in').addEventListener('click', () => cy && cy.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }));
    document.getElementById('zoom-out') && document.getElementById('zoom-out').addEventListener('click', () => cy && cy.zoom({ level: cy.zoom() * 0.75, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }));
    document.getElementById('zoom-fit') && document.getElementById('zoom-fit').addEventListener('click', () => cy && cy.fit(undefined, 40));

    // DSS Submit Button
    const dssSubmitBtn = document.getElementById('dss-submit');
    const dssQuestionEl = document.getElementById('dss-question');
    const dssBackendEl = document.getElementById('dss-backend');
    const dssLoadingEl = document.getElementById('dss-loading');
    const dssResponseEl = document.getElementById('dss-response');
    const dssAnswerEl = document.getElementById('dss-answer');
    const dssSourcesEl = document.getElementById('dss-sources-list');
    const dssCopyBtn = document.getElementById('dss-copy');

    dssSubmitBtn.addEventListener('click', async () => {
        const question = dssQuestionEl.value.trim();
        if (!question) return;

        const backend = dssBackendEl.value;

        dssLoadingEl.classList.remove('hidden');
        dssResponseEl.classList.add('hidden');
        dssSubmitBtn.disabled = true;

        try {
            const res = await fetch(`${API_URL}/dss/query`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ question, backend, topK: 12 })
            });

            if (!res.ok) {
                const err = await res.json();
                dssAnswerEl.textContent = `Error: ${err.error}\n\n${err.details || ''}`;
            } else {
                const data = await res.json();
                dssAnswerEl.textContent = data.answer || 'No response received.';

                // Render sources
                dssSourcesEl.innerHTML = '';
                (data.sources || []).forEach(s => {
                    const chip = document.createElement('span');
                    chip.className = 'source-chip';
                    chip.textContent = `${s.id} — ${s.name.slice(0, 40)}${s.name.length > 40 ? '…' : ''}`;
                    dssSourcesEl.appendChild(chip);
                });
            }

            dssLoadingEl.classList.add('hidden');
            dssResponseEl.classList.remove('hidden');
        } catch (e) {
            dssAnswerEl.textContent = `Connection error: ${e.message}`;
            dssLoadingEl.classList.add('hidden');
            dssResponseEl.classList.remove('hidden');
        } finally {
            dssSubmitBtn.disabled = false;
        }
    });

    dssCopyBtn && dssCopyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(dssAnswerEl.textContent)
            .then(() => { dssCopyBtn.textContent = 'Copied!'; setTimeout(() => dssCopyBtn.textContent = 'Copy', 2000); })
            .catch(() => { });
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

        // Extract Generic Single Nodes (CAPEC, CWE, etc.)
        if ((row.name || row.label) && !row.defensiveLabel && !row.attackLabel && !row.techniqueLabel) {
            const label = row.name || row.label;
            const fallbackId = 'gen_' + label.replace(/\\s+/g, '_');
            const genId = row.id ? 'gen_' + row.id.replace(/[\\W_]+/g, '-') : fallbackId;

            // Adjust color based on framework if available
            let tColor = '#ffa657'; // default orange
            if (row.framework === 'CWE') tColor = '#79c0ff';
            if (row.framework === 'CAPEC') tColor = '#d2a8ff';
            if (row.framework === 'ATT&CK') tColor = '#f85149';
            if (row.framework === 'ATLAS') tColor = '#3fb950';

            if (!addedNodes.has(genId)) {
                elements.push({
                    data: { id: genId, label: label, type: 'attack', borderColor: tColor }
                });
                addedNodes.add(genId);
            }
        }

        // Extract Generic Relationships (if backend query supports source/target logic)
        if (row.sourceId && row.targetId) {
            const sId = 'gen_' + row.sourceId.replace(/[\W_]+/g, '-');
            const tId = 'gen_' + row.targetId.replace(/[\W_]+/g, '-');
            const relType = row.relType || 'RELATED';
            const edgeId = `edge_${sId}_${tId}_${relType}`;

            // Add nodes if missing
            if (!addedNodes.has(sId) && row.sourceName) {
                elements.push({ data: { id: sId, label: row.sourceName, type: 'attack', borderColor: '#ffa657' } });
                addedNodes.add(sId);
            }
            if (!addedNodes.has(tId) && row.targetName) {
                elements.push({ data: { id: tId, label: row.targetName, type: 'attack', borderColor: '#ffa657' } });
                addedNodes.add(tId);
            }

            elements.push({
                data: { id: edgeId, source: sId, target: tId, label: relType.toUpperCase() }
            });
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

        // Add Click Listener
        cy.on('tap', 'node', function (evt) {
            var node = evt.target;
            var description = node.data('description');
            var definition = node.data('definition'); // for d3fend 

            let textToShow = node.data('label');
            if (description && description.trim() !== '') {
                textToShow += '\\n\\nDescription:\\n' + description;
            } else if (definition && definition.trim() !== '') {
                textToShow += '\\n\\nDefinition:\\n' + definition;
            } else {
                textToShow += '\\n\\nNo additional description available.';
            }
            alert(textToShow);
        });
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
