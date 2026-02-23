/**
 * core.js — shared graph logic for all framework pages
 */
const API = 'http://localhost:3000/api';

// ── Utility: strip URI prefix, return short ID ────────────────────────────────
function shortId(val) {
    if (!val) return '';
    // GraphDB returns full URIs like http://cwe.mitre.org/data/definitions/CWE-89
    // We only want CWE-89
    const m = val.match(/(?:CWE-|CAPEC-|T\d{4}|AML\.)[\w\-.]+/);
    if (m) return m[0];
    // Generic: take last path segment
    return val.replace(/.*[/#]/, '').replace(/^definitions\//, '');
}

// ── Normalise raw query results ───────────────────────────────────────────────
function normalise(db, raw) {
    if (db === 'graphdb') {
        const bindings = raw?.results?.bindings || [];
        return bindings.map(b => {
            const row = {};
            Object.keys(b).forEach(k => row[k] = b[k].value);
            return row;
        });
    }
    return raw?.data || [];
}

// ── Build Cytoscape elements from normalised rows ─────────────────────────────
function buildElements(rows, config = {}) {
    const {
        nodeColor = '#58a6ff',
        parentColor = '#ffa657',
        relLabel = 'CHILD_OF'
    } = config;

    const elements = [];
    const seen = new Set();

    const addNode = (id, label, desc, color) => {
        if (!id || seen.has(id)) return;
        seen.add(id);
        elements.push({ data: { id, label: label || id, description: desc || '', borderColor: color || nodeColor } });
    };

    const fwColors = {
        'CAPEC': '#8957e5',
        'CWE': '#f85149',
        'ATTACK': '#58a6ff',
        'ATLAS': '#79c0ff',
        'D3FEND': '#3fb950'
    };

    rows.forEach(row => {
        // Relationship query format: sourceId / sourceName / targetId / targetName
        if (row.sourceId) {
            const sid = shortId(row.sourceId);
            const tid = row.targetId ? shortId(row.targetId) : null;

            const sType = (row.sourceType || '').trim().toUpperCase();
            const tType = (row.targetType || '').trim().toUpperCase();

            const sColor = fwColors[sType] || nodeColor;
            const tColor = fwColors[tType] || parentColor;

            addNode(sid, row.sourceName, row.sourceDesc, sColor);

            if (tid) {
                addNode(tid, row.targetName, row.targetDesc, tColor);
                const eid = `e_${sid}_${tid}`;
                if (!seen.has(eid)) {
                    seen.add(eid);
                    elements.push({ data: { id: eid, source: sid, target: tid, label: row.relType || relLabel } });
                }
            }
        } else if (row.id || row.name) {
            // Simple node query
            const id = shortId(row.id) || row.name;
            addNode(id, row.name || id, row.description, nodeColor);
        }
    });

    return elements;
}

// ── Initialise Cytoscape ──────────────────────────────────────────────────────
function initCy(container, nodeColor = '#58a6ff') {
    return cytoscape({
        container,
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': '#161b22',
                    'border-color': 'data(borderColor)',
                    'border-width': 2,
                    'color': '#c9d1d9',
                    'label': 'data(label)',
                    'text-wrap': 'wrap',
                    'text-max-width': '120px',
                    'font-size': '10px',
                    'font-family': 'Inter, sans-serif',
                    'text-valign': 'bottom',
                    'text-margin-y': 5,
                    'width': 36,
                    'height': 36,
                    'shape': 'ellipse'
                }
            },
            {
                selector: 'node:selected',
                style: { 'border-width': 3, 'border-color': '#fff' }
            },
            {
                selector: 'edge',
                style: {
                    'line-color': 'rgba(240,246,252,0.12)',
                    'target-arrow-color': 'rgba(240,246,252,0.2)',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'width': 1.5,
                    'label': '',
                    'font-size': '8px',
                    'color': '#8b949e'
                }
            }
        ],
        layout: { name: 'preset' },
        minZoom: 0.05,
        maxZoom: 5,
        wheelSensitivity: 0.3
    });
}

// ── Run a layout ──────────────────────────────────────────────────────────────
function runLayout(cy, name) {
    const opts = {
        cose: { name: 'cose', nodeRepulsion: 500000, idealEdgeLength: 80, animate: true, animationDuration: 500 },
        breadthfirst: { name: 'breadthfirst', directed: true, spacingFactor: 1.5, animate: true, animationDuration: 400 },
        concentric: { name: 'concentric', animate: true },
        grid: { name: 'grid' },
        circle: { name: 'circle', animate: true }
    };
    cy.layout(opts[name] || opts.cose).run();
}

// ── Render table ──────────────────────────────────────────────────────────────
function renderTable(rows, thead, tbody) {
    thead.innerHTML = '';
    tbody.innerHTML = '';
    if (!rows.length) return;

    const cols = Object.keys(rows[0]);
    cols.forEach(c => {
        const th = document.createElement('th');
        th.textContent = c;
        thead.appendChild(th);
    });

    rows.forEach(row => {
        const tr = document.createElement('tr');
        cols.forEach(c => {
            const td = document.createElement('td');
            td.textContent = row[c] || '—';
            td.title = row[c] || '';
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
}

// ── Node click detail panel ───────────────────────────────────────────────────
function wireNodeDetail(cy, panel) {
    const titleEl = panel.querySelector('h4');
    const descEl = panel.querySelector('p');
    const closeBtn = panel.querySelector('.close-btn');

    cy.on('tap', 'node', evt => {
        const d = evt.target.data();
        titleEl.textContent = `${d.id} — ${d.label}`;
        descEl.textContent = d.description || 'No description available.';
        panel.classList.add('visible');
    });

    cy.on('tap', evt => {
        if (evt.target === cy) panel.classList.remove('visible');
    });

    closeBtn && closeBtn.addEventListener('click', () => panel.classList.remove('visible'));
}

// ── Toolbar wiring (search, layout, zoom) ─────────────────────────────────────
function wireToolbar(cy, { searchInput, clearBtn, layoutSel, zoomIn, zoomOut, zoomFit }) {
    searchInput && searchInput.addEventListener('input', () => {
        const term = searchInput.value.trim().toLowerCase();
        if (!term) { cy.elements().style('opacity', 1); return; }
        cy.nodes().forEach(n => n.style('opacity', n.data('label').toLowerCase().includes(term) ? 1 : 0.06));
        cy.edges().style('opacity', 0.05);
    });

    clearBtn && clearBtn.addEventListener('click', () => {
        if (searchInput) searchInput.value = '';
        cy.elements().style('opacity', 1);
    });

    layoutSel && layoutSel.addEventListener('change', () => runLayout(cy, layoutSel.value));

    const Z = level => cy.zoom({ level, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    zoomIn && zoomIn.addEventListener('click', () => Z(cy.zoom() * 1.3));
    zoomOut && zoomOut.addEventListener('click', () => Z(cy.zoom() * 0.75));
    zoomFit && zoomFit.addEventListener('click', () => cy.fit(undefined, 40));
}
