# UnifiedThreatGraph Test Environment

> **Aggregating CAPEC, CWE, MITRE ATT&CK, ATLAS & D3FEND**
> **Phase 1 of 2** — SPARQL/GraphDB evaluation.
> Neo4j phase comes after you validate these results.

## Prerequisites

- Node.js (for the Visualization Backend)
- Docker + Docker Compose installed and running
- Python 3.8+ (standard library only, no pip installs needed)
- Internet access (to download the D3FEND ontology and other STIX/JSON data)

---

## Step 1 — Start and Load

```bash
cd d3fend-test

# Make the bootstrap script executable
chmod +x scripts/bootstrap.sh

# Run it — this does everything:
# 1. Starts GraphDB in Docker
# 2. Creates the 'd3fend' repository with OWL-RL reasoning
# 3. Downloads the D3FEND .ttl file
# 4. Loads it into GraphDB
# 5. Verifies with a triple count
./scripts/bootstrap.sh
```

**Expected output:**
```
[INFO] GraphDB is up!
[INFO] Repository 'd3fend' created.
[INFO] Downloaded to ./graphdb/import/d3fend.ttl
[INFO] Import complete!
[INFO] Triple count in repository: ~180000
[INFO] ✅ D3FEND loaded successfully!

  GraphDB Workbench: http://localhost:7200
  SPARQL Endpoint:   http://localhost:7200/repositories/d3fend
  Run queries:       python3 scripts/run_queries.py
```

## Step 2 — Inject Secondary Framework Data
To properly use UnifiedThreatGraph, inject the JSON data for CAPEC, CWE, and MITRE ATT&CK into the Neo4j and GraphDB databases:

```bash
# Fetch extra JSON data (CAPEC) if it does not exist
mkdir -p data
curl -s -L -o data/capec.json https://raw.githubusercontent.com/mitre/cti/master/capec/stix/capec.json
# Ensure CWE and ATT&CK json files are present in the data folder.
# Run the python ingestor (this may take a few minutes)
python3 scripts/inject_threats.py
```

## Step 3 — Start the Visualization Server
The project includes a web visualization dashboard and Node.js proxy server.

```bash
# Start backend server proxy
cd visualization/backend
npm install
node server.js
```

```bash
# In another terminal window, start the frontend UI
cd visualization/frontend
python3 -m http.server 8001
```

Access the Visualizer Application at **[http://localhost:8001](http://localhost:8001)**.

---

## Step 2 — Explore the Workbench (Optional but Recommended)

Open your browser at **http://localhost:7200**

- Go to **Repositories** → confirm `d3fend` exists
- Go to **SPARQL** → try a quick query:

```sparql
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT * WHERE { ?s rdfs:label ?l } LIMIT 10
```

---

## Step 3 — Run the Query Suite

```bash
# Run all queries
python3 scripts/run_queries.py

# Run only technique→countermeasure queries
python3 scripts/run_queries.py --query technique

# Run only category/tactic queries
python3 scripts/run_queries.py --query category

# Run a custom keyword search (most useful for exploration)
python3 scripts/run_queries.py --search "ransomware"
python3 scripts/run_queries.py --search "network traffic"
python3 scripts/run_queries.py --search "authentication"
python3 scripts/run_queries.py --search "encryption"
```

---

## Query Reference

| Query ID | What it answers |
|---|---|
| `Q1_all_attack_to_d3fend` | Full ATT&CK ↔ D3FEND mapping table |
| `Q2_credential_attacks` | Countermeasures for credential-based attacks |
| `Q3_data_exfil_attacks` | Countermeasures for data exfiltration |
| `Q4_tactic_overview` | Technique count per D3FEND tactic (Harden/Detect/etc.) |
| `Q5_harden_techniques` | All "Harden" techniques (maps to GDPR Art.32 / CRA) |
| `Q6_detect_techniques` | All "Detect" techniques |
| `Q7_coverage_priority` | Top controls ranked by ATT&CK coverage breadth |
| `Q8_data_protection` | Encryption, access control, auth techniques |

---

## D3FEND Namespace Cheat Sheet

```sparql
PREFIX d3f:  <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl:  <http://www.w3.org/2002/07/owl#>

-- Key classes --
d3f:DefensiveTechnique    -- root of all countermeasures
d3f:Harden                -- preventative hardening techniques
d3f:Detect                -- detection techniques
d3f:Isolate               -- isolation techniques
d3f:Deceive               -- deception techniques
d3f:Evict                 -- eviction/remediation techniques

-- Key properties --
d3f:counters              -- links D3FEND technique → ATT&CK technique
d3f:d3fend-id             -- D3FEND identifier (e.g. D3-AH)
d3f:definition            -- human-readable definition
d3f:analyzes              -- what artifact the technique analyzes
d3f:monitors              -- what artifact it monitors
d3f:filters               -- what it filters
```

---

## Troubleshooting

**GraphDB doesn't start:**
```bash
docker compose logs graphdb
# Usually a port conflict — check if 7200 is already in use
```

**Import seems stuck:**
```bash
# Check import status
curl http://localhost:7200/rest/repositories/d3fend/import/server
# Or use the Workbench UI → Import → Server files
```

**No results from queries:**
```bash
# Verify triple count
curl -H "Accept: application/sparql-results+json" \
  "http://localhost:7200/repositories/d3fend?query=SELECT+(COUNT(*)+as+%3Fc)+WHERE+%7B+%3Fs+%3Fp+%3Fo+%7D"
```

**Stop everything:**
```bash
docker compose down
```

---

## What's Next (Phase 2 — Neo4j)

Once you've validated SPARQL results here, we'll:
1. Set up Neo4j alongside GraphDB in the same compose file
2. Use **neosemantics (n10s)** to import D3FEND as a property graph
3. Write equivalent Cypher queries
4. Compare: query complexity, result richness, LLM integration ease
