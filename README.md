# UnifiedThreatGraph Test Environment

> **Aggregating CAPEC, CWE, MITRE ATT&CK, ATLAS & D3FEND**
> **Phase 1 of 2** — SPARQL/GraphDB evaluation.

This project integrates multiple MITRE security frameworks into a single GraphDB (RDF) knowledge base and provides a visualization dashboard to explore them.

## Prerequisites

- **Node.js**: required for the Visualization Backend.
- **Docker + Docker Compose**: installed and running (e.g., Docker Desktop on Mac/Windows).
- **Python 3.8+**: required for the ingestion scripts and the frontend server.
- **Internet access**: necessary to download the D3FEND ontology and the STIX/JSON datasets.

---

## Step 1 — Start GraphDB and Load D3FEND

The `bootstrap.sh` script starts GraphDB in a Docker container, creates the required repository with OWL-RL reasoning, and downloads & ingests the D3FEND ontology.

```bash
# Make the bootstrap script executable
chmod +x scripts/bootstrap.sh

# Run the script (Wait 1-3 minutes)
./scripts/bootstrap.sh
```

**Expected output:**
```text
[INFO] GraphDB is up!
[INFO] Repository 'd3fend' created.
[INFO] ✅ D3FEND loaded successfully with ~194000 triples!
```

---

## Step 2 — Inject Secondary Frameworks (CAPEC, CWE, ATT&CK, ATLAS)

We need to download the secondary STIX/JSON datasets and inject them into GraphDB.

```bash
# 1. Create a Python Virtual Environment
python3 -m venv venv
source venv/bin/activate

# 2. Install python dependencies
pip install requests neo4j

# 3. Create the data directory
mkdir -p data

# 4. Download datasets
# Fetch CWE
python3 scripts/fetch_cwe.py
# Download CAPEC
curl -s -L -o data/capec.json "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
# Download ATT&CK
curl -s -L -o data/mitre_attack_enterprise.json "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
# Download ATLAS
curl -s -L -o data/atlas.json "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"

# 5. Inject threats into GraphDB and Neo4j
python3 scripts/inject_threats.py
```

---

## Step 3 — Start the Visualization Server

The project includes a web visualization dashboard and a Node.js proxy server. You will need two terminal windows for this step.

**Terminal 1 (Backend API proxy):**
```bash
cd visualization/backend
npm install
node server.js
# Runs on port 3000
```

**Terminal 2 (Frontend UI):**
```bash
cd visualization/frontend
python3 -m http.server 8001
# Runs on port 8001
```

Access the Visualizer Application at **[http://localhost:8001](http://localhost:8001)**.

---

## Step 4 — Run the Query Suite

Now that the GraphDB repository is populated with all frameworks, you can test the SPARQL queries.

```bash
# Activate python env (if not already activated)
source venv/bin/activate

# Run all predefined queries
python3 run_queries.py

# Run only secondary framework queries (CAPEC, CWE, ATLAS)
python3 run_queries.py --query secondary_frameworks

# Run only cross-framework queries
python3 run_queries.py --query cross_framework

# Run an interactive keyword search across D3FEND
python3 run_queries.py --search "ransomware"
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
| `Q9-Q11` | Overviews of CWE, CAPEC, and ATLAS |
| `Q12_injection_across_frameworks` | Cross-framework search for "injection" related vulnerabilities/patterns |
| `Q13_phishing_across_frameworks` | Cross-framework search for "phishing" related vulnerabilities/patterns |

---

## Explore the GraphDB Workbench

Open your browser at **http://localhost:7200**.
- Go to **Repositories** → confirm `d3fend` exists.
- Go to **SPARQL** to write custom queries directly against the knowledge graph.

### Troubleshooting

- **GraphDB doesn't start:** Run `docker compose logs graphdb` (usually a port 7200 conflict).
- **Import fails / stops:** Ensure your `config.ttl` is updated for GraphDB 10.6.0 (removing FreeSail references).
- **No results from queries in GraphDB:** Check the GraphDB repository triple count using `SELECT (COUNT(*) as ?c) WHERE { ?s ?p ?o }`. Note that some queries expect the `d3fend` name to be exact due to graph bindings. 

---

## What's Next (Phase 2 — Neo4j)

We have already set up a Neo4j container in the `docker-compose.yml`.
1. Use **neosemantics (n10s)** to analyze the GraphDB loaded STIX objects.
2. Write equivalent Cypher queries for the property graph.
3. Compare SPARQL and Cypher approaches.
