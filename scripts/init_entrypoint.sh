#!/usr/bin/env bash
set -euo pipefail

# Environment variables (passed by docker-compose)
GRAPHDB_URL=${GRAPHDB_URL:-"http://graphdb:7200"}
REPO_ID=${REPO_ID:-"d3fend"}
NEO4J_URI=${NEO4J_URI:-"bolt://neo4j:7687"}
NEO4J_AUTH_STRING=${NEO4J_AUTH_STRING:-"neo4j/d3fendtest"}

echo "[INFO] Waiting for GraphDB to start at $GRAPHDB_URL..."
until curl -sf "$GRAPHDB_URL/rest/repositories" > /dev/null; do
  echo -n "."
  sleep 5
done
echo -e "\n[INFO] GraphDB is up!"

echo "[INFO] Waiting for Neo4j to start at $NEO4J_URI..."
until python -c "
from neo4j import GraphDatabase
user, pw = '$NEO4J_AUTH_STRING'.split('/')
try:
  driver = GraphDatabase.driver('$NEO4J_URI', auth=(user, pw))
  driver.verify_connectivity()
  print('Neo4j connection successful')
except Exception as e:
  exit(1)
" 2>/dev/null; do
  echo -n "."
  sleep 5
done
echo -e "\n[INFO] Neo4j is up!"

# --- Load D3FEND into GraphDB ---
echo "[INFO] Check if D3FEND repository exists..."
EXISTING=$(curl -sf "$GRAPHDB_URL/rest/repositories" | grep -c "\"id\":\"$REPO_ID\"" || true)
if [ "$EXISTING" -eq 0 ]; then
  echo "[INFO] Creating repository..."
  curl -sf -X POST "$GRAPHDB_URL/rest/repositories" \
    -H "Content-Type: multipart/form-data" \
    -F "config=@/app/scripts/config.ttl;type=text/turtle"
fi

TRIPLE_COUNT=$(curl -sf -H "Accept: application/sparql-results+json" \
  -G "$GRAPHDB_URL/repositories/$REPO_ID" \
  --data-urlencode "query=SELECT (COUNT(*) as ?count) WHERE { ?s ?p ?o }" \
  | python -c "import sys,json; data=json.load(sys.stdin); print(data['results']['bindings'][0]['count']['value'])" 2>/dev/null || echo "0")

if [ "$TRIPLE_COUNT" -eq 0 ]; then
  echo "[INFO] Downloading D3FEND ontology..."
  curl -L -s -o /tmp/d3fend.ttl "https://d3fend.mitre.org/ontologies/d3fend.ttl"
  
  echo "[INFO] Forcing local GraphDB load via API (since we're external to the volume)..."
  # Use the standard statements API to upload the file directly
  curl -X POST -H "Content-Type: application/x-turtle" \
    -T /tmp/d3fend.ttl \
    "${GRAPHDB_URL}/repositories/${REPO_ID}/statements?context=%3Chttps%3A%2F%2Fd3fend.mitre.org%2Fontologies%2Fd3fend.owl%3E"
  echo "[INFO] D3FEND loaded into GraphDB!"
else
  echo "[INFO] D3FEND already loaded ($TRIPLE_COUNT triples). Skipping."
fi

# --- Download STIX Data ---
mkdir -p /app/data
echo "[INFO] Downloading STIX datasets..."

echo "Fetching CWE..."
python3 /app/scripts/fetch_cwe.py /app/data

echo "Downloading CAPEC..."
curl -s -L -o /app/data/capec.json "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

echo "Downloading ATT&CK Enterprise..."
curl -s -L -o /app/data/mitre_attack_enterprise.json "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

echo "Downloading ATT&CK Mobile..."
curl -s -L -o /app/data/mitre_attack_mobile.json "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"

echo "Downloading ATLAS..."
curl -s -L -o /app/data/atlas.json "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"

# --- Inject into Neo4j ---
echo "[INFO] Injecting STIX data into Neo4j..."
export DATA_DIR=/app/data
python3 /app/scripts/inject_threats.py

echo "[INFO] Initialization completely finished! Container will now exit gracefully."
exit 0
