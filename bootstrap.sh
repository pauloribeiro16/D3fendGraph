#!/usr/bin/env bash
# =============================================================================
# D3FEND Bootstrap Script
# Downloads the D3FEND ontology and loads it into GraphDB
# Usage: ./scripts/bootstrap.sh
# =============================================================================

set -euo pipefail

GRAPHDB_URL="http://localhost:7200"
REPO_ID="d3fend"
IMPORT_DIR="./graphdb/import"
D3FEND_URL="https://d3fend.mitre.org/ontologies/d3fend.ttl"
D3FEND_FILE="$IMPORT_DIR/d3fend.ttl"

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Step 1: Check Docker is running ──────────────────────────────────────────
info "Checking Docker..."
docker info > /dev/null 2>&1 || error "Docker is not running. Please start Docker first."

# ── Step 2: Start GraphDB ────────────────────────────────────────────────────
info "Starting GraphDB container..."
docker compose up -d

info "Waiting for GraphDB to be healthy (may take 30-60s)..."
RETRIES=20
until curl -sf "$GRAPHDB_URL/rest/repositories" > /dev/null; do
  RETRIES=$((RETRIES - 1))
  if [ "$RETRIES" -eq 0 ]; then
    error "GraphDB did not start in time. Check: docker compose logs graphdb"
  fi
  echo -n "."
  sleep 5
done
echo ""
info "GraphDB is up!"

# ── Step 3: Create repository ────────────────────────────────────────────────
info "Creating D3FEND repository..."

# Check if repo already exists
EXISTING=$(curl -sf "$GRAPHDB_URL/rest/repositories" | grep -c "\"id\":\"$REPO_ID\"" || true)
if [ "$EXISTING" -gt 0 ]; then
  warn "Repository '$REPO_ID' already exists. Skipping creation."
else
  curl -sf -X POST "$GRAPHDB_URL/rest/repositories" \
    -H "Content-Type: multipart/form-data" \
    -F "config=@./config.ttl;type=text/turtle" \
    && info "Repository '$REPO_ID' created." \
    || error "Failed to create repository. Check GraphDB logs."
fi

# ── Step 4: Download D3FEND ───────────────────────────────────────────────────
mkdir -p "$IMPORT_DIR"

if [ -f "$D3FEND_FILE" ]; then
  warn "D3FEND ontology already downloaded at $D3FEND_FILE. Skipping download."
  warn "Delete the file and re-run to force a fresh download."
else
  info "Downloading D3FEND ontology from $D3FEND_URL ..."
  curl -L -o "$D3FEND_FILE" "$D3FEND_URL" \
    && info "Downloaded to $D3FEND_FILE" \
    || error "Failed to download D3FEND. Check your internet connection."
fi

# ── Step 5: Load D3FEND into GraphDB ─────────────────────────────────────────
info "Loading D3FEND ontology into GraphDB repository '$REPO_ID'..."
info "This may take 1-3 minutes depending on your machine..."

# Copy to the GraphDB import folder (mapped volume)
if [ "$D3FEND_FILE" != "$IMPORT_DIR/d3fend.ttl" ]; then
  cp "$D3FEND_FILE" "$IMPORT_DIR/d3fend.ttl"
fi

# Trigger import via REST API
RESPONSE=$(curl -sf -X POST \
  "$GRAPHDB_URL/rest/repositories/$REPO_ID/import/server" \
  -H "Content-Type: application/json" \
  -d '{
    "fileNames": ["d3fend.ttl"],
    "importSettings": {
      "context": "https://d3fend.mitre.org/ontologies/d3fend.owl",
      "replaceGraphs": ["https://d3fend.mitre.org/ontologies/d3fend.owl"]
    }
  }' 2>&1) || true

info "Import triggered. Waiting for completion..."
sleep 10

# Poll import status
for i in $(seq 1 12); do
  STATUS=$(curl -sf "$GRAPHDB_URL/rest/repositories/$REPO_ID/import/server" 2>/dev/null || echo "[]")
  DONE=$(echo "$STATUS" | grep -c '"status":"DONE"' || true)
  ERROR=$(echo "$STATUS" | grep -c '"status":"ERROR"' || true)

  if [ "$ERROR" -gt 0 ]; then
    warn "Import may have had issues. Check the GraphDB workbench."
    break
  fi
  if [ "$DONE" -gt 0 ]; then
    info "Import complete!"
    break
  fi
  echo -n "."
  sleep 10
done
echo ""

# ── Step 6: Verify ────────────────────────────────────────────────────────────
info "Verifying data load with a quick triple count..."
TRIPLE_COUNT=$(curl -sf \
  -H "Accept: application/sparql-results+json" \
  -G "$GRAPHDB_URL/repositories/$REPO_ID" \
  --data-urlencode "query=SELECT (COUNT(*) as ?count) WHERE { ?s ?p ?o }" \
  | python3 -c "import sys,json; data=json.load(sys.stdin); print(data['results']['bindings'][0]['count']['value'])" 2>/dev/null || echo "unknown")

info "Triple count in repository: $TRIPLE_COUNT"

if [ "$TRIPLE_COUNT" == "0" ] || [ "$TRIPLE_COUNT" == "unknown" ]; then
  warn "No triples found. The import may still be running."
  warn "Check the GraphDB Workbench at $GRAPHDB_URL → Import → Server files"
else
  info "✅ D3FEND loaded successfully with $TRIPLE_COUNT triples!"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup complete!${NC}"
echo -e "  GraphDB Workbench: ${YELLOW}$GRAPHDB_URL${NC}"
echo -e "  SPARQL Endpoint:   ${YELLOW}$GRAPHDB_URL/repositories/$REPO_ID${NC}"
echo -e "  Run queries:       ${YELLOW}python3 scripts/run_queries.py${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
