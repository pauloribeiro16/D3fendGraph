#!/usr/bin/env bash
# =============================================================================
# Neo4j + n10s Bootstrap — loads D3FEND TTL as a property graph
# Usage: ./neo4j_setup.sh [path/to/d3fend.ttl]
# =============================================================================

set -euo pipefail

NEO4J_URL="http://localhost:7474"
BOLT_URL="bolt://localhost:7687"
NEO4J_USER="neo4j"
NEO4J_PASS="d3fendtest"
D3FEND_FILE="${1:-./files/graphdb/import/d3fend.ttl}"
NEO4J_IMPORT_DIR="./neo4j/import"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

cypher() {
  # Run a Cypher statement via HTTP API
  local stmt="$1"
  curl -sf -X POST "$NEO4J_URL/db/neo4j/tx/commit" \
    -H "Content-Type: application/json" \
    -u "$NEO4J_USER:$NEO4J_PASS" \
    -d "{\"statements\":[{\"statement\":$(echo "$stmt" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}]}"
}

cypher_result() {
  local stmt="$1"
  cypher "$stmt" | python3 -c "
import json,sys
data=json.load(sys.stdin)
errors=data.get('errors',[])
if errors: print('ERROR:', errors[0].get('message',''))
else:
  results=data.get('results',[{}])[0]
  cols=results.get('columns',[])
  for row in results.get('data',[]):
    vals=row.get('row',[])
    print(' | '.join(f'{cols[i]}={vals[i]}' for i in range(len(cols))))
"
}

# ── Step 1: Start Neo4j ───────────────────────────────────────────────────────
info "Starting Neo4j container..."
docker compose up -d neo4j

info "Waiting for Neo4j to be ready (may take 60s on first run — downloads plugins)..."
RETRIES=24
until curl -sf "$NEO4J_URL" > /dev/null 2>&1; do
  RETRIES=$((RETRIES - 1))
  [ "$RETRIES" -eq 0 ] && error "Neo4j did not start. Check: docker compose logs neo4j"
  echo -n "."
  sleep 5
done
echo ""

# Extra wait for bolt
sleep 5
info "Neo4j is up!"

# ── Step 2: Initialise n10s (neosemantics) ────────────────────────────────────
info "Initialising neosemantics (n10s)..."

# Create uniqueness constraint required by n10s
cypher "CREATE CONSTRAINT n10s_unique_uri IF NOT EXISTS FOR (r:Resource) REQUIRE r.uri IS UNIQUE" > /dev/null

# Init graph config — MAP mode preserves URIs, handles D3FEND namespace
INIT_RESULT=$(cypher "
CALL n10s.graphconfig.init({
  handleVocabUris: 'MAP',
  handleMultival: 'ARRAY',
  handleRDFTypes: 'LABELS_AND_NODES',
  keepLangTag: false,
  keepCustomDataTypes: false
})
" 2>&1)

echo "$INIT_RESULT" | grep -q "error\|ERROR" && warn "n10s init may have already run (OK if re-running)" || info "n10s initialised"

# ── Step 3: Copy TTL to Neo4j import dir ──────────────────────────────────────
mkdir -p "$NEO4J_IMPORT_DIR"

if [ ! -f "$D3FEND_FILE" ]; then
  info "Downloading d3fend.ttl..."
  curl -L --progress-bar -o "$NEO4J_IMPORT_DIR/d3fend.ttl" \
    "http://d3fend.mitre.org/ontologies/d3fend.ttl"
else
  info "Copying $D3FEND_FILE → $NEO4J_IMPORT_DIR/d3fend.ttl"
  cp "$D3FEND_FILE" "$NEO4J_IMPORT_DIR/d3fend.ttl"
fi

# ── Step 4: Import TTL via n10s ───────────────────────────────────────────────
info "Importing D3FEND into Neo4j via n10s..."
info "This may take 2-5 minutes..."

IMPORT_RESULT=$(cypher "
CALL n10s.rdf.import.fetch(
  'file:///var/lib/neo4j/import/d3fend.ttl',
  'Turtle'
) YIELD triplesLoaded, triplesParsed, namespaces, extraInfo
RETURN triplesLoaded, triplesParsed
" 2>&1)

echo "$IMPORT_RESULT"

# ── Step 5: Verify ────────────────────────────────────────────────────────────
info "Verifying node count..."
cypher_result "MATCH (n) RETURN count(n) as totalNodes"

info "Sample D3FEND nodes..."
cypher_result "MATCH (n) WHERE n.uri CONTAINS 'd3fend' RETURN n.uri, labels(n) LIMIT 5"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Neo4j ready!${NC}"
echo -e "  Browser UI:  ${YELLOW}http://localhost:7474${NC}"
echo -e "  Credentials: ${YELLOW}neo4j / d3fendtest${NC}"
echo -e "  Run queries: ${YELLOW}python3 neo4j_queries.py${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
