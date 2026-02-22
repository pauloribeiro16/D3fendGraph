#!/usr/bin/env python3
"""
D3FEND Neo4j Cypher Query Suite
================================
Equivalent queries to run_queries.py but using Cypher against Neo4j.
Allows direct comparison: SPARQL/GraphDB vs Cypher/Neo4j

Usage: python3 neo4j_queries.py
       python3 neo4j_queries.py --search "credential"
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.parse
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
NEO4J_URL  = "http://localhost:7474"
NEO4J_USER = "neo4j"
NEO4J_PASS = "d3fendtest"
TX_URL     = f"{NEO4J_URL}/db/neo4j/tx/commit"

D3F = "http://d3fend.mitre.org/ontologies/d3fend.owl#"


# ═════════════════════════════════════════════════════════════════════════════
# CYPHER QUERY LIBRARY
# Direct equivalents of the SPARQL queries
# ═════════════════════════════════════════════════════════════════════════════

QUERIES = {

  # ── Technique → Countermeasure ─────────────────────────────────────────────

  "Q1_all_attack_to_d3fend": {
    "label": "All ATT&CK techniques → D3FEND countermeasures",
    "category": "technique_mapping",
    "query": """
MATCH (defense:Resource)-[:COUNTERS]->(attack:Resource)
WHERE defense.label[0] IS NOT NULL
  AND attack.label[0] IS NOT NULL
RETURN DISTINCT
  attack.label[0]  AS attackLabel,
  defense.label[0] AS defensiveLabel,
  defense.`d3fend-id`[0] AS d3fID
ORDER BY attackLabel, defensiveLabel
LIMIT 200
"""
  },

  "Q2_credential_attacks": {
    "label": "Countermeasures for credential-based attacks",
    "category": "technique_mapping",
    "query": """
MATCH (defense:Resource)-[:COUNTERS]->(attack:Resource)
WHERE toLower(attack.label[0]) CONTAINS 'credential'
RETURN DISTINCT
  attack.label[0]       AS attackLabel,
  defense.label[0]      AS defensiveLabel,
  defense.definition[0] AS definition,
  defense.`d3fend-id`[0]  AS d3fID
ORDER BY attackLabel, defensiveLabel
"""
  },

  "Q3_data_transfer_attacks": {
    "label": "Countermeasures for data transfer/exfiltration attacks",
    "category": "technique_mapping",
    "query": """
MATCH (defense:Resource)-[:COUNTERS]->(attack:Resource)
WHERE toLower(attack.label[0]) CONTAINS 'transfer'
   OR toLower(attack.label[0]) CONTAINS 'exfil'
RETURN DISTINCT
  attack.label[0]       AS attackLabel,
  defense.label[0]      AS defensiveLabel,
  defense.`d3fend-id`[0] AS d3fID
ORDER BY attackLabel, defensiveLabel
"""
  },

  # ── Category / Tactic ──────────────────────────────────────────────────────

  "Q4_tactic_overview": {
    "label": "D3FEND tactic categories — technique count per tactic",
    "category": "category_tactics",
    "query": """
MATCH (technique:Resource)-[:enables]->(tactic:Resource)
WHERE tactic.uri IN [
  'http://d3fend.mitre.org/ontologies/d3fend.owl#Harden',
  'http://d3fend.mitre.org/ontologies/d3fend.owl#Detect',
  'http://d3fend.mitre.org/ontologies/d3fend.owl#Isolate',
  'http://d3fend.mitre.org/ontologies/d3fend.owl#Deceive',
  'http://d3fend.mitre.org/ontologies/d3fend.owl#Evict'
]
RETURN
  tactic.label[0] AS tacticLabel,
  count(DISTINCT technique) AS techniqueCount
ORDER BY techniqueCount DESC
"""
  },

  "Q5_harden_techniques": {
    "label": "All 'Harden' techniques (GDPR Art.32 / CRA relevant)",
    "category": "category_tactics",
    "query": """
MATCH (technique:Resource)-[:enables]->
      (tactic:Resource {uri: 'http://d3fend.mitre.org/ontologies/d3fend.owl#Harden'})
RETURN DISTINCT
  technique.label[0]      AS techniqueLabel,
  technique.definition[0] AS definition,
  technique.`d3fend-id`[0]  AS d3fID
ORDER BY techniqueLabel
"""
  },

  "Q6_detect_techniques": {
    "label": "All 'Detect' techniques",
    "category": "category_tactics",
    "query": """
MATCH (technique:Resource)-[:enables]->
      (tactic:Resource {uri: 'http://d3fend.mitre.org/ontologies/d3fend.owl#Detect'})
RETURN DISTINCT
  technique.label[0]      AS techniqueLabel,
  technique.definition[0] AS definition,
  technique.`d3fend-id`[0]  AS d3fID
ORDER BY techniqueLabel
"""
  },

  "Q7_coverage_priority": {
    "label": "Top techniques by ATT&CK coverage breadth",
    "category": "category_tactics",
    "query": """
MATCH (technique:Resource)-[:COUNTERS]->(attack:Resource)
WHERE technique.`d3fend-id`[0] IS NOT NULL
RETURN
  technique.label[0]     AS techniqueLabel,
  technique.`d3fend-id`[0] AS d3fID,
  count(DISTINCT attack) AS attacksCovered
ORDER BY attacksCovered DESC
LIMIT 20
"""
  },

  "Q8_data_protection": {
    "label": "Data protection countermeasures (encryption, access, auth)",
    "category": "category_tactics",
    "query": """
MATCH (technique:Resource)
WHERE technique.`d3fend-id`[0] IS NOT NULL
  AND (
    toLower(technique.label[0]) CONTAINS 'encrypt'   OR
    toLower(technique.label[0]) CONTAINS 'credential' OR
    toLower(technique.label[0]) CONTAINS 'access'     OR
    toLower(technique.label[0]) CONTAINS 'authenticat'
  )
RETURN DISTINCT
  technique.label[0]      AS techniqueLabel,
  technique.definition[0] AS definition,
  technique.`d3fend-id`[0]  AS d3fID
ORDER BY techniqueLabel
"""
  },

}


# ═════════════════════════════════════════════════════════════════════════════
# CYPHER CLIENT
# ═════════════════════════════════════════════════════════════════════════════

def run_cypher(query: str) -> dict:
    """Execute a Cypher query via HTTP transactional API."""
    import base64
    payload = json.dumps({"statements": [{"statement": query}]}).encode()
    token = base64.b64encode(f"{NEO4J_USER}:{NEO4J_PASS}".encode()).decode()
    req = urllib.request.Request(
        TX_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {token}"
        }
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            elapsed = round((time.time() - start) * 1000)
            data = json.loads(resp.read().decode())
            errors = data.get("errors", [])
            if errors:
                return {"ok": False, "error": errors[0].get("message", "Unknown"), "ms": elapsed, "rows": []}
            results = data.get("results", [{}])[0]
            cols = results.get("columns", [])
            rows = [dict(zip(cols, r.get("row", []))) for r in results.get("data", [])]
            return {"ok": True, "rows": rows, "count": len(rows), "ms": elapsed}
    except Exception as e:
        return {"ok": False, "error": str(e), "ms": 0, "rows": [], "count": 0}


def check_neo4j() -> bool:
    try:
        import base64
        token = base64.b64encode(f"{NEO4J_USER}:{NEO4J_PASS}".encode()).decode()
        req = urllib.request.Request(
            f"{NEO4J_URL}/db/neo4j/tx/commit",
            data=json.dumps({"statements": [{"statement": "RETURN 1"}]}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Basic {token}"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


# ═════════════════════════════════════════════════════════════════════════════
# REPORT
# ═════════════════════════════════════════════════════════════════════════════

def shorten(val, max_len=60):
    if val is None: return "—"
    s = str(val)
    return s[:max_len] + "…" if len(s) > max_len else s

def render_table(rows: list, max_rows: int = 8):
    if not rows:
        print("    (no results)")
        return
    cols = list(rows[0].keys())
    data = [[shorten(r.get(c)) for c in cols] for r in rows[:max_rows]]
    widths = [max(len(c), max((len(d[i]) for d in data), default=0)) for i, c in enumerate(cols)]
    sep = "  ┼  ".join("─" * w for w in widths)
    hdr = "  │  ".join(c.ljust(widths[i]) for i, c in enumerate(cols))
    print(f"    ┌─{sep}─┐")
    print(f"    │ {hdr} │")
    print(f"    ├─{sep}─┤")
    for row in data:
        line = "  │  ".join(c.ljust(widths[i]) for i, c in enumerate(row))
        print(f"    │ {line} │")
    print(f"    └─{sep}─┘")
    if len(rows) > max_rows:
        print(f"    … and {len(rows) - max_rows} more rows")


def run_all(filter_key=None):
    print("\n" + "═" * 70)
    print(f"  D3FEND Cypher Query Suite — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Endpoint: {TX_URL}")
    print("═" * 70)

    print("\n[CHECK] Neo4j connectivity... ", end="")
    if not check_neo4j():
        print("❌ FAILED")
        print(f"       Neo4j not reachable. Run: ./scripts/neo4j_setup.sh")
        sys.exit(1)
    print("✅ OK")

    # Node count
    r = run_cypher("MATCH (n) RETURN count(n) as c")
    if r["ok"] and r["rows"]:
        print(f"       Total nodes in graph: {r['rows'][0]['c']}")

    summary = []
    queries = {k: v for k, v in QUERIES.items() if filter_key is None or filter_key in k}

    for qid, meta in queries.items():
        print(f"\n{'─' * 70}")
        print(f"  [{meta['category'].upper()}] {meta['label']}")
        print(f"  Query ID: {qid}")
        print()
        result = run_cypher(meta["query"])
        if result["ok"]:
            print(f"  ✅ {result['count']} results in {result['ms']}ms\n")
            render_table(result["rows"])
        else:
            print(f"  ❌ ERROR: {result['error']}")
        summary.append({"id": qid, "ok": result["ok"], "count": result.get("count", 0), "ms": result["ms"]})

    print(f"\n{'═' * 70}")
    print("  SUMMARY")
    print(f"{'─' * 70}")
    print(f"  {'Query':<40} {'Status':<8} {'Results':<10} {'Time(ms)'}")
    print(f"  {'─' * 38} {'─' * 6} {'─' * 8} {'─' * 8}")
    for r in summary:
        print(f"  {r['id']:<40} {'✅' if r['ok'] else '❌':<8} {r['count']:<10} {r['ms']}")
    print("═" * 70 + "\n")


# ── Keyword search ────────────────────────────────────────────────────────────

def run_keyword(keyword: str):
    print(f"\n🔍 Searching D3FEND (Neo4j) for: '{keyword}'\n")
    q = f"""
MATCH (technique:Resource)-[:COUNTERS]->(attack:Resource)
WHERE toLower(technique.label[0]) CONTAINS '{keyword.lower()}'
   OR toLower(attack.label[0]) CONTAINS '{keyword.lower()}'
RETURN DISTINCT
  technique.label[0] AS techniqueLabel,
  technique.`d3fend-id`[0] AS d3fID,
  attack.label[0] AS attackLabel
ORDER BY techniqueLabel
LIMIT 50
"""
    result = run_cypher(q)
    if result["ok"]:
        print(f"  Found {result['count']} results in {result['ms']}ms\n")
        render_table(result["rows"], max_rows=20)
    else:
        print(f"  Error: {result['error']}")


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="D3FEND Neo4j Cypher Query Suite")
    parser.add_argument("--query",  help="Run only queries matching this string")
    parser.add_argument("--search", help="Search by keyword")
    args = parser.parse_args()

    if args.search:
        if not check_neo4j():
            print("❌ Neo4j not reachable. Run: ./scripts/neo4j_setup.sh")
            sys.exit(1)
        run_keyword(args.search)
    else:
        run_all(filter_key=args.query)
