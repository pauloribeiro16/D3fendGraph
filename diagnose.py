#!/usr/bin/env python3
"""
D3FEND Diagnostic Script
========================
Run this to figure out why queries return 0 results.
Usage: python3 diagnose.py
"""

import json
import urllib.request
import urllib.parse

GRAPHDB_URL = "http://localhost:7200"
REPO_ID     = "d3fend"
SPARQL_URL  = f"{GRAPHDB_URL}/repositories/{REPO_ID}"

def sparql(query, label=""):
    params = urllib.parse.urlencode({"query": query})
    req = urllib.request.Request(
        f"{SPARQL_URL}?{params}",
        headers={"Accept": "application/sparql-results+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return data.get("results", {}).get("bindings", [])
    except Exception as e:
        return [{"ERROR": {"value": str(e)}}]

def p(label, bindings, key=None):
    print(f"\n{'─'*60}")
    print(f"  {label}")
    if not bindings:
        print("  → (no results)")
    elif "ERROR" in bindings[0]:
        print(f"  → ERROR: {bindings[0]['ERROR']['value']}")
    else:
        for b in bindings[:15]:
            if key:
                print(f"  → {b.get(key, b)['value']}")
            else:
                row = " | ".join(f"{k}={v['value'][:80]}" for k,v in b.items())
                print(f"  → {row}")

# ── 1. Total triple count ────────────────────────────────────────────────────
print("\n" + "═"*60)
print("  D3FEND DIAGNOSTICS")
print("═"*60)

r = sparql("SELECT (COUNT(*) as ?c) WHERE { ?s ?p ?o }")
p("TOTAL TRIPLES in repository", r, "c")

# ── 2. What named graphs exist? ──────────────────────────────────────────────
r = sparql("SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } }")
p("NAMED GRAPHS found", r, "g")

# ── 3. Triple count per graph ────────────────────────────────────────────────
r = sparql("SELECT ?g (COUNT(*) as ?c) WHERE { GRAPH ?g { ?s ?p ?o } } GROUP BY ?g ORDER BY DESC(?c)")
p("TRIPLES PER GRAPH", r)

# ── 4. What prefixes/namespaces are present? ─────────────────────────────────
r = sparql("""
SELECT DISTINCT (STRBEFORE(STR(?s), "#") as ?ns)
WHERE { ?s ?p ?o }
LIMIT 20
""")
p("NAMESPACES in use (first 20)", r, "ns")

# ── 5. Sample subjects ───────────────────────────────────────────────────────
r = sparql("SELECT DISTINCT ?s WHERE { ?s ?p ?o } LIMIT 10")
p("SAMPLE SUBJECTS (first 10)", r, "s")

# ── 6. Try D3FEND namespace directly ─────────────────────────────────────────
r = sparql("""
SELECT ?s ?p ?o WHERE {
  ?s ?p ?o
  FILTER(CONTAINS(STR(?s), "d3fend"))
} LIMIT 5
""")
p("ANY TRIPLES containing 'd3fend' in subject URI", r)

# ── 7. Check all graphs including default ────────────────────────────────────
r = sparql("""
SELECT ?s ?p ?o WHERE {
  { ?s ?p ?o } UNION { GRAPH ?g { ?s ?p ?o } }
  FILTER(CONTAINS(STR(?s), "d3fend"))
} LIMIT 5
""")
p("D3FEND triples (default + named graphs combined)", r)

# ── 8. Any rdfs:label triples? ───────────────────────────────────────────────
r = sparql("""
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?s ?l WHERE { ?s rdfs:label ?l } LIMIT 10
""")
p("ANY rdfs:label triples", r)

# ── 9. What rulesets / reasoning is configured? ──────────────────────────────
try:
    req = urllib.request.Request(
        f"{GRAPHDB_URL}/rest/repositories/{REPO_ID}",
        headers={"Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        config = json.loads(resp.read().decode())
    print(f"\n{'─'*60}")
    print(f"  REPOSITORY CONFIG")
    print(f"  → {json.dumps(config, indent=2)[:500]}")
except Exception as e:
    print(f"\n  Could not fetch repo config: {e}")

# ── 10. Import status ─────────────────────────────────────────────────────────
try:
    req = urllib.request.Request(
        f"{GRAPHDB_URL}/rest/repositories/{REPO_ID}/import/server",
        headers={"Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        status = json.loads(resp.read().decode())
    print(f"\n{'─'*60}")
    print(f"  IMPORT STATUS")
    if not status:
        print("  → No import history found (file may not have been imported yet)")
    for item in status[:5]:
        print(f"  → {item.get('name','?')} | status={item.get('status','?')} | message={item.get('message','')[:100]}")
except Exception as e:
    print(f"\n  Could not fetch import status: {e}")

print("\n" + "═"*60)
print("  DIAGNOSIS COMPLETE")
print("  Share the output above to identify the issue.")
print("═"*60 + "\n")
