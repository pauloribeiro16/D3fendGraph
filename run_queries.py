#!/usr/bin/env python3
"""
D3FEND SPARQL Test Runner
=========================
Runs all query suites against GraphDB and produces a structured report.
Usage: python3 scripts/run_queries.py [--query Q1] [--attack "credential"]
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
GRAPHDB_URL = "http://localhost:7200"
REPO_ID     = "d3fend"
SPARQL_URL  = f"{GRAPHDB_URL}/repositories/{REPO_ID}"


# ═════════════════════════════════════════════════════════════════════════════
# QUERY LIBRARY
# ═════════════════════════════════════════════════════════════════════════════

QUERIES = {

  # ── Technique → Countermeasure ─────────────────────────────────────────────

  "Q1_all_attack_to_d3fend": {
    "label": "All ATT&CK techniques → D3FEND countermeasures",
    "category": "technique_mapping",
    "query": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
  ?attackLabel
  ?defensiveLabel
  ?d3fID
WHERE {
  ?defensiveTechnique rdfs:subClassOf* d3f:DefensiveTechnique ;
                      rdfs:label ?defensiveLabel ;
                      d3f:counters ?attackTechnique .
  ?attackTechnique rdfs:label ?attackLabel .
  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
}
ORDER BY ?attackLabel ?defensiveLabel
LIMIT 200
"""
  },

  "Q2_credential_attacks": {
    "label": "Countermeasures for credential-based attacks",
    "category": "technique_mapping",
    "query": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
  ?attackLabel
  ?defensiveLabel
  ?definition
  ?d3fID
WHERE {
  ?defensiveTechnique rdfs:subClassOf* d3f:DefensiveTechnique ;
                      rdfs:label ?defensiveLabel ;
                      d3f:counters ?attackTechnique .
  ?attackTechnique rdfs:label ?attackLabel .
  OPTIONAL { ?defensiveTechnique d3f:definition ?definition . }
  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
  FILTER(CONTAINS(LCASE(?attackLabel), "credential"))
}
ORDER BY ?attackLabel ?defensiveLabel
"""
  },

  "Q3_data_exfil_attacks": {
    "label": "Countermeasures for data exfiltration attacks",
    "category": "technique_mapping",
    "query": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
  ?attackLabel
  ?defensiveLabel
  ?d3fID
WHERE {
  ?defensiveTechnique rdfs:subClassOf* d3f:DefensiveTechnique ;
                      rdfs:label ?defensiveLabel ;
                      d3f:counters ?attackTechnique .
  ?attackTechnique rdfs:label ?attackLabel .
  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
  FILTER(CONTAINS(LCASE(?attackLabel), "exfil"))
}
ORDER BY ?attackLabel ?defensiveLabel
"""
  },

  # ── Category / Tactic ──────────────────────────────────────────────────────

  "Q4_tactic_overview": {
    "label": "D3FEND tactic categories — technique count per tactic",
    "category": "category_tactics",
    "query": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?tacticLabel (COUNT(DISTINCT ?technique) AS ?techniqueCount)
WHERE {
  VALUES ?tactic { d3f:Harden d3f:Detect d3f:Isolate d3f:Deceive d3f:Evict }
  ?tactic rdfs:label ?tacticLabel .
  ?technique d3f:enables ?tactic .
}
GROUP BY ?tacticLabel
ORDER BY DESC(?techniqueCount)
"""
  },

  "Q5_harden_techniques": {
    "label": "All 'Harden' techniques (most relevant to GDPR Art.32 / CRA)",
    "category": "category_tactics",
    "query": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT DISTINCT
  ?techniqueLabel
  ?definition
  ?d3fID
WHERE {
  ?technique d3f:enables d3f:Harden ;
             rdfs:label ?techniqueLabel .
  OPTIONAL { ?technique d3f:definition ?definition . }
  OPTIONAL { ?technique d3f:d3fend-id ?d3fID . }
}
ORDER BY ?techniqueLabel
"""
  },

  "Q6_detect_techniques": {
    "label": "All 'Detect' techniques",
    "category": "category_tactics",
    "query": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT DISTINCT
  ?techniqueLabel
  ?definition
  ?d3fID
WHERE {
  ?technique d3f:enables d3f:Detect ;
             rdfs:label ?techniqueLabel .
  OPTIONAL { ?technique d3f:definition ?definition . }
  OPTIONAL { ?technique d3f:d3fend-id ?d3fID . }
}
ORDER BY ?techniqueLabel
"""
  },

  "Q7_coverage_priority": {
    "label": "Top techniques by ATT&CK coverage (controls with broadest reach)",
    "category": "category_tactics",
    "query": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT
  ?techniqueLabel
  ?d3fID
  (COUNT(DISTINCT ?attackTechnique) AS ?attacksCovered)
WHERE {
  ?technique rdfs:subClassOf* d3f:DefensiveTechnique ;
             rdfs:label ?techniqueLabel ;
             d3f:counters ?attackTechnique .
  OPTIONAL { ?technique d3f:d3fend-id ?d3fID . }
}
GROUP BY ?techniqueLabel ?d3fID
ORDER BY DESC(?attacksCovered)
LIMIT 20
"""
  },

  "Q8_data_protection": {
    "label": "Data protection countermeasures (encryption, access control, auth)",
    "category": "category_tactics",
    "query": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
  ?techniqueLabel
  ?definition
  ?d3fID
WHERE {
  ?technique rdfs:subClassOf* d3f:DefensiveTechnique ;
             rdfs:label ?techniqueLabel .
  OPTIONAL { ?technique d3f:definition ?definition . }
  OPTIONAL { ?technique d3f:d3fend-id ?d3fID . }
  FILTER(
    CONTAINS(LCASE(?techniqueLabel), "encrypt")   ||
    CONTAINS(LCASE(?techniqueLabel), "credential") ||
    CONTAINS(LCASE(?techniqueLabel), "access")     ||
    CONTAINS(LCASE(?techniqueLabel), "authenticat")
  )
}
ORDER BY ?techniqueLabel
"""
  },

  "Q9_cwe_overview": {
    "label": "CWE Weaknesses Overview",
    "category": "secondary_frameworks",
    "query": """
PREFIX cwe: <http://cwe.mitre.org/cwe-schema#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?cweID ?cweLabel
WHERE {
  ?cweID a cwe:Weakness ;
         rdfs:label ?cweLabel .
}
ORDER BY ?cweID
LIMIT 20
"""
  },

  "Q10_capec_overview": {
    "label": "CAPEC Attack Patterns Overview",
    "category": "secondary_frameworks",
    "query": """
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX capec: <http://capec.mitre.org/data/definitions/>

SELECT ?capecID ?capecLabel
WHERE {
  ?capecID a capec:Pattern ;
           rdfs:label ?capecLabel .
}
ORDER BY ?capecID
LIMIT 20
"""
  },

  "Q11_atlas_overview": {
    "label": "ATLAS Attack Patterns Overview",
    "category": "secondary_frameworks",
    "query": """
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX atlas: <http://atlas.mitre.org/>

SELECT ?atlasID ?atlasLabel
WHERE {
  ?atlasID a atlas:Pattern ;
           rdfs:label ?atlasLabel .
}
ORDER BY ?atlasID
LIMIT 20
"""
  },

  "Q12_injection_across_frameworks": {
    "label": "Search for 'injection' across CWE, CAPEC, ATLAS, and ATT&CK",
    "category": "cross_framework",
    "query": """
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?framework ?id ?label
WHERE {
  {
     ?id a <http://cwe.mitre.org/cwe-schema#Weakness> ;
         rdfs:label ?label .
     BIND("CWE" AS ?framework)
  } UNION {
     ?id a <http://capec.mitre.org/data/definitions/Pattern> ;
         rdfs:label ?label .
     BIND("CAPEC" AS ?framework)
  } UNION {
     ?id a <http://atlas.mitre.org/Pattern> ;
         rdfs:label ?label .
     BIND("ATLAS" AS ?framework)
  } UNION {
     ?id a <http://attack.mitre.org/Pattern> ;
         rdfs:label ?label .
     BIND("ATT&CK" AS ?framework)
  }
  FILTER(CONTAINS(LCASE(?label), "injection"))
}
ORDER BY ?framework
LIMIT 50
"""
  },

  "Q13_phishing_across_frameworks": {
    "label": "Search for 'phishing' across CWE, CAPEC, ATLAS, and ATT&CK",
    "category": "cross_framework",
    "query": """
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?framework ?id ?label
WHERE {
  {
     ?id a <http://cwe.mitre.org/cwe-schema#Weakness> ;
         rdfs:label ?label .
     BIND("CWE" AS ?framework)
  } UNION {
     ?id a <http://capec.mitre.org/data/definitions/Pattern> ;
         rdfs:label ?label .
     BIND("CAPEC" AS ?framework)
  } UNION {
     ?id a <http://atlas.mitre.org/Pattern> ;
         rdfs:label ?label .
     BIND("ATLAS" AS ?framework)
  } UNION {
     ?id a <http://attack.mitre.org/Pattern> ;
         rdfs:label ?label .
     BIND("ATT&CK" AS ?framework)
  }
  FILTER(CONTAINS(LCASE(?label), "phishing"))
}
ORDER BY ?framework
LIMIT 50
"""
  },

}


# ═════════════════════════════════════════════════════════════════════════════
# SPARQL CLIENT
# ═════════════════════════════════════════════════════════════════════════════

def run_sparql(query: str, label: str = "") -> dict:
    """Execute a SPARQL query and return results + timing."""
    params = urllib.parse.urlencode({"query": query})
    req = urllib.request.Request(
        f"{SPARQL_URL}?{params}",
        headers={"Accept": "application/sparql-results+json"}
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            elapsed = round((time.time() - start) * 1000)
            data = json.loads(resp.read().decode())
            bindings = data.get("results", {}).get("bindings", [])
            return {"ok": True, "bindings": bindings, "count": len(bindings), "ms": elapsed}
    except urllib.error.URLError as e:
        return {"ok": False, "error": str(e), "ms": 0, "count": 0, "bindings": []}


def check_graphdb() -> bool:
    """Verify GraphDB is reachable and the repository exists."""
    try:
        req = urllib.request.Request(f"{GRAPHDB_URL}/rest/repositories",
                                     headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            repos = json.loads(resp.read().decode())
            ids = [r.get("id") for r in repos]
            return REPO_ID in ids
    except Exception:
        return False


# ═════════════════════════════════════════════════════════════════════════════
# REPORT
# ═════════════════════════════════════════════════════════════════════════════

def render_table(bindings: list, max_rows: int = 10):
    """Print a simple ASCII table of results."""
    if not bindings:
        print("    (no results)")
        return

    vars_ = list(bindings[0].keys())
    rows  = [[b.get(v, {}).get("value", "—")[:80] for v in vars_] for b in bindings[:max_rows]]
    widths = [max(len(v), max((len(r[i]) for r in rows), default=0)) for i, v in enumerate(vars_)]

    sep = "  ┼  ".join("─" * w for w in widths)
    hdr = "  │  ".join(v.ljust(widths[i]) for i, v in enumerate(vars_))

    print(f"    ┌─{sep}─┐")
    print(f"    │ {hdr} │")
    print(f"    ├─{sep}─┤")
    for row in rows:
        line = "  │  ".join(c.ljust(widths[i]) for i, c in enumerate(row))
        print(f"    │ {line} │")
    print(f"    └─{sep}─┘")

    if len(bindings) > max_rows:
        print(f"    … and {len(bindings) - max_rows} more rows")


def run_all(filter_key: str = None):
    print("\n" + "═" * 70)
    print(f"  D3FEND SPARQL Test Suite — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Endpoint: {SPARQL_URL}")
    print("═" * 70)

    # Connectivity check
    print("\n[CHECK] GraphDB connectivity... ", end="")
    if not check_graphdb():
        print("❌ FAILED")
        print(f"       GraphDB not reachable at {GRAPHDB_URL}")
        print(f"       Run: docker compose up -d && ./scripts/bootstrap.sh")
        sys.exit(1)
    print("✅ OK")

    results_summary = []
    queries = {k: v for k, v in QUERIES.items() if filter_key is None or filter_key in k}

    for qid, meta in queries.items():
        print(f"\n{'─' * 70}")
        print(f"  [{meta['category'].upper()}] {meta['label']}")
        print(f"  Query ID: {qid}")
        print()

        result = run_sparql(meta["query"], meta["label"])

        if result["ok"]:
            print(f"  ✅ {result['count']} results in {result['ms']}ms\n")
            render_table(result["bindings"], max_rows=8)
        else:
            print(f"  ❌ ERROR: {result['error']}")

        results_summary.append({
            "id": qid,
            "label": meta["label"],
            "ok": result["ok"],
            "count": result["count"],
            "ms": result["ms"]
        })

    # Summary table
    print(f"\n{'═' * 70}")
    print("  SUMMARY")
    print(f"{'─' * 70}")
    print(f"  {'Query':<40} {'Status':<8} {'Results':<10} {'Time(ms)'}")
    print(f"  {'─' * 38} {'─' * 6} {'─' * 8} {'─' * 8}")
    for r in results_summary:
        status = "✅" if r["ok"] else "❌"
        print(f"  {r['id']:<40} {status:<8} {r['count']:<10} {r['ms']}")
    print("═" * 70 + "\n")


# ═════════════════════════════════════════════════════════════════════════════
# INTERACTIVE MODE — run a single custom query
# ═════════════════════════════════════════════════════════════════════════════

INTERACTIVE_QUERY = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT ?techniqueLabel ?d3fID ?attackLabel
WHERE {{
  ?technique rdfs:subClassOf* d3f:DefensiveTechnique ;
             rdfs:label ?techniqueLabel ;
             d3f:counters ?attack .
  ?attack rdfs:label ?attackLabel .
  OPTIONAL {{ ?technique d3f:d3fend-id ?d3fID . }}
  FILTER(CONTAINS(LCASE(?attackLabel), "{keyword}") ||
         CONTAINS(LCASE(?techniqueLabel), "{keyword}"))
}}
ORDER BY ?techniqueLabel
LIMIT 50
"""

def run_keyword(keyword: str):
    print(f"\n🔍 Searching D3FEND for: '{keyword}'\n")
    q = INTERACTIVE_QUERY.format(keyword=keyword.lower())
    result = run_sparql(q)
    if result["ok"]:
        print(f"  Found {result['count']} results in {result['ms']}ms\n")
        render_table(result["bindings"], max_rows=20)
    else:
        print(f"  Error: {result['error']}")


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

# ═════════════════════════════════════════════════════════════════════════════
# INGEST — load a .ttl file directly into GraphDB
# ═════════════════════════════════════════════════════════════════════════════

def ingest_ttl(ttl_path: str):
    """Upload a Turtle (.ttl) file directly into the GraphDB repository."""
    import os

    if not os.path.isfile(ttl_path):
        print(f"❌ File not found: {ttl_path}")
        sys.exit(1)

    size_mb = os.path.getsize(ttl_path) / (1024 * 1024)
    print(f"\n📥 Ingesting: {ttl_path} ({size_mb:.1f} MB)")
    print(f"   Target:    {GRAPHDB_URL}/repositories/{REPO_ID}/statements")
    print(f"   This may take 1-3 minutes...\n")

    with open(ttl_path, "rb") as f:
        data = f.read()

    req = urllib.request.Request(
        f"{GRAPHDB_URL}/repositories/{REPO_ID}/statements",
        data=data,
        headers={"Content-Type": "text/turtle"},
        method="POST"
    )

    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            elapsed = round(time.time() - start)
            code = resp.status
    except urllib.error.HTTPError as e:
        print(f"❌ HTTP {e.code}: {e.reason}")
        print(e.read().decode()[:300])
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"❌ Connection error: {e.reason}")
        sys.exit(1)

    if code in (200, 204):
        print(f"✅ Upload complete in {elapsed}s (HTTP {code})")
    else:
        print(f"⚠️  Unexpected HTTP {code}")

    # Verify triple count
    print("\n🔍 Verifying triple count...")
    result = run_sparql("SELECT (COUNT(*) as ?c) WHERE { ?s ?p ?o }")
    if result["ok"] and result["bindings"]:
        count = result["bindings"][0]["c"]["value"]
        print(f"   Total triples in repository: {count}")
        if int(count) > 10000:
            print("✅ Data loaded successfully!\n")
        else:
            print("⚠️  Low triple count — load may have failed or is still processing.\n")
    else:
        print("⚠️  Could not verify triple count.\n")


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="D3FEND SPARQL Test Runner")
    parser.add_argument("--query",  help="Run only queries matching this string")
    parser.add_argument("--search", help="Search D3FEND by keyword (technique or attack)")
    parser.add_argument("--ingest", help="Path to .ttl file to load into GraphDB before querying")
    args = parser.parse_args()

    if not check_graphdb():
        print("❌ GraphDB not reachable. Start it with: docker compose up -d")
        sys.exit(1)

    if args.ingest:
        ingest_ttl(args.ingest)

    if args.search:
        run_keyword(args.search)
    elif not args.ingest:
        run_all(filter_key=args.query)
    else:
        # After ingest, run all queries automatically
        run_all()