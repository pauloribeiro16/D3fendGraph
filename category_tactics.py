# =============================================================================
# SPARQL Query Suite: Countermeasures by Category / Tactic
# Priority 2 for ARM use case
# =============================================================================

# ── Q5: All D3FEND top-level tactic categories ───────────────────────────────
# D3FEND organises defenses into: Harden, Detect, Isolate, Deceive, Evict
Q5_TACTIC_CATEGORIES = """
PREFIX d3f: <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT DISTINCT ?tactic ?tacticLabel (COUNT(?technique) AS ?techniqueCount)
WHERE {
  # Top-level D3FEND defensive tactic classes
  VALUES ?tactic {
    d3f:Harden
    d3f:Detect
    d3f:Isolate
    d3f:Deceive
    d3f:Evict
  }

  ?tactic rdfs:label ?tacticLabel .

  ?technique rdfs:subClassOf* ?tactic ;
             a owl:Class .
}
GROUP BY ?tactic ?tacticLabel
ORDER BY DESC(?techniqueCount)
"""

# ── Q6: Browse all techniques within a specific tactic category ──────────────
Q6_TECHNIQUES_BY_TACTIC = """
PREFIX d3f: <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT DISTINCT
  ?technique
  ?techniqueLabel
  ?definition
  ?d3fID
  ?parentLabel
WHERE {
  # Change d3f:Harden to: d3f:Detect, d3f:Isolate, d3f:Deceive, d3f:Evict
  ?technique rdfs:subClassOf+ d3f:Harden ;
             a owl:Class ;
             rdfs:label ?techniqueLabel .

  OPTIONAL { ?technique d3f:definition ?definition . }
  OPTIONAL { ?technique d3f:d3fend-id ?d3fID . }
  OPTIONAL {
    ?technique rdfs:subClassOf ?parent .
    ?parent rdfs:label ?parentLabel .
    FILTER(?parent != owl:Thing)
  }
}
ORDER BY ?parentLabel ?techniqueLabel
"""

# ── Q7: Category summary — techniques per sub-category ───────────────────────
Q7_SUBCATEGORY_BREAKDOWN = """
PREFIX d3f: <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?parentLabel (COUNT(DISTINCT ?technique) AS ?count)
WHERE {
  ?technique rdfs:subClassOf ?parent ;
             a owl:Class .

  ?parent rdfs:subClassOf d3f:DefensiveTechnique ;
          rdfs:label ?parentLabel .
}
GROUP BY ?parentLabel
ORDER BY DESC(?count)
"""

# ── Q8: ARM-specific — find all "Harden" techniques relevant to data protection
# Useful for mapping GDPR Art.32 "appropriate technical measures"
Q8_DATA_PROTECTION_TECHNIQUES = """
PREFIX d3f: <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
  ?technique
  ?techniqueLabel
  ?definition
  ?d3fID
WHERE {
  ?technique rdfs:subClassOf* d3f:DefensiveTechnique ;
             rdfs:label ?techniqueLabel .

  OPTIONAL { ?technique d3f:definition ?definition . }
  OPTIONAL { ?technique d3f:d3fend-id ?d3fID . }

  FILTER(
    CONTAINS(LCASE(?techniqueLabel), "encrypt") ||
    CONTAINS(LCASE(?techniqueLabel), "data") ||
    CONTAINS(LCASE(?techniqueLabel), "credential") ||
    CONTAINS(LCASE(?techniqueLabel), "access control") ||
    CONTAINS(LCASE(?techniqueLabel), "authentication")
  )
}
ORDER BY ?techniqueLabel
"""

# ── Q9: Compliance bridge — techniques + how many attacks they counter ────────
# Useful for prioritising which controls give you the most coverage
Q9_COVERAGE_PRIORITY = """
PREFIX d3f: <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT
  ?tacticArea
  ?techniqueLabel
  ?d3fID
  (COUNT(DISTINCT ?attackTechnique) AS ?attacksCovered)
WHERE {
  ?technique rdfs:subClassOf* d3f:DefensiveTechnique ;
             rdfs:label ?techniqueLabel ;
             d3f:counters ?attackTechnique .

  OPTIONAL { ?technique d3f:d3fend-id ?d3fID . }

  # Get tactic area
  OPTIONAL {
    ?technique rdfs:subClassOf+ ?tactic .
    VALUES ?tactic { d3f:Harden d3f:Detect d3f:Isolate d3f:Deceive d3f:Evict }
    ?tactic rdfs:label ?tacticArea .
  }
}
GROUP BY ?tacticArea ?techniqueLabel ?d3fID
ORDER BY DESC(?attacksCovered)
LIMIT 30
"""
