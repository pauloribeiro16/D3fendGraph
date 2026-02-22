# =============================================================================
# SPARQL Query Suite: Technique → Countermeasure Mapping
# Priority 1 for ARM use case
# =============================================================================

# ── Q1: All ATT&CK techniques and the D3FEND techniques that counter them ────
# Use this to understand the full ATT&CK ↔ D3FEND coverage
Q1_ATTACK_TO_D3FEND = """
PREFIX d3f: <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT DISTINCT
  ?attackTechnique
  ?attackLabel
  ?defensiveTechnique
  ?defensiveLabel
  ?defensiveDefinition
WHERE {
  ?defensiveTechnique a/rdfs:subClassOf* d3f:DefensiveTechnique ;
                      rdfs:label ?defensiveLabel ;
                      d3f:counters ?attackTechnique .

  ?attackTechnique rdfs:label ?attackLabel .

  OPTIONAL { ?defensiveTechnique d3f:definition ?defensiveDefinition . }
}
ORDER BY ?attackLabel ?defensiveLabel
LIMIT 200
"""

# ── Q2: Find all D3FEND countermeasures for a specific ATT&CK technique ──────
# Parameterised — replace the FILTER value with the technique you care about
Q2_SPECIFIC_ATTACK = """
PREFIX d3f: <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
  ?defensiveTechnique
  ?defensiveLabel
  ?defensiveDefinition
  ?d3fID
WHERE {
  ?defensiveTechnique a/rdfs:subClassOf* d3f:DefensiveTechnique ;
                      rdfs:label ?defensiveLabel ;
                      d3f:counters ?attackTechnique .

  ?attackTechnique rdfs:label ?attackLabel .

  OPTIONAL { ?defensiveTechnique d3f:definition ?defensiveDefinition . }
  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }

  FILTER(CONTAINS(LCASE(?attackLabel), "credential"))  # ← change this filter
}
ORDER BY ?defensiveLabel
"""

# ── Q3: Reverse — given a D3FEND technique, what attacks does it counter? ────
Q3_REVERSE_LOOKUP = """
PREFIX d3f: <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
  ?defensiveLabel
  ?attackTechnique
  ?attackLabel
WHERE {
  ?defensiveTechnique rdfs:label ?defensiveLabel ;
                      d3f:counters ?attackTechnique .

  ?attackTechnique rdfs:label ?attackLabel .

  FILTER(CONTAINS(LCASE(?defensiveLabel), "network traffic"))  # ← change this
}
ORDER BY ?defensiveLabel ?attackLabel
"""

# ── Q4: Full technique chain — ARM traceability path ─────────────────────────
# SecurityGoal concept: from attack → defensive technique → digital artifact
Q4_TECHNIQUE_CHAIN = """
PREFIX d3f: <https://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
  ?attackLabel
  ?defensiveLabel
  ?artifactLabel
  ?digitalArtifactType
WHERE {
  ?defensiveTechnique a/rdfs:subClassOf* d3f:DefensiveTechnique ;
                      rdfs:label ?defensiveLabel ;
                      d3f:counters ?attackTechnique .

  ?attackTechnique rdfs:label ?attackLabel .

  # What digital artifacts does the defensive technique act on?
  OPTIONAL {
    ?defensiveTechnique d3f:analyzes|d3f:monitors|d3f:filters|d3f:blocks ?artifact .
    ?artifact rdfs:label ?artifactLabel .
    ?artifact a ?digitalArtifactType .
    ?digitalArtifactType rdfs:label ?typeLabel .
  }
}
ORDER BY ?attackLabel ?defensiveLabel
LIMIT 100
"""
