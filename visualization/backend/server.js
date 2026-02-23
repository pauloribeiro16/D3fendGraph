const express = require('express');
const cors = require('cors');
const axios = require('axios');
const neo4j = require('neo4j-driver');
const { spawn } = require('child_process');
const path = require('path');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// --- Setup GraphDB / SPARQL ---
const GRAPHDB_URL = "http://localhost:7200";
const REPO_ID = "d3fend";
const SPARQL_URL = `${GRAPHDB_URL}/repositories/${REPO_ID}`;

// --- Setup Neo4j / Cypher ---
const NEO4J_URL = "bolt://localhost:7687";
const NEO4J_USER = "neo4j";
const NEO4J_PASS = "d3fendtest";
const driver = neo4j.driver(NEO4J_URL, neo4j.auth.basic(NEO4J_USER, NEO4J_PASS));

// Example Queries Dictionary organized by domain
const DOMAIN_QUERIES = {
    d3fend: {
        "Q1_all_attack_to_d3fend": {
            name: "🛡️ All ATT&CK → D3FEND",
            group: "Overview",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                    ?defensiveTechnique rdfs:subClassOf* d3f:DefensiveTechnique ;
                                        rdfs:label ?defensiveLabel ;
                                        d3f:counters ?attackTechnique .
                    ?attackTechnique rdfs:label ?attackLabel .
                    OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel LIMIT 200
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
                LIMIT 200
            `
        },
        "Q2_platform_hardening": {
            name: "🛡️ Platform Hardening",
            group: "Defense Domains",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                    ?defensiveTechnique rdfs:subClassOf* d3f:PlatformHardening ;
                                        rdfs:label ?defensiveLabel ;
                                        d3f:counters ?attackTechnique .
                    ?attackTechnique rdfs:label ?attackLabel .
                    OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                WHERE defense.name CONTAINS 'Hardening' OR defense.description CONTAINS 'Hardening'
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
            `
        },
        "Q3_network_isolation": {
            name: "🌐 Network Isolation",
            group: "Defense Domains",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                    ?defensiveTechnique rdfs:subClassOf* d3f:NetworkIsolation ;
                                        rdfs:label ?defensiveLabel ;
                                        d3f:counters ?attackTechnique .
                    ?attackTechnique rdfs:label ?attackLabel .
                    OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                WHERE defense.name CONTAINS 'Isolation' OR defense.description CONTAINS 'Isolation'
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
            `
        },
        "Q4_deceptive_defenses": {
            name: "👺 Deception & Decoys",
            group: "Deception",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                    ?defensiveTechnique rdfs:subClassOf* d3f:DeceptiveTechnique ;
                                        rdfs:label ?defensiveLabel ;
                                        d3f:counters ?attackTechnique .
                    ?attackTechnique rdfs:label ?attackLabel .
                    OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                WHERE defense.name CONTAINS 'Decoy' OR defense.description CONTAINS 'Decoy' OR defense.name CONTAINS 'Deception'
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
            `
        },
        "Q5_analysis_defenses": {
            name: "🔍 Analysis Techniques",
            group: "Monitoring",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                    ?defensiveTechnique rdfs:subClassOf* d3f:DetectionTechnique ;
                                        rdfs:label ?defensiveLabel ;
                                        d3f:counters ?attackTechnique .
                    ?attackTechnique rdfs:label ?attackLabel .
                    OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                WHERE defense.name CONTAINS 'Analysis' OR defense.description CONTAINS 'Analysis' OR defense.name CONTAINS 'Detection'
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
            `
        },
        "Q6_credential_protection": {
            name: "🔑 Credential Protection",
            group: "Defense Domains",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                  ?defensiveTechnique rdfs:subClassOf* d3f:CredentialHardening ;
                                      rdfs:label ?defensiveLabel ;
                                      d3f:counters ?attackTechnique .
                  ?attackTechnique rdfs:label ?attackLabel .
                  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                WHERE defense.name CONTAINS 'Credential' OR defense.description CONTAINS 'Credential'
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
            `
        },
        "Q7_data_protection": {
            name: "📦 Data Exfiltration Defenses",
            group: "Defense Domains",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                  ?defensiveTechnique rdfs:subClassOf* d3f:DataProtection ;
                                      rdfs:label ?defensiveLabel ;
                                      d3f:counters ?attackTechnique .
                  ?attackTechnique rdfs:label ?attackLabel .
                  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                WHERE defense.name CONTAINS 'Data' OR defense.description CONTAINS 'Data'
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
            `
        },
        "Q8_message_filtering": {
            name: "✉️ Message Filtering",
            group: "Defense Domains",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                  ?defensiveTechnique rdfs:subClassOf* d3f:MessageFiltering ;
                                      rdfs:label ?defensiveLabel ;
                                      d3f:counters ?attackTechnique .
                  ?attackTechnique rdfs:label ?attackLabel .
                  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                WHERE defense.name CONTAINS 'Message' OR defense.description CONTAINS 'Filtering'
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
            `
        },
        "Q9_system_config_hardening": {
            name: "⚙️ System Configuration Hardening",
            group: "Hardening",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                  ?defensiveTechnique rdfs:subClassOf* d3f:SystemConfigurationHardening ;
                                      rdfs:label ?defensiveLabel ;
                                      d3f:counters ?attackTechnique .
                  ?attackTechnique rdfs:label ?attackLabel .
                  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                WHERE defense.name CONTAINS 'Hardening' OR defense.description CONTAINS 'Hardening'
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
            `
        },
        "Q10_os_hardening": {
            name: "💻 Operating System Hardening",
            group: "Hardening",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                  ?defensiveTechnique rdfs:subClassOf* d3f:OperatingSystemHardening ;
                                      rdfs:label ?defensiveLabel ;
                                      d3f:counters ?attackTechnique .
                  ?attackTechnique rdfs:label ?attackLabel .
                  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK)
                WHERE defense.name CONTAINS 'OS' OR defense.description CONTAINS 'Operating System'
                RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType,
                       defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType
            `
        }
    }
    ,
    capec: {
        "Q1_all_capec": {
            name: "📊 All Patterns & Relations",
            group: "Overview",
            sparql: `
                SELECT ?sourceId ?sourceName ?sourceDesc ?targetId ?targetName ?relType WHERE {
                    ?sourceId a <http://capec.mitre.org/data/definitions/Pattern> ;
                              <http://www.w3.org/2000/01/rdf-schema#label> ?sourceName .
                    OPTIONAL { ?sourceId <http://www.w3.org/2000/01/rdf-schema#comment> ?sourceDesc . }
                    OPTIONAL {
                        ?sourceId ?p ?targetId .
                        FILTER(STRSTARTS(STR(?p), "http://capec.mitre.org/data/definitions/relationship/"))
                        BIND(REPLACE(STR(?p), "http://capec.mitre.org/data/definitions/relationship/", "") AS ?relType)
                        ?targetId <http://www.w3.org/2000/01/rdf-schema#label> ?targetName .
                    }
                } LIMIT 500
            `,
            cypher: "MATCH (s:Resource:CAPEC)-[r]->(t) RETURN s.id AS sourceId, s.name AS sourceName, s.description AS sourceDesc, t.id AS targetId, t.name AS targetName, type(r) AS relType LIMIT 500"
        },
        "Q2_capec_injection": {
            name: "💉 Injection Patterns",
            group: "Attack Domains",
            sparql: `
                SELECT ?id ?name ?description WHERE {
                    ?id a <http://capec.mitre.org/data/definitions/Pattern> ;
                        <http://www.w3.org/2000/01/rdf-schema#label> ?name .
                    OPTIONAL { ?id <http://www.w3.org/2000/01/rdf-schema#comment> ?description . }
                    FILTER(CONTAINS(LCASE(?name), "injection"))
                } LIMIT 100
            `,
            cypher: "MATCH (n:Resource:CAPEC) WHERE toLower(n.name) CONTAINS 'injection' RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        },
        "Q3_capec_spoofing": {
            name: "👺 Spoofing & Impersonation",
            group: "Attack Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://capec.mitre.org/data/definitions/Pattern> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name . FILTER(CONTAINS(LCASE(?name), "spoofing")) } LIMIT 50`,
            cypher: "MATCH (n:Resource:CAPEC) WHERE toLower(n.name) CONTAINS 'spoofing' OR toLower(n.name) CONTAINS 'impersonation' RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        },
        "Q4_capec_leakage": {
            name: "🔓 Data Leakage Patterns",
            group: "Attack Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://capec.mitre.org/data/definitions/Pattern> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name . FILTER(CONTAINS(LCASE(?name), "leakage") || CONTAINS(LCASE(?name), "disclosure")) } LIMIT 50`,
            cypher: "MATCH (n:Resource:CAPEC) WHERE toLower(n.name) CONTAINS 'leakage' OR toLower(n.name) CONTAINS 'disclosure' RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        }
    }
    ,
    cwe: {
        // ── GROUP: Views & Lists ────────────────────────────────────────────────
        "Q1_all_cwe": {
            name: "📊 Full CWE Hierarchy",
            group: "Views & Lists",
            cypher: `
                MATCH (child:CWE)
                OPTIONAL MATCH (child)-[:CHILD_OF]->(parent:CWE)
                RETURN child.id AS sourceId, child.name AS sourceName, child.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                LIMIT 500
            `,
            sparql: `SELECT ?sourceId ?sourceName ?sourceDesc ?targetId ?targetName WHERE {
                ?sourceId a <http://cwe.mitre.org/cwe-schema#Weakness> ; <http://www.w3.org/2000/01/rdf-schema#label> ?sourceName .
                OPTIONAL { ?sourceId <http://cwe.mitre.org/cwe-schema#description> ?sourceDesc . }
                OPTIONAL { ?sourceId <http://cwe.mitre.org/cwe-schema#childOf> ?targetId . ?targetId <http://www.w3.org/2000/01/rdf-schema#label> ?targetName . }
            } LIMIT 500`
        },
        "Q2_cwe_top25": {
            name: "🏆 Top-25 Most Dangerous (2024)",
            group: "Views & Lists",
            cypher: `
                MATCH (n:CWE)
                WHERE n.id IN [
                    'CWE-79','CWE-787','CWE-89','CWE-416','CWE-78',
                    'CWE-20','CWE-125','CWE-22','CWE-352','CWE-434',
                    'CWE-862','CWE-476','CWE-287','CWE-190','CWE-502',
                    'CWE-77','CWE-119','CWE-798','CWE-918','CWE-306',
                    'CWE-362','CWE-269','CWE-94','CWE-863','CWE-276'
                ]
                OPTIONAL MATCH (n)-[:CHILD_OF]->(parent:CWE) WHERE parent.id IN [
                    'CWE-79','CWE-787','CWE-89','CWE-416','CWE-78',
                    'CWE-20','CWE-125','CWE-22','CWE-352','CWE-434',
                    'CWE-862','CWE-476','CWE-287','CWE-190','CWE-502',
                    'CWE-77','CWE-119','CWE-798','CWE-918','CWE-306',
                    'CWE-362','CWE-269','CWE-94','CWE-863','CWE-276'
                ]
                RETURN n.id AS sourceId, n.name AS sourceName, n.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
            `,
            sparql: `SELECT ?id ?name ?description WHERE {
                ?id a <http://cwe.mitre.org/cwe-schema#Weakness> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name .
                OPTIONAL { ?id <http://cwe.mitre.org/cwe-schema#description> ?description . }
                VALUES ?id {
                    <http://cwe.mitre.org/data/definitions/CWE-79> <http://cwe.mitre.org/data/definitions/CWE-787>
                    <http://cwe.mitre.org/data/definitions/CWE-89> <http://cwe.mitre.org/data/definitions/CWE-416>
                    <http://cwe.mitre.org/data/definitions/CWE-78> <http://cwe.mitre.org/data/definitions/CWE-20>
                }
            }`
        },
        "Q5_cwe_software_dev": {
            name: "🖥️ Software Development View (699)",
            group: "Views & Lists",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (w:CWE)-[:MEMBER_OF]->(cat:CWECategory)
                WHERE cat.view699 = true
                RETURN w.id AS sourceId, w.name AS sourceName, w.description AS sourceDesc,
                       cat.id AS targetId, cat.name AS targetName
            `
        },
        "Q_pillars_tree": {
            name: "🌲 Pillars & Hierarchy",
            group: "Views & Lists",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (child:CWE)
                OPTIONAL MATCH (child)-[:CHILD_OF]->(parent:CWE)
                WHERE child.abstraction IN ['Pillar','Class']
                   OR parent.abstraction IN ['Pillar','Class']
                RETURN child.id AS sourceId, child.name AS sourceName, child.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                LIMIT 300
            `
        },

        // ── GROUP: Security Domains ─────────────────────────────────────────────
        "Q3_cwe_injection_family": {
            name: "💉 Injection (SQL, XSS, Command, LDAP…)",
            group: "Security Domains",
            cypher: `
                MATCH (child:CWE)
                WHERE toLower(child.name) CONTAINS 'injection'
                   OR child.id IN ['CWE-79','CWE-89','CWE-78','CWE-94','CWE-77','CWE-90','CWE-91','CWE-917']
                OPTIONAL MATCH (child)-[:CHILD_OF]->(parent:CWE)
                RETURN child.id AS sourceId, child.name AS sourceName, child.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                LIMIT 100
            `,
            sparql: `SELECT ?sourceId ?sourceName ?sourceDesc ?targetId ?targetName WHERE {
                ?sourceId a <http://cwe.mitre.org/cwe-schema#Weakness> ; <http://www.w3.org/2000/01/rdf-schema#label> ?sourceName .
                OPTIONAL { ?sourceId <http://cwe.mitre.org/cwe-schema#description> ?sourceDesc . }
                OPTIONAL { ?sourceId <http://cwe.mitre.org/cwe-schema#childOf> ?targetId . ?targetId <http://www.w3.org/2000/01/rdf-schema#label> ?targetName . }
                FILTER(CONTAINS(LCASE(?sourceName), "injection"))
            } LIMIT 100`
        },
        "Q4_cwe_memory_safety": {
            name: "🔐 Memory Safety (Buffer, Overflow, UAF, Null)",
            group: "Security Domains",
            cypher: `
                MATCH (child:CWE)
                WHERE toLower(child.name) CONTAINS 'buffer'
                   OR toLower(child.name) CONTAINS 'overflow'
                   OR toLower(child.name) CONTAINS 'out-of-bounds'
                   OR toLower(child.name) CONTAINS 'use after free'
                   OR toLower(child.name) CONTAINS 'null pointer'
                   OR toLower(child.name) CONTAINS 'memory'
                   OR child.id IN ['CWE-416','CWE-476','CWE-787','CWE-125','CWE-119','CWE-190']
                OPTIONAL MATCH (child)-[:CHILD_OF]->(parent:CWE)
                RETURN child.id AS sourceId, child.name AS sourceName, child.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                LIMIT 100
            `,
            sparql: `SELECT ?sourceId ?sourceName ?sourceDesc ?targetId ?targetName WHERE {
                ?sourceId a <http://cwe.mitre.org/cwe-schema#Weakness> ; <http://www.w3.org/2000/01/rdf-schema#label> ?sourceName .
                OPTIONAL { ?sourceId <http://cwe.mitre.org/cwe-schema#description> ?sourceDesc . }
                OPTIONAL { ?sourceId <http://cwe.mitre.org/cwe-schema#childOf> ?targetId . ?targetId <http://www.w3.org/2000/01/rdf-schema#label> ?targetName . }
                FILTER(CONTAINS(LCASE(?sourceName), "buffer") || CONTAINS(LCASE(?sourceName), "overflow"))
            } LIMIT 100`
        },
        "Q_auth": {
            name: "🔑 Authentication & Session Errors",
            group: "Security Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (w:CWE)-[:MEMBER_OF]->(cat:CWECategory)
                WHERE cat.id IN ['CWE-1211','CWE-1217']
                RETURN w.id AS sourceId, w.name AS sourceName, w.description AS sourceDesc,
                       cat.id AS targetId, cat.name AS targetName
            `
        },
        "Q_authz": {
            name: "🛡️ Authorization & Access Control",
            group: "Security Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (w:CWE)-[:MEMBER_OF]->(cat:CWECategory)
                WHERE cat.id IN ['CWE-1212']
                UNION
                MATCH (w:CWE)
                WHERE w.id IN ['CWE-862','CWE-863','CWE-269','CWE-276','CWE-306','CWE-287','CWE-732']
                WITH w, null AS cat
                RETURN w.id AS sourceId, w.name AS sourceName, w.description AS sourceDesc,
                       cat.id AS targetId, cat.name AS targetName
            `
        },
        "Q_crypto": {
            name: "🔒 Cryptographic Issues",
            group: "Security Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (w:CWE)-[:MEMBER_OF]->(cat:CWECategory)
                WHERE cat.id IN ['CWE-310','CWE-320']
                RETURN w.id AS sourceId, w.name AS sourceName, w.description AS sourceDesc,
                       cat.id AS targetId, cat.name AS targetName
            `
        },
        "Q_input_val": {
            name: "✅ Input Validation Failures",
            group: "Security Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (w:CWE)-[:MEMBER_OF]->(cat:CWECategory)
                WHERE cat.id IN ['CWE-1215','CWE-19','CWE-137']
                RETURN w.id AS sourceId, w.name AS sourceName, w.description AS sourceDesc,
                       cat.id AS targetId, cat.name AS targetName
            `
        },
        "Q_web": {
            name: "🌐 Web Application Security",
            group: "Security Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (n:CWE)
                WHERE n.id IN [
                    'CWE-79','CWE-89','CWE-352','CWE-918','CWE-22','CWE-94',
                    'CWE-434','CWE-601','CWE-116','CWE-614','CWE-384','CWE-311',
                    'CWE-200','CWE-285','CWE-494','CWE-598','CWE-643'
                ]
                OPTIONAL MATCH (n)-[:CHILD_OF]->(parent:CWE)
                RETURN n.id AS sourceId, n.name AS sourceName, n.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
            `
        },
        "Q_credentials": {
            name: "🗝️ Credentials & Secrets Management",
            group: "Security Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (w:CWE)-[:MEMBER_OF]->(cat:CWECategory)
                WHERE cat.id IN ['CWE-255']
                RETURN w.id AS sourceId, w.name AS sourceName, w.description AS sourceDesc,
                       cat.id AS targetId, cat.name AS targetName
            `
        },
        "Q_concurrency": {
            name: "⚡ Concurrency & Race Conditions",
            group: "Security Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (w:CWE)-[:MEMBER_OF]->(cat:CWECategory)
                WHERE cat.id IN ['CWE-557']
                RETURN w.id AS sourceId, w.name AS sourceName, w.description AS sourceDesc,
                       cat.id AS targetId, cat.name AS targetName
            `
        },
        "Q_resource": {
            name: "📦 Resource Management Errors",
            group: "Security Domains",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (w:CWE)-[:MEMBER_OF]->(cat:CWECategory)
                WHERE cat.id IN ['CWE-399','CWE-452']
                RETURN w.id AS sourceId, w.name AS sourceName, w.description AS sourceDesc,
                       cat.id AS targetId, cat.name AS targetName
            `
        },

        // ── GROUP: Exploitability ───────────────────────────────────────────────
        "Q_high_exploit": {
            name: "🔥 High Likelihood of Exploit",
            group: "Exploitability",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (n:CWE)
                WHERE n.likelihood = 'High'
                OPTIONAL MATCH (n)-[:CHILD_OF]->(parent:CWE)
                RETURN n.id AS sourceId, n.name AS sourceName, n.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                ORDER BY n.id
            `
        },
        "Q_medium_exploit": {
            name: "⚠️ Medium Likelihood of Exploit",
            group: "Exploitability",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (n:CWE)
                WHERE n.likelihood = 'Medium'
                OPTIONAL MATCH (n)-[:CHILD_OF]->(parent:CWE)
                RETURN n.id AS sourceId, n.name AS sourceName, n.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                ORDER BY n.id
            `
        },
        "Q_confidentiality": {
            name: "🕵️ Confidentiality Impact",
            group: "Exploitability",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (n:CWE)
                WHERE n.consequences CONTAINS '"Confidentiality"'
                   OR n.consequences CONTAINS 'Read Application Data'
                   OR n.consequences CONTAINS 'Read Files'
                OPTIONAL MATCH (n)-[:CHILD_OF]->(parent:CWE)
                RETURN n.id AS sourceId, n.name AS sourceName, n.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                LIMIT 200
            `
        },
        "Q_rce": {
            name: "💣 Remote Code Execution Risk",
            group: "Exploitability",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (n:CWE)
                WHERE n.consequences CONTAINS 'Execute Unauthorized Code'
                   OR n.consequences CONTAINS 'Execute Code'
                OPTIONAL MATCH (n)-[:CHILD_OF]->(parent:CWE)
                RETURN n.id AS sourceId, n.name AS sourceName, n.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                LIMIT 150
            `
        },

        // ── GROUP: Abstraction Level ────────────────────────────────────────────
        "Q_pillars": {
            name: "🏛️ Pillar Weaknesses",
            group: "Abstraction Level",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (n:CWE)
                WHERE n.abstraction = 'Pillar'
                OPTIONAL MATCH (n)<-[:CHILD_OF]-(child:CWE)
                RETURN n.id AS sourceId, n.name AS sourceName, n.description AS sourceDesc,
                       child.id AS targetId, child.name AS targetName
                LIMIT 200
            `
        },
        "Q_classes": {
            name: "🏗️ Class-Level Weaknesses",
            group: "Abstraction Level",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (n:CWE)
                WHERE n.abstraction = 'Class'
                OPTIONAL MATCH (n)-[:CHILD_OF]->(parent:CWE)
                RETURN n.id AS sourceId, n.name AS sourceName, n.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                LIMIT 200
            `
        },
        "Q_bases": {
            name: "🔩 Base-Level Weaknesses",
            group: "Abstraction Level",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://www.w3.org/2002/07/owl#Class> } LIMIT 1`,
            cypher: `
                MATCH (n:CWE)
                WHERE n.abstraction = 'Base'
                OPTIONAL MATCH (n)-[:CHILD_OF]->(parent:CWE)
                RETURN n.id AS sourceId, n.name AS sourceName, n.description AS sourceDesc,
                       parent.id AS targetId, parent.name AS targetName
                LIMIT 300
            `
        }
    },

    attack: {
        "Q1_all_attack": {
            name: "📊 All Techniques & Relations",
            group: "Overview",
            sparql: `
                SELECT ?sourceId ?sourceName ?sourceDesc ?targetId ?targetName ?relType WHERE {
                    ?sourceId a <http://attack.mitre.org/Pattern> ;
                              <http://www.w3.org/2000/01/rdf-schema#label> ?sourceName .
                    OPTIONAL { ?sourceId <http://www.w3.org/2000/01/rdf-schema#comment> ?sourceDesc . }
                    OPTIONAL {
                        ?sourceId ?p ?targetId .
                        FILTER(STRSTARTS(STR(?p), "http://attack.mitre.org/relationship/"))
                        BIND(REPLACE(STR(?p), "http://attack.mitre.org/relationship/", "") AS ?relType)
                        ?targetId <http://www.w3.org/2000/01/rdf-schema#label> ?targetName .
                    }
                } LIMIT 500
            `,
            cypher: "MATCH (s:Resource:ATTACK)-[r]->(t) RETURN s.id AS sourceId, s.name AS sourceName, s.description AS sourceDesc, t.id AS targetId, t.name AS targetName, type(r) AS relType LIMIT 500"
        },
        "Q_attack_pattern_mitigation": {
            name: "🛡️ Techniques & Mitigations",
            group: "Defenses",
            sparql: `
                SELECT ?sourceId ?sourceName ?sourceDesc ?targetId ?targetName WHERE {
                    ?sourceId a <http://attack.mitre.org/CourseOfAction> ; <http://www.w3.org/2000/01/rdf-schema#label> ?sourceName ; <http://attack.mitre.org/relationship/mitigates> ?targetId .
                    OPTIONAL { ?sourceId <http://www.w3.org/2000/01/rdf-schema#comment> ?sourceDesc . }
                    ?targetId <http://www.w3.org/2000/01/rdf-schema#label> ?targetName .
                } LIMIT 200
            `,
            cypher: "MATCH (s:Resource:ATTACK {type: 'course-of-action'})-[r:RELATED {type: 'mitigates'}]->(t:Resource:ATTACK {type: 'attack-pattern'}) RETURN s.id AS sourceId, s.name AS sourceName, s.description AS sourceDesc, t.id AS targetId, t.name AS targetName, type(r) AS relType LIMIT 200"
        },
        "Q_attack_groups_software": {
            name: "🕴️ Groups & Software",
            group: "Threat Actors",
            sparql: `
                SELECT ?sourceId ?sourceName ?sourceDesc ?targetId ?targetName WHERE {
                    ?sourceId a <http://attack.mitre.org/IntrusionSet> ; <http://www.w3.org/2000/01/rdf-schema#label> ?sourceName ; <http://attack.mitre.org/relationship/uses> ?targetId .
                    OPTIONAL { ?sourceId <http://www.w3.org/2000/01/rdf-schema#comment> ?sourceDesc . }
                    ?targetId a ?targetType ; <http://www.w3.org/2000/01/rdf-schema#label> ?targetName .
                    FILTER(?targetType IN (<http://attack.mitre.org/Malware>, <http://attack.mitre.org/Tool>))
                } LIMIT 200
            `,
            cypher: "MATCH (s:Resource:ATTACK {type: 'intrusion-set'})-[r:RELATED]->(t:Resource:ATTACK) WHERE t.type IN ['malware', 'tool'] RETURN s.id AS sourceId, s.name AS sourceName, s.description AS sourceDesc, t.id AS targetId, t.name AS targetName, type(r) AS relType LIMIT 200"
        },
        "Q_attack_campaigns": {
            name: "🎯 Campaigns & Dependencies",
            group: "Threat Actors",
            sparql: `
                SELECT ?sourceId ?sourceName ?sourceDesc ?targetId ?targetName WHERE {
                    ?sourceId a <http://attack.mitre.org/Campaign> ; <http://www.w3.org/2000/01/rdf-schema#label> ?sourceName ; ?rel ?targetId .
                    OPTIONAL { ?sourceId <http://www.w3.org/2000/01/rdf-schema#comment> ?sourceDesc . }
                    ?targetId <http://www.w3.org/2000/01/rdf-schema#label> ?targetName .
                    FILTER(STRSTARTS(STR(?rel), "http://attack.mitre.org/relationship/"))
                } LIMIT 200
            `,
            cypher: "MATCH (s:Resource:ATTACK {type: 'campaign'})-[r:RELATED]->(t:Resource:ATTACK) RETURN s.id AS sourceId, s.name AS sourceName, s.description AS sourceDesc, t.id AS targetId, t.name AS targetName, type(r) AS relType LIMIT 200"
        },
        "Q_attack_malware": {
            name: "🦠 Malware Variants",
            group: "Software & Tools",
            sparql: `
                 SELECT ?id ?name ?description WHERE {
                     ?id a <http://attack.mitre.org/Malware> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name .
                     OPTIONAL { ?id <http://www.w3.org/2000/01/rdf-schema#comment> ?description . }
                 } LIMIT 200
             `,
            cypher: "MATCH (n:Resource:ATTACK {type: 'malware'}) RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 200"
        },
        "Q_attack_mobile": {
            name: "📱 Mobile-Related Techniques",
            group: "Mobile",
            sparql: `
                 SELECT ?id ?name ?description WHERE {
                     ?id a <http://attack.mitre.org/Pattern> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name .
                     OPTIONAL { ?id <http://www.w3.org/2000/01/rdf-schema#comment> ?description . }
                     FILTER(CONTAINS(LCASE(?name), "android") || CONTAINS(LCASE(?name), "ios") || CONTAINS(LCASE(?name), "mobile"))
                 } LIMIT 100
             `,
            cypher: "MATCH (n:Resource:ATTACK {type: 'attack-pattern'}) WHERE toLower(n.name) CONTAINS 'android' OR toLower(n.name) CONTAINS 'ios' OR toLower(n.description) CONTAINS 'mobile' RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        },
        "Q2_attack_privilege": {
            name: "📈 Privilege Escalation",
            group: "Enterprise Tactics",
            sparql: `
                SELECT ?id ?name ?description WHERE {
                    ?id a <http://attack.mitre.org/Pattern> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name .
                    OPTIONAL { ?id <http://www.w3.org/2000/01/rdf-schema#comment> ?description . }
                    FILTER(CONTAINS(LCASE(?name), "privilege"))
                } LIMIT 100
            `,
            cypher: "MATCH (n:Resource:ATTACK) WHERE toLower(n.name) CONTAINS 'privilege' RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        },
        "Q3_attack_persistence": {
            name: "⚓ Persistence Techniques",
            group: "Enterprise Tactics",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://attack.mitre.org/Pattern> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name . FILTER(CONTAINS(LCASE(?name), "persistent") || CONTAINS(LCASE(?name), "persistence")) } LIMIT 50`,
            cypher: "MATCH (n:Resource:ATTACK) WHERE toLower(n.name) CONTAINS 'persistence' OR toLower(n.name) CONTAINS 'resident' RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        },
        "Q_attack_defense_evasion": {
            name: "🥷 Defense Evasion Techniques",
            group: "Enterprise Tactics",
            sparql: `
                SELECT ?id ?name ?description WHERE {
                    ?id a <http://attack.mitre.org/Pattern> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name .
                    OPTIONAL { ?id <http://www.w3.org/2000/01/rdf-schema#comment> ?description . }
                    FILTER(CONTAINS(LCASE(?name), "evasion") || CONTAINS(LCASE(?name), "bypass") || CONTAINS(LCASE(?name), "hide"))
                } LIMIT 100
            `,
            cypher: "MATCH (n:Resource:ATTACK {type: 'attack-pattern'}) WHERE toLower(n.name) CONTAINS 'evasion' OR toLower(n.name) CONTAINS 'bypass' OR toLower(n.name) CONTAINS 'hide' RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        },
        "Q_attack_credential_access": {
            name: "🔐 Credential Access",
            group: "Enterprise Tactics",
            sparql: `
                SELECT ?id ?name ?description WHERE {
                    ?id a <http://attack.mitre.org/Pattern> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name .
                    OPTIONAL { ?id <http://www.w3.org/2000/01/rdf-schema#comment> ?description . }
                    FILTER(CONTAINS(LCASE(?name), "credential") || CONTAINS(LCASE(?name), "password"))
                } LIMIT 100
            `,
            cypher: "MATCH (n:Resource:ATTACK {type: 'attack-pattern'}) WHERE toLower(n.name) CONTAINS 'credential' OR toLower(n.name) CONTAINS 'password' RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        }
    }
    ,
    atlas: {
        "Q1_all_atlas": {
            name: "🤖 All ATLAS AI Patterns",
            group: "Overview",
            sparql: `
                SELECT ?id ?name ?description WHERE {
                    ?id a <http://atlas.mitre.org/Pattern> ; <http://www.w3.org/2000/01/rdf-schema#label> ?name .
                    OPTIONAL { ?id <http://www.w3.org/2000/01/rdf-schema#comment> ?description . }
                } LIMIT 100
            `,
            cypher: "MATCH (n:Resource:ATLAS) RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        },
        "Q2_atlas_poisoning": {
            name: "🧪 Data Poisoning Patterns",
            group: "AI Threats",
            sparql: `SELECT ?id ?name WHERE { ?id a <http://atlas.mitre.org/Pattern> ; rdfs:label ?name . FILTER(CONTAINS(LCASE(?name), "poisoning")) } LIMIT 50`,
            cypher: "MATCH (n:Resource:ATLAS) WHERE toLower(n.name) CONTAINS 'poisoning' RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 100"
        }
    },
    cross_framework: {
        "Q1_injection": {
            name: "🔍 Search 'injection' (Global)",
            group: "Discovery",
            sparql: `
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT ?framework ?id ?label WHERE {
                  { ?id a <http://cwe.mitre.org/cwe-schema#Weakness> ; rdfs:label ?label . BIND("CWE" AS ?framework) } UNION
                  { ?id a <http://capec.mitre.org/data/definitions/Pattern> ; rdfs:label ?label . BIND("CAPEC" AS ?framework) } UNION
                  { ?id a <http://atlas.mitre.org/Pattern> ; rdfs:label ?label . BIND("ATLAS" AS ?framework) } UNION
                  { ?id a <http://attack.mitre.org/Pattern> ; rdfs:label ?label . BIND("ATT&CK" AS ?framework) }
                  FILTER(CONTAINS(LCASE(?label), "injection"))
                } ORDER BY ?framework LIMIT 50
            `,
            cypher: "MATCH (n) WHERE toLower(n.name) CONTAINS 'injection' RETURN labels(n) AS framework, n.id AS id, n.name AS label LIMIT 50"
        },
        "Q2_phishing": {
            name: "🎣 Search 'phishing' (Global)",
            group: "Discovery",
            sparql: `
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT ?framework ?id ?label WHERE {
                  { ?id a <http://cwe.mitre.org/cwe-schema#Weakness> ; rdfs:label ?label . BIND("CWE" AS ?framework) } UNION
                  { ?id a <http://capec.mitre.org/data/definitions/Pattern> ; rdfs:label ?label . BIND("CAPEC" AS ?framework) } UNION
                  { ?id a <http://atlas.mitre.org/Pattern> ; rdfs:label ?label . BIND("ATLAS" AS ?framework) } UNION
                  { ?id a <http://attack.mitre.org/Pattern> ; rdfs:label ?label . BIND("ATT&CK" AS ?framework) }
                  FILTER(CONTAINS(LCASE(?label), "phishing"))
                } ORDER BY ?framework LIMIT 50
            `,
            cypher: "MATCH (n) WHERE toLower(n.name) CONTAINS 'phishing' RETURN labels(n) AS framework, n.id AS id, n.name AS label LIMIT 50"
        }
    },
    relationships: {
        "Q1_capec_cwe_attack": {
            name: "🔥 CAPEC → CWE → ATT&CK",
            group: "Kill Chains",
            sparql: `
                SELECT ?sourceId ?sourceName ("CAPEC" AS ?sourceType) ?targetId ?targetName ?targetType ?relType
                WHERE {
                    {
                        SELECT (?capecId AS ?sourceId) (?capecName AS ?sourceName) (?cweId AS ?targetId) (?cweName AS ?targetName) ("CWE" AS ?targetType) ("explores" AS ?relType)
                        WHERE {
                            ?capecId a <http://capec.mitre.org/data/definitions/Pattern> ;
                                     <http://www.w3.org/2000/01/rdf-schema#label> ?capecName .
                            ?capecId <http://capec.mitre.org/relationship/explores> ?cweId .
                            ?cweId <http://www.w3.org/2000/01/rdf-schema#label> ?cweName .
                        }
                    }
                    UNION
                    {
                        SELECT (?capecId AS ?sourceId) (?capecName AS ?sourceName) (?attackId AS ?targetId) (?attackName AS ?targetName) ("ATTACK" AS ?targetType) ("maps_to" AS ?relType)
                        WHERE {
                            ?capecId a <http://capec.mitre.org/data/definitions/Pattern> ;
                                     <http://www.w3.org/2000/01/rdf-schema#label> ?capecName .
                            ?capecId <http://capec.mitre.org/relationship/maps_to> ?attackId .
                            ?attackId <http://www.w3.org/2000/01/rdf-schema#label> ?attackName .
                        }
                    }
                } LIMIT 200
            `,
            cypher: "MATCH (capec:Resource:CAPEC)-[r:RELATED {type: 'explores'}]->(cwe) RETURN capec.id AS sourceId, capec.name AS sourceName, 'CAPEC' AS sourceType, cwe.id AS targetId, cwe.name AS targetName, 'CWE' AS targetType, type(r) AS relType UNION MATCH (capec:Resource:CAPEC)-[r:RELATED {type: 'maps_to'}]->(attack:Resource:ATTACK) RETURN capec.id AS sourceId, capec.name AS sourceName, 'CAPEC' AS sourceType, attack.id AS targetId, attack.name AS targetName, 'ATTACK' AS targetType, type(r) AS relType LIMIT 200"
        },
        "Q2_attack_d3fend": {
            name: "🛡️ ATT&CK → D3FEND",
            group: "Defensive Mappings",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT (?attackLabel AS ?sourceId) (?attackLabel AS ?sourceName) ("ATTACK" AS ?sourceType) 
                                (COALESCE(?d3fID, ?defensiveLabel) AS ?targetId) (?defensiveLabel AS ?targetName) ("D3FEND" AS ?targetType)
                                ("counters" AS ?relType)
                WHERE {
                    ?defensiveTechnique rdfs:subClassOf* d3f:DefensiveTechnique ;
                                        rdfs:label ?defensiveLabel ;
                                        d3f:counters ?attackTechnique .
                    ?attackTechnique rdfs:label ?attackLabel .
                    OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel LIMIT 200
            `,
            cypher: "MATCH (defense:Resource)-[r:RELATED {type: 'mitigates'}]->(attack:Resource:ATTACK) RETURN attack.id AS sourceId, attack.name AS sourceName, 'ATTACK' AS sourceType, defense.id AS targetId, defense.name AS targetName, 'D3FEND' AS targetType, type(r) AS relType LIMIT 200"
        },
        "Q3_atlas_attack": {
            name: "🤖 ATLAS → ATT&CK",
            group: "AI Kill Chains",
            sparql: `
                SELECT (?atlasId AS ?sourceId) (?atlasName AS ?sourceName) ("ATLAS" AS ?sourceType)
                       (?attackId AS ?targetId) (?attackName AS ?targetName) ("ATTACK" AS ?targetType)
                       ("maps_to" AS ?relType)
                WHERE {
                    ?atlasId a <http://atlas.mitre.org/Pattern> ;
                             <http://www.w3.org/2000/01/rdf-schema#label> ?atlasName .
                    ?atlasId <http://atlas.mitre.org/relationship/maps_to> ?attackId .
                    ?attackId <http://www.w3.org/2000/01/rdf-schema#label> ?attackName .
                } LIMIT 100
            `,
            cypher: "MATCH (atlas:Resource:ATLAS)-[r:RELATED]->(attack:Resource:ATTACK) RETURN atlas.id AS sourceId, atlas.name AS sourceName, 'ATLAS' AS sourceType, attack.id AS targetId, attack.name AS targetName, 'ATTACK' AS targetType, type(r) AS relType LIMIT 200"
        }
    }
};


// 1. Endpoint to proxy SPARQL queries
app.post('/api/graphdb/query', async (req, res) => {
    try {
        const { query } = req.body;
        if (!query) return res.status(400).json({ error: "Missing query parameter" });

        const params = new URLSearchParams({ query: query });
        const response = await axios.get(`${SPARQL_URL}?${params.toString()}`, {
            headers: { "Accept": "application/sparql-results+json" }
        });
        res.json(response.data);
    } catch (error) {
        console.error("GraphDB Error:", error.message);
        res.status(500).json({ error: "Failed to connect to GraphDB", details: error.message });
    }
});

// 2. Endpoint to proxy Cypher queries
app.post('/api/neo4j/query', async (req, res) => {
    try {
        const { query } = req.body;
        if (!query) return res.status(400).json({ error: "Missing query parameter" });

        const session = driver.session();
        try {
            const result = await session.run(query);
            const data = result.records.map(record => {
                const obj = {};
                record.keys.forEach(key => {
                    obj[key] = record.get(key);
                });
                return obj;
            });
            res.json({ data: data });
        } finally {
            await session.close();
        }
    } catch (error) {
        console.error("Neo4j Error:", error.message);
        res.status(500).json({ error: "Failed to connect to Neo4j", details: error.message });
    }
});

// 3. Convenience endpoint to get pre-defined domains
app.get('/api/domains', (req, res) => {
    res.json(Object.keys(DOMAIN_QUERIES));
});

// 4. Endpoint to get queries for a specific domain
app.get('/api/domains/:domain/queries', (req, res) => {
    const domain = req.params.domain.toLowerCase();
    if (DOMAIN_QUERIES[domain]) {
        // Return summary of queries (id and name)
        const summary = Object.keys(DOMAIN_QUERIES[domain]).map(qid => ({
            id: qid,
            name: DOMAIN_QUERIES[domain][qid].name
        }));
        res.json(summary);
    } else {
        res.status(404).json({ error: "Domain not found" });
    }
});

// 5. Endpoint to get a specific query
app.get('/api/domains/:domain/queries/:id', (req, res) => {
    const domain = req.params.domain.toLowerCase();
    const qid = req.params.id;

    if (DOMAIN_QUERIES[domain] && DOMAIN_QUERIES[domain][qid]) {
        res.json(DOMAIN_QUERIES[domain][qid]);
    } else {
        res.status(404).json({ error: "Query not found" });
    }
});


// 6. DSS AI Query endpoint — calls rag_engine.py via Python subprocess
app.post('/api/dss/query', (req, res) => {
    const { question, backend = 'ollama', topK = 10, ollamaModel = 'llama3.2' } = req.body;
    if (!question) return res.status(400).json({ error: 'Missing question parameter' });

    const projectRoot = path.resolve(__dirname, '..', '..');
    const ragScript = path.join(projectRoot, 'rag', 'rag_engine.py');
    const venvPython = path.join(projectRoot, 'venv', 'bin', 'python3');

    const pythonBin = require('fs').existsSync(venvPython) ? venvPython : 'python3';

    const proc = spawn(pythonBin, [
        ragScript,
        '--query', question,
        '--backend', backend,
        '--top-k', String(topK),
        '--ollama-model', ollamaModel
    ], { env: { ...process.env } });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', d => stdout += d);
    proc.stderr.on('data', d => stderr += d);

    proc.on('close', code => {
        if (code !== 0) {
            console.error('[DSS] RAG engine error:', stderr);
            return res.status(500).json({ error: 'RAG engine failed', details: stderr.slice(0, 500) });
        }
        try {
            const result = JSON.parse(stdout);
            res.json(result);
        } catch (e) {
            res.status(500).json({ error: 'Failed to parse RAG response', raw: stdout.slice(0, 500) });
        }
    });
});


app.listen(port, () => {
    console.log(`Visualization backend running on http://localhost:${port}`);
});

// Clean up Neo4j driver on exit
process.on('SIGINT', async () => {
    await driver.close();
    process.exit(0);
});
process.on('SIGTERM', async () => {
    await driver.close();
    process.exit(0);
});
