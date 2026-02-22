const express = require('express');
const cors = require('cors');
const axios = require('axios');
const neo4j = require('neo4j-driver');

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
            name: "All ATT&CK → D3FEND",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT ?attackLabel ?defensiveLabel ?d3fID WHERE {
                    ?defensiveTechnique rdfs:subClassOf* d3f:DefensiveTechnique ;
                                        rdfs:label ?defensiveLabel ;
                                        d3f:counters ?attackTechnique .
                    ?attackTechnique rdfs:label ?attackLabel .
                    OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                } ORDER BY ?attackLabel ?defensiveLabel LIMIT 200
            `,
            cypher: `
                MATCH (defense:Resource)-[:COUNTERS]->(attack:Resource)
                WHERE defense.label[0] IS NOT NULL AND attack.label[0] IS NOT NULL
                RETURN DISTINCT attack.label[0] AS attackLabel, defense.label[0] AS defensiveLabel, defense.\`d3fend-id\`[0] AS d3fID
                ORDER BY attackLabel, defensiveLabel LIMIT 200
            `
        },
        "Q2_credential_attacks": {
            name: "Credential Attacks",
            sparql: `
                PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                SELECT DISTINCT ?attackLabel ?defensiveLabel ?definition ?d3fID WHERE {
                  ?defensiveTechnique rdfs:subClassOf* d3f:DefensiveTechnique ;
                                      rdfs:label ?defensiveLabel ;
                                      d3f:counters ?attackTechnique .
                  ?attackTechnique rdfs:label ?attackLabel .
                  OPTIONAL { ?defensiveTechnique d3f:definition ?definition . }
                  OPTIONAL { ?defensiveTechnique d3f:d3fend-id ?d3fID . }
                  FILTER(CONTAINS(LCASE(?attackLabel), "credential"))
                } ORDER BY ?attackLabel ?defensiveLabel
            `,
            cypher: `
                MATCH (defense:Resource)-[:COUNTERS]->(attack:Resource)
                WHERE toLower(attack.label[0]) CONTAINS 'credential'
                RETURN DISTINCT attack.label[0] AS attackLabel, defense.label[0] AS defensiveLabel, defense.definition[0] AS definition, defense.\`d3fend-id\`[0] AS d3fID
                ORDER BY attackLabel, defensiveLabel
            `
        }
    },
    capec: {
        "Q1_sample_capec": {
            name: "Sample CAPEC Query",
            sparql: "SELECT * WHERE { ?s ?p ?o } LIMIT 10",
            cypher: "MATCH (n) RETURN n LIMIT 10"
        }
    },
    cwe: {
        "Q1_sample_cwe": {
            name: "Sample CWE Query",
            sparql: "SELECT * WHERE { ?s ?p ?o } LIMIT 10",
            cypher: "MATCH (n) RETURN n LIMIT 10"
        }
    },
    attack: {
        "Q1_sample_attack": {
            name: "Sample ATT&CK Query",
            sparql: "SELECT * WHERE { ?s ?p ?o } LIMIT 10",
            cypher: "MATCH (n) RETURN n LIMIT 10"
        }
    },
    atlas: {
        "Q1_sample_atlas": {
            name: "Sample ATLAS Query",
            sparql: "SELECT * WHERE { ?s ?p ?o } LIMIT 10",
            cypher: "MATCH (n) RETURN n LIMIT 10"
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
