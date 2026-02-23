"""
build_embeddings.py
Phase 2: Generate vector embeddings for all knowledge graph nodes and store them in Neo4j.

Supports two embedding backends:
  - openai: uses text-embedding-3-small (requires OPENAI_API_KEY env var)
  - ollama: uses nomic-embed-text (free, local, requires Ollama running)

Usage:
    python3 scripts/build_embeddings.py --backend ollama
    python3 scripts/build_embeddings.py --backend openai
"""
import argparse
import os
import json
from neo4j import GraphDatabase

NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = ("neo4j", "d3fendtest")

def get_embedding_openai(texts):
    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    embeddings = []
    batch_size = 100
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        resp = client.embeddings.create(input=batch, model="text-embedding-3-small")
        embeddings.extend([d.embedding for d in resp.data])
    return embeddings

def get_embedding_ollama(texts):
    import httpx
    embeddings = []
    for text in texts:
        resp = httpx.post(
            "http://localhost:11434/api/embeddings",
            json={"model": "nomic-embed-text", "prompt": text},
            timeout=60
        )
        resp.raise_for_status()
        embeddings.append(resp.json()["embedding"])
    return embeddings

def build_text(node):
    parts = [node.get("id", ""), node.get("name", ""), node.get("description", "")]
    return " | ".join(p for p in parts if p)

def embed_and_store(backend="ollama"):
    driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)

    labels_to_embed = [
        ("CWE",           "MATCH (n:CWE) RETURN elementId(n) AS eid, n.id AS id, n.name AS name, n.description AS desc, coalesce(n.mitigations,'') AS mitigations LIMIT 1000"),
        ("CAPEC",         "MATCH (n:Resource:CAPEC) RETURN elementId(n) AS eid, n.id AS id, n.name AS name, n.description AS desc, '' AS mitigations LIMIT 1000"),
        ("ATTACK",        "MATCH (n:Resource:ATTACK) RETURN elementId(n) AS eid, n.id AS id, n.name AS name, n.description AS desc, '' AS mitigations LIMIT 1000"),
        ("ATLAS",         "MATCH (n:Resource:ATLAS) RETURN elementId(n) AS eid, n.id AS id, n.name AS name, n.description AS desc, '' AS mitigations LIMIT 1000"),
    ]

    for label, query in labels_to_embed:
        print(f"\n[EMBEDDING] {label} ...")
        with driver.session() as session:
            records = list(session.run(query))
        
        if not records:
            print(f"  No {label} nodes found, skipping.")
            continue

        texts = [f"{r['id']} {r['name']} {r.get('desc') or ''} {r.get('mitigations') or ''}" for r in records]
        eids = [r["eid"] for r in records]

        print(f"  Fetched {len(texts)} nodes. Generating embeddings via {backend}...")
        if backend == "openai":
            vecs = get_embedding_openai(texts)
        else:
            vecs = get_embedding_ollama(texts)

        print(f"  Storing embeddings back to Neo4j...")
        with driver.session() as session:
            for eid, vec in zip(eids, vecs):
                session.run(
                    "MATCH (n) WHERE elementId(n) = $eid SET n.embedding = $vec",
                    eid=eid, vec=vec
                )
        print(f"  Done: {len(vecs)} {label} embeddings stored.")

    driver.close()
    print("\nAll embeddings built successfully!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", default="ollama", choices=["openai", "ollama"])
    args = parser.parse_args()
    embed_and_store(args.backend)
