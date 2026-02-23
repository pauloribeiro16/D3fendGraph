"""
rag_engine.py — Phase 3
RAG (Retrieval-Augmented Generation) engine for the AI-Driven DSS.

Query flow:
  1. Embed the user's natural language question
  2. Retrieve top-K most similar nodes from Neo4j vector search
  3. Assemble a context block from the retrieved nodes
  4. Call the LLM (OpenAI or Ollama) with a structured prompt
  5. Return JSON: { "answer": str, "sources": list }

Usage (standalone test):
    OPENAI_API_KEY=sk-... python3 rag/rag_engine.py --backend openai --query "brute force login attacks"
    python3 rag/rag_engine.py --backend ollama --query "SQL injection weaknesses"

As a module (called from server.js via child_process):
    python3 rag/rag_engine.py --backend ollama --query "<user question>" --top-k 10
"""
import os
import sys
import json
import argparse
import numpy as np
from neo4j import GraphDatabase

NEO4J_URI  = "bolt://localhost:7687"
NEO4J_AUTH = ("neo4j", "d3fendtest")

# ── Embedding helpers ──────────────────────────────────────────────────────────

def embed_openai(text: str) -> list:
    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    resp = client.embeddings.create(input=[text], model="text-embedding-3-small")
    return resp.data[0].embedding

def embed_ollama(text: str) -> list:
    import httpx
    resp = httpx.post(
        "http://localhost:11434/api/embeddings",
        json={"model": "nomic-embed-text", "prompt": text},
        timeout=60
    )
    resp.raise_for_status()
    return resp.json()["embedding"]

def cosine_similarity(a, b):
    a, b = np.array(a), np.array(b)
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    return float(np.dot(a, b) / denom) if denom > 0 else 0.0

# ── Retrieval ──────────────────────────────────────────────────────────────────

def retrieve_nodes(query_embedding: list, top_k: int = 10) -> list:
    """
    Brute-force cosine similarity search over all nodes with embeddings in Neo4j.
    When Neo4j 5 vector index is available, use CALL db.index.vector.queryNodes(...) instead.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    cypher = """
    MATCH (n)
    WHERE n.embedding IS NOT NULL
    RETURN labels(n) AS labels,
           n.id AS id, n.name AS name,
           coalesce(n.description, '') AS description,
           coalesce(n.mitigations, '') AS mitigations,
           n.embedding AS embedding
    """
    with driver.session() as session:
        records = list(session.run(cypher))
    driver.close()

    scored = []
    for r in records:
        sim = cosine_similarity(query_embedding, r["embedding"])
        scored.append({
            "labels": r["labels"],
            "id": r["id"],
            "name": r["name"],
            "description": r["description"],
            "mitigations": r["mitigations"],
            "similarity": sim
        })

    scored.sort(key=lambda x: x["similarity"], reverse=True)
    return scored[:top_k]

# ── Context assembly ───────────────────────────────────────────────────────────

def format_context(nodes: list) -> str:
    lines = []
    for n in nodes:
        framework = ", ".join(n["labels"]) if n["labels"] else "Unknown"
        lines.append(f"[{framework}] {n['id']} — {n['name']}")
        if n["description"]:
            lines.append(f"  Description: {n['description'][:400]}")
        if n["mitigations"]:
            lines.append(f"  Mitigations: {n['mitigations'][:400]}")
        lines.append("")
    return "\n".join(lines)

# ── LLM call ──────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert cybersecurity analyst and Decision Support System.
You will be given a security requirement from a researcher or engineer.
You will also receive a Context of relevant knowledge graph entries from D3FEND, ATT&CK, CAPEC, CWE, and ATLAS.
Your task is to:
1. Identify and list the most relevant threats and attack patterns.
2. Map each threat to specific CWE weaknesses where applicable.
3. Provide concrete defensive techniques from D3FEND or ATLAS.
4. Summarize with a structured, actionable recommendations section.

Always be precise, cite the IDs provided (e.g. CWE-89, CAPEC-66), and organize your response clearly.
"""

def call_openai(question: str, context: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Security Requirement / Question:\n{question}\n\n--- Knowledge Graph Context ---\n{context}\n\nPlease provide your analysis."}
    ]
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=messages, max_tokens=1500)
    return resp.choices[0].message.content

def call_ollama(question: str, context: str, model: str = "llama3.2") -> str:
    import httpx
    prompt = f"""{SYSTEM_PROMPT}

Security Requirement / Question:
{question}

--- Knowledge Graph Context ---
{context}

Please provide your analysis."""
    resp = httpx.post(
        "http://localhost:11434/api/generate",
        json={"model": model, "prompt": prompt, "stream": False},
        timeout=120
    )
    resp.raise_for_status()
    return resp.json()["response"]

# ── Main ───────────────────────────────────────────────────────────────────────

def run(query: str, backend: str = "ollama", top_k: int = 10, ollama_model: str = "llama3.2") -> dict:
    # Step 1: Embed the query
    if backend == "openai":
        q_embedding = embed_openai(query)
    else:
        q_embedding = embed_ollama(query)

    # Step 2: Retrieve relevant nodes
    nodes = retrieve_nodes(q_embedding, top_k=top_k)

    # Step 3: Assemble context
    context = format_context(nodes)

    # Step 4: Call LLM
    if backend == "openai":
        answer = call_openai(query, context)
    else:
        answer = call_ollama(query, context, model=ollama_model)

    sources = [{"id": n["id"], "name": n["name"], "labels": n["labels"], "similarity": round(n["similarity"], 4)} for n in nodes]
    return {"answer": answer, "sources": sources}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RAG Engine for AI-Driven DSS")
    parser.add_argument("--query", required=True, help="Natural language security question")
    parser.add_argument("--backend", default="ollama", choices=["openai", "ollama"])
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--ollama-model", default="llama3.2")
    args = parser.parse_args()

    result = run(args.query, backend=args.backend, top_k=args.top_k, ollama_model=args.ollama_model)
    print(json.dumps(result, indent=2))
