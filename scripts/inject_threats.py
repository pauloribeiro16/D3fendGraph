import json
import requests
from neo4j import GraphDatabase

NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = ("neo4j", "d3fendtest")

GRAPHDB_REPO = "http://localhost:7200/repositories/d3fend/statements"

def insert_cwe():
    try:
        with open('data/cwe_parsed.json') as f:
            cwes = json.load(f)
    except Exception as e:
        print("CWE file not found:", e)
        return
        
    print(f"Loaded {len(cwes)} CWEs")

    # Neo4j
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        with driver.session() as session:
            session.run("UNWIND $cwes AS c MERGE (n:CWE {id: c.id}) SET n.name = c.name", cwes=cwes)
            print("CWE inserted into Neo4j")
        driver.close()
    except Exception as e:
        print("Neo4j error:", e)
    
    # GraphDB
    try:
        triples = []
        prefix = "http://cwe.mitre.org/data/definitions/"
        for cwe in cwes:
            cwe_uri = f"<{prefix}{cwe['id']}>"
            name_lit = json.dumps(cwe.get('name', '')).replace("\\n", " ")
            triples.append(f"{cwe_uri} <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://cwe.mitre.org/cwe-schema#Weakness> .")
            triples.append(f"{cwe_uri} <http://www.w3.org/2000/01/rdf-schema#label> {name_lit} .")
            
        rdf_data = "\n".join(triples)
        resp = requests.post(GRAPHDB_REPO, data=rdf_data.encode('utf-8'), headers={"Content-Type": "application/x-ntriples"})
        print("GraphDB CWE insert status:", resp.status_code)
    except Exception as e:
        print("GraphDB error:", e)


def insert_stix(file_path, label, uri_prefix):
    try:
        with open(file_path) as f:
            data = json.load(f)
    except Exception as e:
        print(f"{label} file not found: {e}")
        return
        
    objects = data.get('objects', [])
    items = []
    for obj in objects:
        if obj.get('type') == 'attack-pattern':
            
            # extract external id
            ext_id = obj.get('id', '')
            if obj.get('external_references'):
                ext_id = obj['external_references'][0].get('external_id', ext_id)
                
            items.append({
                'id': ext_id,
                'name': obj.get('name', ''),
            })
            
    print(f"Loaded {len(items)} {label} from {file_path}")

    if not items: return

    # Neo4j
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        with driver.session() as session:
            session.run(f"UNWIND $items AS item MERGE (n:Resource:{label} {{id: item.id}}) SET n.name = item.name", items=items)
            print(f"{label} inserted into Neo4j")
        driver.close()
    except Exception as e:
        print(f"Neo4j {label} error:", e)

    # GraphDB
    try:
        triples = []
        for item in items:
            item_uri = f"<{uri_prefix}{item['id']}>"
            name_lit = json.dumps(item.get('name', '')).replace("\\n", " ")
            triples.append(f"{item_uri} <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <{uri_prefix}Pattern> .")
            triples.append(f"{item_uri} <http://www.w3.org/2000/01/rdf-schema#label> {name_lit} .")

        rdf_data = "\n".join(triples)
        resp = requests.post(GRAPHDB_REPO, data=rdf_data.encode('utf-8'), headers={"Content-Type": "application/x-ntriples"})
        print(f"GraphDB {label} insert status:", resp.status_code)
    except Exception as e:
        print(f"GraphDB {label} error:", e)

if __name__ == '__main__':
    insert_cwe()
    insert_stix('data/capec.json', 'CAPEC', 'http://capec.mitre.org/data/definitions/')
    insert_stix('data/mitre_attack_enterprise.json', 'ATTACK', 'http://attack.mitre.org/')
