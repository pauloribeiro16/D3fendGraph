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

    # Load categories if available
    categories = []
    try:
        with open('data/cwe_categories.json') as f:
            categories = json.load(f)
        print(f"Loaded {len(categories)} CWE categories")
    except Exception:
        pass

    # Neo4j
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        with driver.session() as session:
            # Serialise list/dict fields to JSON strings for Neo4j
            cwes_neo = []
            for c in cwes:
                cwes_neo.append({
                    'id':                c['id'],
                    'name':              c.get('name', ''),
                    'abstraction':       c.get('abstraction', ''),
                    'status':            c.get('status', ''),
                    'description':       c.get('description', ''),
                    'extended_description': c.get('extended_description', ''),
                    'likelihood':        c.get('likelihood', ''),
                    'platforms':         json.dumps(c.get('platforms', [])),
                    'consequences':      json.dumps(c.get('consequences', [])),
                    'mitigations':       json.dumps(c.get('mitigations', [])),
                    'detection':         json.dumps(c.get('detection', [])),
                    'intro_phases':      json.dumps(c.get('intro_phases', [])),
                    'taxonomy':          json.dumps(c.get('taxonomy', [])),
                    'observed_examples': json.dumps(c.get('observed_examples', [])),
                })
            session.run("""
            UNWIND $cwes AS c 
            MERGE (n:CWE {id: c.id}) 
            SET n.name = c.name,
                n.abstraction = c.abstraction,
                n.status = c.status,
                n.description = c.description,
                n.extended_description = c.extended_description,
                n.likelihood = c.likelihood,
                n.platforms = c.platforms,
                n.consequences = c.consequences,
                n.mitigations = c.mitigations,
                n.detection = c.detection,
                n.intro_phases = c.intro_phases,
                n.taxonomy = c.taxonomy,
                n.observed_examples = c.observed_examples
            """, cwes=cwes_neo)

            # Add ChildOf edges
            edges = [{'child': c['id'], 'parent': p} for c in cwes for p in c.get('parents', [])]
            if edges:
                session.run("""
                UNWIND $edges AS e
                MATCH (child:CWE {id: e.child})
                MATCH (parent:CWE {id: e.parent})
                MERGE (child)-[:CHILD_OF]->(parent)
                """, edges=edges)
                print(f"CWE: inserted {len(edges)} ChildOf edges into Neo4j")

            # Insert Category nodes (CWECategory label)
            if categories:
                cats_neo = [{'id': cat['id'], 'name': cat['name'], 'summary': cat.get('summary', '')} for cat in categories]
                session.run("""
                UNWIND $cats AS c
                MERGE (n:CWECategory {id: c.id})
                SET n.name = c.name, n.summary = c.summary, n.view699 = true
                """, cats=cats_neo)
                print(f"CWE: inserted {len(cats_neo)} Category nodes into Neo4j")

            # Add MEMBER_OF edges (weakness → category) for View-699
            member_edges = []
            for cat in categories:
                for wid in cat.get('members', []):
                    member_edges.append({'weakness': wid, 'category': cat['id']})
            if member_edges:
                session.run("""
                UNWIND $edges AS e
                MATCH (w:CWE {id: e.weakness})
                MATCH (cat:CWECategory {id: e.category})
                MERGE (w)-[:MEMBER_OF]->(cat)
                """, edges=member_edges)
                print(f"CWE: inserted {len(member_edges)} MEMBER_OF edges into Neo4j")

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
            desc_lit = json.dumps(cwe.get('description', '')).replace("\\n", " ")
            type_uri = "<http://cwe.mitre.org/cwe-schema#Weakness>"
            triples.append(f"{cwe_uri} <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> {type_uri} .")
            triples.append(f"{cwe_uri} <http://www.w3.org/2000/01/rdf-schema#label> {name_lit} .")
            if desc_lit and desc_lit != '""':
                triples.append(f"{cwe_uri} <http://cwe.mitre.org/cwe-schema#description> {desc_lit} .")
            for parent_id in cwe.get('parents', []):
                parent_uri = f"<{prefix}{parent_id}>"
                triples.append(f"{cwe_uri} <http://cwe.mitre.org/cwe-schema#childOf> {parent_uri} .")
        rdf_data = "\n".join(triples)
        resp = requests.post(GRAPHDB_REPO, data=rdf_data.encode('utf-8'), headers={"Content-Type": "application/n-triples"})
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
    id_map = {}
    for obj in objects:
        obj_type = obj.get('type')
        if obj_type in ('attack-pattern', 'course-of-action', 'intrusion-set', 'malware', 'tool', 'x-mitre-tactic', 'campaign', 'grouping'):
            
            # extract external id
            stix_id = obj.get('id', '')
            ext_id = stix_id
            if obj.get('external_references'):
                ext_id = obj['external_references'][0].get('external_id', ext_id)
            
            id_map[stix_id] = ext_id
                
            items.append({
                'id': ext_id,
                'stix_id': stix_id,
                'name': obj.get('name', ''),
                'description': obj.get('description', ''),
                'type': obj_type
            })
            
    relationships = []
    for obj in objects:
        if obj.get('type') == 'relationship':
            src = id_map.get(obj.get('source_ref'), obj.get('source_ref'))
            tgt = id_map.get(obj.get('target_ref'), obj.get('target_ref'))
            r_type = obj.get('relationship_type', 'related-to')
            if src and tgt:
                relationships.append({'source': src, 'target': tgt, 'type': r_type})
                
    cross_relationships = []
    for obj in objects:
        if obj.get('type') in ('attack-pattern', 'course-of-action', 'intrusion-set', 'malware', 'tool', 'x-mitre-tactic', 'campaign', 'grouping'):
            ext_id = id_map.get(obj.get('id', ''))
            if not ext_id: continue
            for ref in obj.get('external_references', []):
                ref_id = ref.get('external_id')
                src_name = ref.get('source_name', '').lower()
                if not ref_id or ref_id == ext_id: continue
                if src_name == 'cwe':
                    cross_relationships.append({'source': ext_id, 'target': ref_id, 'type': 'explores'})
                elif src_name == 'capec':
                    cross_relationships.append({'source': ext_id, 'target': ref_id, 'type': 'related-to'})
                elif 'attack' in src_name:
                    cross_relationships.append({'source': ext_id, 'target': ref_id, 'type': 'maps_to'})
                
    print(f"Loaded {len(items)} {label} nodes, {len(relationships)} standard rels, and {len(cross_relationships)} cross-rels from {file_path}")

    if not items: return

    # Neo4j
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        with driver.session() as session:
            session.run(f"UNWIND $items AS item MERGE (n:Resource:{label} {{id: item.id}}) SET n.stix_id = item.stix_id, n.name = item.name, n.description = item.description, n.type = item.type", items=items)
            
            if relationships:
                session.run(f"""
                UNWIND $rels AS rel
                MATCH (s) WHERE s.id = rel.source OR s.stix_id = rel.source
                MATCH (t) WHERE t.id = rel.target OR t.stix_id = rel.target
                MERGE (s)-[:RELATED {{type: rel.type}}]->(t)
                """, rels=relationships)
                
            if cross_relationships:
                session.run(f"""
                UNWIND $rels AS rel
                MATCH (s:Resource:{label} {{id: rel.source}})
                MATCH (t) WHERE t.id = rel.target OR t.stix_id = rel.target
                MERGE (s)-[:RELATED {{type: rel.type}}]->(t)
                """, rels=cross_relationships)
                print(f"{label} inserted {len(cross_relationships)} cross relationships into Neo4j")

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
            desc_lit = json.dumps(item.get('description', '')).replace("\\n", " ")
            type_uri = f"<{uri_prefix}{item['type'].title().replace('-', '')}>"
            triples.append(f"{item_uri} <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> {type_uri} .")
            triples.append(f"{item_uri} <http://www.w3.org/2000/01/rdf-schema#label> {name_lit} .")
            if desc_lit and desc_lit != '""':
                triples.append(f"{item_uri} <http://www.w3.org/2000/01/rdf-schema#comment> {desc_lit} .")

        for rel in relationships:
            src_uri = f"<{uri_prefix}{rel['source']}>"
            tgt_uri = f"<{uri_prefix}{rel['target']}>"
            rel_uri = f"<{uri_prefix}relationship/{rel['type']}>"
            triples.append(f"{src_uri} {rel_uri} {tgt_uri} .")

        rdf_data = "\n".join(triples)
        resp = requests.post(GRAPHDB_REPO, data=rdf_data.encode('utf-8'), headers={"Content-Type": "application/n-triples"})
        print(f"GraphDB {label} insert status:", resp.status_code)
    except Exception as e:
        print(f"GraphDB {label} error:", e)

if __name__ == '__main__':
    insert_cwe()
    insert_stix('data/capec.json', 'CAPEC', 'http://capec.mitre.org/data/definitions/')
    insert_stix('data/mitre_attack_enterprise.json', 'ATTACK', 'http://attack.mitre.org/')
    insert_stix('data/mitre_attack_mobile.json', 'ATTACK', 'http://attack.mitre.org/')
    insert_stix('data/atlas.json', 'ATLAS', 'http://atlas.mitre.org/')
