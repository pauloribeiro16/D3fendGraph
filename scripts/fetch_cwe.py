"""
fetch_cwe.py — Fetches full CWE data from the official CWE REST API.

API root: https://cwe-api.mitre.org/api/v1/
Endpoints used:
  GET /cwe/view/699           → categories in the Software Development view
  GET /cwe/category/{id}       → weaknesses that are MemberOf each category
  GET /cwe/weakness/{id}       → full weakness detail (all fields)
  GET /cwe/weakness/{id}/parents?view=1000  → ChildOf parents in research view

As recommended by the API docs, results are cached locally as:
  data/cwe_parsed.json      — list of weakness dicts
  data/cwe_categories.json  — list of category dicts
"""

import json
import os
import time
import urllib.request
import urllib.error
import ssl

BASE = 'https://cwe-api.mitre.org/api/v1'

def _get(path, retries=3, delay=1.0):
    """GET JSON from the CWE REST API with basic retry logic."""
    url = f'{BASE}{path}'
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'D3fendGraph/1.0', 'Accept': 'application/json'})
            with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if attempt < retries - 1:
                time.sleep(delay)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                raise
    return None


def _parse_weakness(w):
    """Normalise a single weakness JSON object from the API into our schema."""
    cwe_id = 'CWE-' + str(w.get('ID', ''))

    # ── Platforms ──────────────────────────────────────────────────────────────
    platforms = []
    for p in w.get('ApplicablePlatforms', []):
        label = p.get('Name') or p.get('Class', '')
        prev  = p.get('Prevalence', '')
        if label:
            platforms.append(f"{label} ({prev})" if prev else label)

    # ── Common Consequences ────────────────────────────────────────────────────
    consequences = []
    for c in w.get('CommonConsequences', []):
        cons_entry = {
            'scope':  ', '.join(c.get('Scope',  []) or []),
            'impact': ', '.join(c.get('Impact', []) or [])
        }
        if c.get('Note'):
            cons_entry['note'] = c['Note']
        if cons_entry['scope'] or cons_entry['impact']:
            consequences.append(cons_entry)

    # ── Mitigations ────────────────────────────────────────────────────────────
    mitigations = []
    for m in w.get('PotentialMitigations', []):
        phases = m.get('Phase', []) or []
        desc   = m.get('Description', '') or ''
        if desc or phases:
            mitigations.append({'phases': phases, 'description': desc.strip()})

    # ── Detection Methods ──────────────────────────────────────────────────────
    detection = []
    for d in w.get('DetectionMethods', []):
        method = d.get('Method', '')
        desc   = d.get('Description', '') or ''
        eff    = d.get('Effectiveness', '') or ''
        if method:
            detection.append({'method': method, 'description': desc.strip(), 'effectiveness': eff})

    # ── Intro Phases ───────────────────────────────────────────────────────────
    intro_phases = [m.get('Phase', '') for m in w.get('ModesOfIntroduction', []) if m.get('Phase')]

    # ── Related Weaknesses ─────────────────────────────────────────────────────
    parents   = []
    member_of = []
    for rel in w.get('RelatedWeaknesses', []):
        nature = rel.get('Nature', '')
        rid    = 'CWE-' + str(rel.get('CweID', ''))
        view   = str(rel.get('ViewID', ''))
        if nature == 'ChildOf':
            parents.append(rid)
        elif nature == 'MemberOf':
            member_of.append({'category_id': rid, 'view_id': view})

    # ── Taxonomy Mappings ──────────────────────────────────────────────────────
    taxonomy = []
    for t in w.get('TaxonomyMappings', []):
        tax_name = t.get('TaxonomyName', '')
        if tax_name:
            taxonomy.append({'taxonomy': tax_name, 'id': t.get('EntryID', ''), 'name': t.get('EntryName', '')})

    # ── Observed Examples ──────────────────────────────────────────────────────
    examples = []
    for e in w.get('ObservedExamples', []):
        ref = e.get('Reference', '')
        if ref:
            examples.append({'reference': ref, 'description': e.get('Description', ''), 'link': e.get('Link', '')})

    return {
        'id':                   cwe_id,
        'name':                 w.get('Name', ''),
        'abstraction':          w.get('Abstraction', ''),
        'status':               w.get('Status', ''),
        'description':          (w.get('Description', '') or '').strip(),
        'extended_description':  (w.get('ExtendedDescription', '') or '').strip(),
        'likelihood':           w.get('LikelihoodOfExploit', '') or '',
        'platforms':            platforms,
        'consequences':         consequences,
        'mitigations':          mitigations,
        'detection':            detection,
        'intro_phases':         intro_phases,
        'taxonomy':             taxonomy,
        'observed_examples':    examples,
        'parents':              parents,
        'member_of':            member_of,
    }


def download_cwe():
    DATA_DIR = os.environ.get('DATA_DIR', 'data')
    os.makedirs(DATA_DIR, exist_ok=True)

    # ── Step 1: get View-699 (Software Development) members = category IDs ─────
    print('Fetching View-699 (Software Development)…')
    view_data = _get('/cwe/view/699')
    category_ids = []
    if view_data and view_data.get('Views'):
        for member in view_data['Views'][0].get('Members', []):
            category_ids.append(str(member['CweID']))
    print(f'  Found {len(category_ids)} top-level categories in View-699')

    # ── Step 2: fetch each category and collect its member weakness IDs ─────────
    print('Fetching category details…')
    categories    = []
    weakness_ids  = set()

    for cid in category_ids:
        cat_data = _get(f'/cwe/category/{cid}')
        if not cat_data or not cat_data.get('Categories'):
            continue
        cat = cat_data['Categories'][0]
        summary = ''
        for n in cat.get('Notes', []):
            if n.get('Type') == 'Summary':
                summary = n.get('Note', '')
                break

        member_weakness_ids = []
        for rel in cat.get('Relationships', []):
            # Relationships in a category = Has_Member references
            wid = str(rel.get('CweID', ''))
            if wid:
                member_weakness_ids.append('CWE-' + wid)
                weakness_ids.add(wid)

        categories.append({
            'id':          'CWE-' + cid,
            'name':        cat.get('Name', ''),
            'summary':     summary,
            'view_ids':    ['699'],
            'members':     member_weakness_ids
        })
        time.sleep(0.1)  # be polite

    print(f'  Collected {len(weakness_ids)} unique weakness IDs from categories')

    # ── Always include the full CWE Top-25 (2024) — some aren't in View-699 ────
    TOP_25 = {
        '79','787','89','416','78','20','125','22','352','434',
        '862','476','287','190','502','77','119','798','918','306',
        '362','269','94','863','276'
    }
    before = len(weakness_ids)
    weakness_ids.update(TOP_25)
    print(f'  Added {len(weakness_ids) - before} extra Top-25 IDs not in View-699 categories')

    # ── Step 3: fetch full detail for each weakness ─────────────────────────────
    print(f'Fetching full weakness detail for {len(weakness_ids)} weaknesses…')
    cwes = []
    for i, wid in enumerate(sorted(weakness_ids, key=lambda x: int(x)), 1):
        if i % 50 == 0:
            print(f'  {i}/{len(weakness_ids)}…')
        w_data = _get(f'/cwe/weakness/{wid}')
        if not w_data or not w_data.get('Weaknesses'):
            continue
        cwes.append(_parse_weakness(w_data['Weaknesses'][0]))
        time.sleep(0.05)  # ~20 req/s

    print(f'  Parsed {len(cwes)} weaknesses')

    # ── Save ────────────────────────────────────────────────────────────────────
    parsed_path = os.path.join(DATA_DIR, 'cwe_parsed.json')
    with open(parsed_path, 'w') as f:
        json.dump(cwes, f, indent=2)
    print(f'Saved {len(cwes)} CWEs → {parsed_path}')

    cat_path = os.path.join(DATA_DIR, 'cwe_categories.json')
    with open(cat_path, 'w') as f:
        json.dump(categories, f, indent=2)
    print(f'Saved {len(categories)} categories → {cat_path}')

    return cwes, categories


if __name__ == '__main__':
    download_cwe()
