"""Validate launch-02 production-art catalog metadata without asserting hosted assets.
This is an index gate; genuine downloaded files are hash-checked separately.
"""
import json
from pathlib import Path

p = Path(__file__).with_name('launch-02-transfer-art-index.json')
data = json.loads(p.read_text(encoding='utf-8'))
assert data['schema'] == 'trendyjoes-launch02-transfer-catalog-v1'
entries = data['items']
assert len(entries) == 36, 'Expected 36 standard designs'
assert len({entry['sku'] for entry in entries}) == 36
assert len({entry['artwork_prefix'] for entry in entries}) == 36
categories = {k: sum(1 for x in entries if x['category'] == k) for k in ('Thanksgiving', 'Holiday', 'Everyday')}
assert categories == {'Thanksgiving': 12, 'Holiday': 12, 'Everyday': 12}, categories
for entry in entries:
    assert entry['sku'][0] in ('T', 'H', 'E')
    assert entry['rights'] == 'pending-review'
    assert entry['checkout'] == 'disabled'
    assert entry['asset_presence'] == 'owner-download-archive-only'
    paths = entry['files']
    assert len(paths) == 4 and len(set(paths)) == 4
    expected_paths = [
        f"editable_svg/{entry['artwork_prefix']}.svg",
        f"dtf_3600x4500/{entry['artwork_prefix']}.png",
        f"uv_dtf_4x5_1200x1500/{entry['artwork_prefix']}.png",
        f"uv_dtf_3x3_900x900/{entry['artwork_prefix']}.png",
    ]
    assert paths == expected_paths, entry['sku']
holds = data['private_trademark_review_only']
assert len(holds) == 2
assert {x['sku'] for x in holds} == {'R01', 'R02'}
assert all('GRINCH' in h['title'] for h in holds)
assert not any('GRINCH' in item['title'] for item in entries)
assert data['asset_hosting'].startswith('NOT YET')
print('PASS: 36 catalog references, 12 per collection, 2 rights holds, no hosted-asset or checkout claim')
