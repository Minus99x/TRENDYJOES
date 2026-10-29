"""Validate the owner streetwear archive and build a traceable print-test pack.
No Shopify writes, resizing, printer profiles, or production approval.
"""
import argparse
import csv
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path, PurePosixPath
from PIL import Image

FORMATS = {
    'dtf_front': ('art/dtf/{code}-FRONT_900x900.png', (900, 900), 'DTF', 'front'),
    'dtf_back': ('art/dtf/{code}-BACK_3600x4500.png', (3600, 4500), 'DTF', 'back'),
    'uv_hardgoods': ('art/uv/{code}-HARDGOODS_1200x1500.png', (1200, 1500), 'UV-DTF', 'hardgoods'),
    'uv_spot': ('art/uv/{code}-SPOT_900x900.png', (900, 900), 'UV-DTF', 'spot'),
}

def inspect_png(data, expected):
    with Image.open(io.BytesIO(data)) as image:
        if image.format != 'PNG' or image.size != expected or image.mode != 'RGBA':
            raise ValueError('Expected exact-size RGBA PNG')
        image.load()
        alpha = image.getchannel('A')
        low, high = alpha.getextrema()
        if low != 0 or high == 0:
            raise ValueError('Artwork must contain both transparent and visible pixels')
        dpi = image.info.get('dpi', ())
        if len(dpi) != 2 or any(abs(value - 300) > 1 for value in dpi):
            raise ValueError('Expected 300-PPI metadata; do not silently rescale')
        box = alpha.getbbox()
        return {'pixels': list(image.size), 'ppi': list(dpi),
                'canvas_inches_at_300ppi': [round(x / 300, 3) for x in image.size],
                'visible_bounds_pixels': list(box),
                'visible_inches_at_300ppi': [round((box[2]-box[0])/300, 3), round((box[3]-box[1])/300, 3)]}

def validate_names(infos):
    names = [i.filename for i in infos]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate archive entries')
    for info in infos:
        path = PurePosixPath(info.filename)
        if path.is_absolute() or '..' in path.parts or '\\' in info.filename or ':' in info.filename:
            raise ValueError('Unsafe archive path')
        if info.file_size > 64 * 1024 * 1024:
            raise ValueError('Oversized archive entry')
    if sum(i.file_size for i in infos) > 512 * 1024 * 1024:
        raise ValueError('Archive exceeds expanded size limit')

def prepare(source, output, report_path=None):
    source, output = Path(source), Path(output)
    if source.resolve() == output.resolve():
        raise ValueError('Output must not overwrite source')
    entries, files = [], {}
    with zipfile.ZipFile(source) as archive:
        validate_names(archive.infolist())
        original = json.loads(archive.read('MANIFEST.json'))
        release = json.loads(archive.read('RELEASE_MANIFEST.json'))['source_files']
        records = original['records']
        codes = [r['code'] for r in records]
        if len(codes) != 48 or len(set(codes)) != 48 or any(not re.fullmatch(r'M(?:0[1-9]|1[0-9]|2[0-4])-[AB]', c) for c in codes):
            raise ValueError('Expected 48 unique paired streetwear looks')
        for record in records:
            code = record['code']
            item = {'code': code, 'phrase': record['phrase'], 'style': record['style'], 'files': []}
            for kind, (pattern, dimensions, process, side) in FORMATS.items():
                name = pattern.format(code=code)
                data = archive.read(name)
                digest = hashlib.sha256(data).hexdigest()
                receipt = release.get(name, {})
                if receipt.get('sha256') != digest or receipt.get('bytes') != len(data):
                    raise ValueError(f'Integrity mismatch: {name}')
                info = inspect_png(data, dimensions)
                info.update(path=name, sha256=digest, bytes=len(data), kind=kind, process=process, side=side)
                files[name] = data
                item['files'].append(info)
            entries.append(item)
    report = {'schema': 'trendyjoes-print-test-pack-v1', 'source_archive_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'looks': len(entries), 'verified_pngs': len(files), 'file_validation': 'PASS',
              'physical_print_approved': False, 'rights_approved': False, 'checkout_enabled': False,
              'notes': ['Canvas inches and visible artwork inches are distinct; use the recorded bounds when planning placement.',
                        'No printer-specific white ink, varnish, mirroring, curing, or heat settings are supplied.',
                        'Use one verified substrate/material workflow and record physical test results before sale.',
                        'PNGs are unchanged original pixels. SVG masters remain in the original archive.'],
              'items': entries}
    manifest = json.dumps(report, indent=2) + '\n'
    sheet = io.StringIO(newline='')
    writer = csv.writer(sheet)
    writer.writerow(['look','phrase','process','side','file','canvas_width_in','canvas_height_in','visible_width_in','visible_height_in','material_lot','substrate','printer_profile','test_date','operator','dimensions_pass','adhesion_or_wash_test','visual_pass','rights_review','approved_for_sale','notes'])
    for item in entries:
        for file in item['files']:
            writer.writerow([item['code'],item['phrase'],file['process'],file['side'],file['path'],*file['canvas_inches_at_300ppi'],*file['visible_inches_at_300ppi'],*(['']*9),'NO',''])
    instructions = '''TRENDYJOES — PRINT-TEST STARTER PACK

1. Extract this ZIP. Open PRINT_TEST_QUEUE.csv to select a look and process.
2. DTF apparel files are in art/dtf. UV-DTF hardgoods files are in art/uv.
3. Import the original PNG into the manufacturer's supported software.
4. Confirm dimensions with the queue: canvas size includes transparent margins.
5. Use the manufacturer's instructions for the exact printer, transfer media,
   substrate and finishing equipment. Do not infer settings from the PNG metadata.
6. Print a small trial, measure placement, inspect the result, and record tests.
7. Keep approved_for_sale NO until physical results and rights are approved.

This pack verifies file integrity, pixels, alpha and PPI only. It does not certify
printer compatibility, durability, wash resistance, licensing or checkout.
The original editable SVG masters are retained in the original full archive.
'''
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + '.tmp')
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED) as target:
            for name, data in sorted(files.items()):
                target.writestr(name, data)
            target.writestr('VERIFIED_MANIFEST.json', manifest)
            target.writestr('PRINT_TEST_QUEUE.csv', sheet.getvalue())
            target.writestr('START_HERE.txt', instructions)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    if report_path:
        Path(report_path).write_text(manifest)
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source'); parser.add_argument('output'); parser.add_argument('--report')
    args = parser.parse_args()
    result = prepare(args.source, args.output, args.report)
    print(json.dumps({k: result[k] for k in ('looks','verified_pngs','file_validation','physical_print_approved')}))
