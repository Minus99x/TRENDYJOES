"""Validate and reorient closed binary STL meshes; no manufacturing approval implied.

Usage: python scripts/repair_stl_orientation.py input.zip output.zip
Dependency: trimesh>=4.11,<5. Never alters source inputs.
"""
import hashlib
import json
import sys
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

import trimesh


def repair_bytes(blob):
    mesh = trimesh.load(BytesIO(blob), file_type='stl', process=True)
    if not isinstance(mesh, trimesh.Trimesh) or mesh.is_empty:
        raise ValueError('STL contains no usable triangle mesh')
    if not mesh.is_watertight or not mesh.is_winding_consistent or len(mesh.split()) != 1:
        raise ValueError('STL must be closed, consistently wound and connected before repair')
    signed_before = float(mesh.volume)
    if abs(signed_before) < 1e-8:
        raise ValueError('STL has no valid enclosed volume')
    bounds_before = mesh.bounds.copy()
    if signed_before < 0:
        mesh.invert()
    exported = mesh.export(file_type='stl')
    check = trimesh.load(BytesIO(exported), file_type='stl', process=True)
    if not check.is_watertight or not check.is_winding_consistent or check.volume <= 0 or len(check.split()) != 1:
        raise ValueError('Orientation repair failed validation')
    if not (abs(bounds_before - check.bounds) < 1e-4).all():
        raise ValueError('Orientation repair unexpectedly changed mesh bounds')
    return exported, {
        'source_sha256': hashlib.sha256(blob).hexdigest(),
        'output_sha256': hashlib.sha256(exported).hexdigest(),
        'signed_volume_before': round(signed_before, 3),
        'signed_volume_after': round(float(check.volume), 3),
        'dimensions_mm_assumed': [round(float(n), 3) for n in check.extents],
        'triangles': len(check.faces),
        'watertight': True,
        'connected_components': 1,
        'orientation_repaired': signed_before < 0,
        'physical_print_verified': False,
    }


def repair_archive(source, destination):
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('Source and destination must be different paths')
    results = {}
    with ZipFile(source) as src, ZipFile(destination, 'w', compression=ZIP_DEFLATED) as out:
        names = [item.filename for item in src.infolist() if item.filename.lower().endswith('.stl')]
        if not names or len(names) != len(set(names)):
            raise ValueError('Archive must contain uniquely named STL files')
        for name in names:
            if name.startswith('/') or '..' in Path(name).parts:
                raise ValueError('Unsafe archive path')
            converted, record = repair_bytes(src.read(name))
            out.writestr(Path(name).name, converted)
            results[Path(name).name] = record
        out.writestr('VERIFICATION.json', json.dumps({
            'units': 'millimeters assumed (not encoded by STL)',
            'rights_cleared': False,
            'printer_tested': False,
            'files': results,
        }, indent=2) + '\n')
    return results


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(json.dumps(repair_archive(sys.argv[1], sys.argv[2]), indent=2))
