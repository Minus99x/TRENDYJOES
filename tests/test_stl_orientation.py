"""Regression checks for real printable mesh export, never a physical print claim."""
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

import trimesh

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'repair_stl_orientation.py'
spec = importlib.util.spec_from_file_location('tj_stl_orientation', MODULE)
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)


class STLOrientationTests(unittest.TestCase):
    def test_inverted_closed_mesh_reorients_without_changing_geometry(self):
        original = trimesh.creation.box(extents=[44.07, 44.07, 4.68])
        original.invert()
        self.assertLess(original.volume, 0)
        fixed, report = repair.repair_bytes(original.export(file_type='stl'))
        converted = trimesh.load(io.BytesIO(fixed), file_type='stl')
        self.assertTrue(converted.is_watertight)
        self.assertGreater(converted.volume, 0)
        self.assertTrue(report['orientation_repaired'])
        self.assertAlmostEqual(converted.volume, -original.volume, places=2)
        self.assertFalse(report['physical_print_verified'])

    def test_valid_mesh_remains_valid(self):
        model = trimesh.creation.icosphere(subdivisions=2)
        _, record = repair.repair_bytes(model.export(file_type='stl'))
        self.assertFalse(record['orientation_repaired'])
        self.assertGreater(record['signed_volume_after'], 0)

    def test_open_geometry_fails_closed_mesh_gate(self):
        model = trimesh.creation.box()
        model.update_faces(list(range(len(model.faces) - 1)))
        with self.assertRaises(ValueError):
            repair.repair_bytes(model.export(file_type='stl'))

    def test_archive_includes_usable_stl_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp)/'input.zip', Path(tmp)/'output.zip'
            model = trimesh.creation.box()
            model.invert()
            with ZipFile(src, 'w') as archive:
                archive.writestr('models/love.stl', model.export(file_type='stl'))
            receipt = repair.repair_archive(src, dst)
            self.assertIn('love.stl', receipt)
            with ZipFile(dst) as archive:
                self.assertIn('VERIFICATION.json', archive.namelist())
                mesh = trimesh.load(io.BytesIO(archive.read('love.stl')), file_type='stl')
                self.assertGreater(mesh.volume, 0)


if __name__ == '__main__':
    unittest.main()
