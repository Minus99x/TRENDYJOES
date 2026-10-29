import importlib.util
import io
import unittest
import zipfile
from pathlib import Path
from PIL import Image
spec=importlib.util.spec_from_file_location('transfer',Path(__file__).parents[1]/'scripts/prepare_transfer_release.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def png(size=(30,30), mode='RGBA', transparent=True, dpi=300, blank=False):
    im=Image.new(mode,size,(0,0,0,0) if mode=='RGBA' and transparent else 'white')
    if not blank:im.paste('red',(5,5,20,20))
    out=io.BytesIO();im.save(out,format='PNG',dpi=(dpi,dpi));return out.getvalue()

class TransferTests(unittest.TestCase):
    def test_valid_bounds_and_inches(self):
        r=m.inspect_png(png(),(30,30))
        self.assertEqual(r['visible_bounds_pixels'],[5,5,20,20])
        self.assertEqual(r['canvas_inches_at_300ppi'],[.1,.1])
        self.assertEqual(r['visible_inches_at_300ppi'],[.05,.05])
    def test_wrong_dimensions(self):
        with self.assertRaises(ValueError):m.inspect_png(png(),(900,900))
    def test_rgb_rejected(self):
        with self.assertRaises(ValueError):m.inspect_png(png(mode='RGB'),(30,30))
    def test_opaque_rgba_rejected(self):
        with self.assertRaises(ValueError):m.inspect_png(png(transparent=False),(30,30))
    def test_empty_art_rejected(self):
        with self.assertRaises(ValueError):m.inspect_png(png(blank=True),(30,30))
    def test_wrong_ppi_rejected(self):
        with self.assertRaises(ValueError):m.inspect_png(png(dpi=72),(30,30))
    def test_corrupt_image_rejected(self):
        with self.assertRaises(Exception):m.inspect_png(b'not png',(30,30))
    def test_duplicate_entry_rejected(self):
        with self.assertRaises(ValueError):m.validate_names([zipfile.ZipInfo('art/a.png')]*2)
    def test_paths_rejected(self):
        for name in ['../evil','/evil','art/../../evil','C:/evil','art\\evil']:
            with self.subTest(name=name),self.assertRaises(ValueError):m.validate_names([zipfile.ZipInfo(name)])
    def test_large_entry_rejected(self):
        item=zipfile.ZipInfo('art/a.png');item.file_size=65*1024*1024
        with self.assertRaises(ValueError):m.validate_names([item])
    def test_normal_names_allowed(self):
        m.validate_names([zipfile.ZipInfo('art/dtf/M01-A.png')])
    def test_same_source_output_rejected(self):
        with self.assertRaises(ValueError):m.prepare('same.zip','same.zip')

if __name__=='__main__':unittest.main()
