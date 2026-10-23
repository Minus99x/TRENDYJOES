#!/usr/bin/env python3
"""Read-only, fail-closed Main57A / latest Night candidate comparison.

Requires an independently preserved Main57A archive; no remote source is inferred.
Prints exact source digests. A hosted-source directory may be supplied; all 13
files must then be present and independently captured before classifying any
three-way state. Never copies, replaces, installs or approves Shopify files.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
STATIC=ROOT/'integrations/shopify/staging-static-preview'
RECON=ROOT/'integrations/shopify/main-staging-reconciliation-candidate'
REQUIRED=[
 'assets/tj34i-demo-static-preview.css',
 'assets/tj34i-demo-static-preview.js',
 'assets/tj34i-demo-studio.css',
 'assets/tj34i-src-catalog.js',
 'assets/tj34i-src-core.js',
 'assets/tj34i-src-geometry3d.js',
 'assets/tj34i-src-preview-design-summary.js',
 'assets/tj34i-src-preview-editor-state.js',
 'assets/tj34i-src-preview-entry.js',
 'assets/tj34i-src-preview-product-options.js',
 'assets/tj34i-src-static-preview-contract.js',
 'assets/tj34i-src-viewer3d.js',
 'sections/tj-static-preview-34i.liquid',
]
MAIN_PREFIX='trendyjoes-main-objective57/snapshot/'
def digest(data): return hashlib.sha256(data).hexdigest()
def read_exact(base,name):
 p=base/name
 if not p.is_file() or p.is_symlink():raise ValueError('MISSING_OR_UNSAFE_SOURCE:'+name)
 return p.read_bytes()
def reconcile(main_zip,stage=None,static=STATIC,reconciled=RECON,expected_main=None):
 main_zip=Path(main_zip)
 raw=main_zip.read_bytes()
 actual=digest(raw)
 if expected_main is not None and actual!=expected_main:raise ValueError('MAIN_ARCHIVE_HASH_MISMATCH')
 with zipfile.ZipFile(main_zip) as z:
  if z.testzip():raise ValueError('MAIN_ARCHIVE_CRC_ERROR')
  source={name:z.read(MAIN_PREFIX+name) for name in REQUIRED}
 stage=Path(stage) if stage else None
 # A partial source export is never compared as if it represented current hosted state.
 if stage is not None:
  for name in REQUIRED:read_exact(stage,name)
 rows=[]
 for name in REQUIRED:
  m=digest(source[name]); n=digest(read_exact(static,name)); candidate=digest(read_exact(reconciled,name))
  hosted=digest(read_exact(stage,name)) if stage else None
  if n==m and candidate==m: decision='OFFLINE_MATCH'
  elif n==candidate:decision='NIGHT_CHANGE_PENDING_MANUAL_REVIEW'
  else:decision='OFFLINE_BRANCH_CONFLICT_MANUAL_REVIEW'
  if hosted is not None:
   if hosted!=m or n!=m or candidate!=m:decision='THREE_WAY_MANUAL_REVIEW'
   else:decision='THREE_WAY_IDENTICAL_NO_WRITE_REQUIRED'
  rows.append({'path':name,'mainSha256':m,'nightStaticSha256':n,'nightReconciliationSha256':candidate,
   'hostedSha256':hosted,'decision':decision,'writeAuthorized':False})
 return {'schema':'TJ-UNIFIED-READONLY-1','source':'offline','mainArchiveSha256':actual,
  'sourceCompleteHostedCapture':stage is not None,'nightArchiveSha256':None,
  'staticDifferences':sum(r['mainSha256']!=r['nightStaticSha256'] for r in rows),
  'reconciliationDifferences':sum(r['mainSha256']!=r['nightReconciliationSha256'] for r in rows),
  'rows':rows,'allWritesBlocked':True,'productionApproved':False}

def main():
 a=argparse.ArgumentParser(description=__doc__)
 a.add_argument('--main-archive',required=True)
 a.add_argument('--main-sha256',help='Required pinned SHA256 of authoritative Main57A archive',required=True)
 a.add_argument('--hosted-capture',help='Already independently captured read-only 13-file directory')
 a.add_argument('--output',help='Save JSON report; otherwise stdout')
 opt=a.parse_args()
 try:r=reconcile(opt.main_archive,opt.hosted_capture,expected_main=opt.main_sha256)
 except (OSError,ValueError,KeyError,zipfile.BadZipFile) as e:
  print(f'BLOCKED / NO RELEASE ADVANCEMENT: {e}',file=sys.stderr);return 2
 out=json.dumps(r,indent=2,sort_keys=True)+'\n'
 if opt.output:Path(opt.output).write_text(out)
 else:print(out,end='')
 # Review gates are mandatory when any source differs or hosted capture missing.
 return 3 if (r['staticDifferences'] or r['reconciliationDifferences'] or not r['sourceCompleteHostedCapture']) else 0
if __name__=='__main__':sys.exit(main())
