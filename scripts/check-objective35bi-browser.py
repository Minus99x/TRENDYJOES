"""Offline Chromium DOM check for GLB import and redacted evidence download.
The about:blank test harness lacks secure-origin WebCrypto, so only the
browser control/download path uses an explicit digest stub. Real digest
accuracy is tested in Node, never represented as browser crypto evidence.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright
from urllib.parse import urljoin
import json,re,struct,sys
root=Path(__file__).resolve().parent.parent
results=[]
def check(name,ok):
 results.append({'name':name,'pass':bool(ok)})
 if not ok:print('FAIL',name)
def make_glb():
 xyz=[-.5,0,0,.5,0,0,0,1,0];uv=[0,0,1,0,0,1];idx=[0,1,2]
 bin_data=struct.pack('<9f6f3H',*(xyz+uv+idx))+b'\x00\x00'
 doc={'asset':{'version':'2.0'},'buffers':[{'byteLength':len(bin_data)}],
  'bufferViews':[{'buffer':0,'byteOffset':0,'byteLength':36},{'buffer':0,'byteOffset':36,'byteLength':24},{'buffer':0,'byteOffset':60,'byteLength':6}],
  'accessors':[{'bufferView':0,'componentType':5126,'count':3,'type':'VEC3'},{'bufferView':1,'componentType':5126,'count':3,'type':'VEC2'},{'bufferView':2,'componentType':5123,'count':3,'type':'SCALAR'}],
  'meshes':[{'primitives':[{'attributes':{'POSITION':0,'TEXCOORD_0':1},'indices':2}]}],
  'nodes':[{'mesh':0,'extras':{'tjSurfaceId':'front'}}], 'scenes':[{'nodes':[0]}],'scene':0}
 data=json.dumps(doc,separators=(',',':')).encode();data+=b' ' *((-len(data))%4)
 body=struct.pack('<II',len(data),0x4e4f534a)+data+struct.pack('<II',len(bin_data),0x004e4942)+bin_data
 return struct.pack('<III',0x46546c67,2,12+len(body))+body
def setup(page):
 manifest=json.loads((root/'integrations/shopify/preview-asset-manifest.json').read_text())
 mods={}
 for path in [a['path'] for a in manifest['assets'] if a['path'].endswith('.mjs')]:
  src=(root/path).read_text()
  def rewrite(m):
   quote,spec=m.group(1),m.group(2)
   if not spec.startswith('.'):return m.group(0)
   return m.group(0).replace(quote+spec+quote,quote+urljoin('https://offline.invalid/'+path,spec)+quote)
  src=re.sub(r'''\bfrom\s+(['"])([^'"\n]+)\1''',rewrite,src)
  src=re.sub(r'''\bimport\s+(['"])([^'"\n]+)\1''',rewrite,src)
  mods['https://offline.invalid/'+path]=src
 html=(root/'demo/index.html').read_text()
 html=re.sub(r'<meta\s+http-equiv="Content-Security-Policy"[^>]*>', '', html)
 html=re.sub(r'<script\s+type="module"[^>]*></script>','',html)
 html=re.sub(r'<link rel="stylesheet" href="([^"]+)">',lambda m:'<style>'+(root/'demo'/m.group(1)).read_text()+'</style>',html)
 page.set_content(html,wait_until='domcontentloaded')
 page.evaluate('''([mods])=>{
  Object.defineProperty(crypto,'subtle',{configurable:true,value:{digest:async()=>new Uint8Array(32).buffer}});
  const imports={imports:{}};
  for(const [name,source] of Object.entries(mods))imports.imports[name]=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));
  const map=document.createElement('script');map.type='importmap';map.textContent=JSON.stringify(imports);document.head.append(map);
  const module=document.createElement('script');module.type='module';module.textContent='import "https://offline.invalid/demo/studio.mjs";';document.head.append(module);
 }''',[mods]);page.wait_for_timeout(550)
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-background-networking'])
 page=browser.new_page(accept_downloads=True,viewport={'width':1280,'height':850})
 errs=[];requests=[]
 page.on('pageerror',lambda e:errs.append(str(e)))
 page.on('request',lambda r:requests.append(r.url) if r.url.startswith('http') else None)
 page.on('dialog',lambda d:d.accept())
 setup(page)
 check('35BA_EDITOR_READY',page.locator('#product option').count()>=8)
 check('35BI_UV_STATUS_NO_MODEL','No verified UV concept report' in page.locator('#uv-diagnostic-live').inner_text())
 page.locator('#mode-2d').click()
 page.locator('#text-entry').fill('PRIVATE USER WORDS 42')
 page.locator('#add-text').click()
 page.locator('#model-file').set_input_files({'name':'synthetic.glb','mimeType':'model/gltf-binary','buffer':make_glb()})
 page.wait_for_function('document.getElementById("model-import-summary").textContent.includes("IMPORTED / UNVERIFIED")',timeout=9000)
 summary=page.locator('#model-import-summary').inner_text()
 check('35BA_GLB_PARSED','1 triangles' in summary)
 check('35BA_LOCAL_ONLY','UNVERIFIED' in summary)
 check('35BA_FOOTPRINT_NOT_APPROVAL','NOT production approval' in summary)
 check('35BA_CLEAR_ENABLED',page.locator('#clear-model').is_enabled())
 check('35BI_UV_STATUS_LIVE','Unverified UV concept' in page.locator('#uv-diagnostic-live').inner_text())
 check('35BI_UV_STATUS_NOT_APPROVAL','NOT production approval' in page.locator('#uv-diagnostic-live').inner_text())
 with page.expect_download(timeout=10000) as dl:
  page.locator('#download-concept-evidence').click()
 download=dl.value
 check('35BA_REDACTED_FILENAME',download.suggested_filename=='trendyjoes-private-concept-evidence.json')
 path=root/'demo'/'objective35ba-browser-output.json';download.save_as(path)
 raw=path.read_text();path.unlink()
 data=json.loads(raw);inspection=data['evidence']['modelInspection']
 check('35BA_MODEL_SUMMARY_INCLUDED',inspection['triangleCount']==1 and inspection['mappedSurfaces']==['front'])
 check('35BA_MODEL_STATUS_UNVERIFIED',inspection['status']=='IMPORTED_UNVERIFIED' and inspection['manufacturingApproved'] is False)
 check('35BA_NO_PRIVATE_USER_TEXT','PRIVATE USER WORDS 42' not in raw)
 check('35BA_NO_RAW_TRIANGLES','"triangles"' not in raw and '"uv"' not in raw and '"assetBoundsMeters"' not in raw)
 check('35BA_CHECKOUT_DISABLED',data['checkoutEnabled'] is False and page.locator('.disabled-checkout').is_disabled())
 check('35BA_DOWNLOAD_ANNOUNCED','downloaded' in page.locator('#concept-evidence-status').inner_text())
 check('35BA_NO_PAGE_ERRORS',not errs)
 check('35BA_NO_HTTP_REQUESTS',not requests)
 check('35BA_DIGEST_NOT_BROWSER_VERIFIED',inspection['sha256']=='0'*64)
 with page.expect_download(timeout=10000) as review_dl:
  page.locator('#download-concept-review').click()
 review=review_dl.value
 check('35BI_REVIEW_DOWNLOAD_FILENAME',review.suggested_filename=='trendyjoes-private-concept-review.json')
 review_path=root/'demo'/'objective35bi-browser-output.json';review.save_as(review_path)
 review_raw=review_path.read_text();review_path.unlink()
 payload=json.loads(review_raw)
 check('35BI_REVIEW_SCOPE',payload['schema']=='TJ-CONCEPT-REVIEW-PACKET-35BG-1')
 check('35BI_REVIEW_BLOCKED',payload['manufacturingApproved'] is False and payload['checkoutEnabled'] is False)
 check('35BI_REVIEW_PRIVATE_REDACTED','PRIVATE USER WORDS 42' not in review_raw and '"triangles"' not in review_raw)
 check('35BI_MODEL_PRESERVED',payload['modelSha256']==inspection['sha256'])
 check('35BI_MISSING_MEASUREMENTS_DISCLOSED','NO_MEASUREMENT_WORKSHEET' in payload['issues'])
 check('35BI_REVIEW_STATUS_ANNOUNCED','Redacted review downloaded' in page.locator('#concept-review-status').inner_text())
 check('35BI_ALL_ERRORS_CLEAN',not errs)
 check('35BI_ALL_HTTP_CLEAN',not requests)

 summary={'pass':sum(x['pass'] for x in results),'fail':sum(not x['pass'] for x in results),'pageErrors':errs,'externalRequests':requests,'mode':'offline Chromium DOM with explicit stub digest; real SHA separately in Node','checks':results}
 print(json.dumps(summary,indent=2));browser.close()
 assert summary['fail']==0
