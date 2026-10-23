import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {hasCustomerWork,eligibleSnapshotEntries,mayApplyDelayedEntry} from '../src/preview-catalog-merge.mjs';
const draft=id=>({title:'Local draft',issues:[],manifest:{id,surfaces:[{id:'front'}]}});
const known=Object.assign(Object.create(null),{'concept-crew-tee':{id:'concept-crew-tee'}});
const deferred={initialEntryStatus:'UNKNOWN_PRODUCT',resolvedEntry:{status:'SELECTED',manifestId:'draft-mug'},userInteracted:false,currentProductId:'concept-crew-tee',initialProductId:'concept-crew-tee',currentSnapshot:'same',initialSnapshot:'same',hasWork:false};
test('34C pristine delayed draft selection is allowed once',()=>assert.equal(mayApplyDelayedEntry(deferred),true));
test('34C a user pointer or keyboard interaction blocks delayed replacement',()=>assert.equal(mayApplyDelayedEntry({...deferred,userInteracted:true}),false));
test('34C editing layers blocks delayed replacement',()=>assert.equal(mayApplyDelayedEntry({...deferred,hasWork:true}),false));
test('34C snapshot divergence blocks delayed replacement',()=>assert.equal(mayApplyDelayedEntry({...deferred,currentSnapshot:'changed'}),false));
test('34C manual product selection blocks delayed replacement',()=>assert.equal(mayApplyDelayedEntry({...deferred,currentProductId:'concept-rug'}),false));
test('34C invalid, missing and already-selected URLs never navigate on snapshot arrival',()=>{
 for(const initialEntryStatus of ['INVALID_LINK','DEFAULT','SELECTED'])assert.equal(mayApplyDelayedEntry({...deferred,initialEntryStatus}),false);
 assert.equal(mayApplyDelayedEntry({...deferred,resolvedEntry:{status:'UNKNOWN_PRODUCT'}}),false);
});
test('34C product selection and imported model count as customer work',()=>{
 assert.equal(hasCustomerWork({layers:[{id:'a'}]}),true);
 assert.equal(hasCustomerWork({imported:{asset:'glb'}}),true);
 assert.equal(hasCustomerWork({calibration:{width:12}}),true);
 assert.equal(hasCustomerWork({saved:{reference:'x'}}),true);
 assert.equal(hasCustomerWork({savedSnapshot:'digest'}),true);
});
test('34C concept color and size changes count as customer work',()=>{
 const defaults={colorId:'slate',sizeId:'m'};
 assert.equal(hasCustomerWork({previewSelection:{colorId:'oxblood',sizeId:'m'},defaultSelection:defaults}),true);
 assert.equal(hasCustomerWork({previewSelection:{colorId:'slate',sizeId:'l'},defaultSelection:defaults}),true);
 assert.equal(hasCustomerWork({previewSelection:defaults,defaultSelection:defaults}),false);
});
test('34C eligible local snapshot entries are accepted without modifying original manifests',()=>{
 const entries=[draft('draft-mug'),draft('draft-shirt')];
 assert.deepEqual(eligibleSnapshotEntries(entries,known).map(e=>e.manifest.id),['draft-mug','draft-shirt']);
 assert.deepEqual(Object.keys(known),['concept-crew-tee']);
});
test('34C catalog rejects concept ID collisions and duplicate draft entries',()=>{
 const entries=[draft('concept-crew-tee'),draft('draft-mug'),draft('draft-mug')];
 assert.deepEqual(eligibleSnapshotEntries(entries,known).map(e=>e.manifest.id),['draft-mug']);
});
test('34C catalog rejects prototype pollution, invalid IDs, and flagged records',()=>{
 const entries=[draft('__proto__'),draft('constructor'),draft('bad%id'),{...draft('flagged'),issues:['unapproved']},draft('draft-mug')];
 assert.deepEqual(eligibleSnapshotEntries(entries,known).map(e=>e.manifest.id),['draft-mug']);
});
test('34C catalog rejects malformed snapshots without throwing',()=>{
 assert.deepEqual(eligibleSnapshotEntries(null,known),[]);
 assert.deepEqual(eligibleSnapshotEntries([null,{}, {manifest:{id:'draft-mug'}}, {...draft('draft-mug'),title:123}],known),[]);
 assert.deepEqual(eligibleSnapshotEntries(Array.from({length:251},()=>draft('draft-mug')),known),[]);
});
test('34C editor uses guarded delayed selection, explicit switch confirmation and URL cleanup',()=>{
 const editor=readFileSync(new URL('../demo/studio.mjs',import.meta.url),'utf8');
 assert.match(editor,/mayApplyDelayedEntry\(/);
 assert.match(editor,/eligibleSnapshotEntries\(body.entries,availableManifests\)/);
 assert.match(editor,/window\.confirm\(/);
 assert.match(editor,/URL\.revokeObjectURL\(url\)/);
 assert.doesNotMatch(editor,/\n  applyPreviewEntry\(\);\s*\n \}catch/);
});
