import test from 'node:test';
import assert from 'node:assert/strict';
import {O1_EDITIONS, O1_ROUTES, O1_MODULES, evaluateO1Route, listO1Routes} from '../src/o1-omni-capabilities.mjs';
const uvdt = {edition: O1_EDITIONS.UV_DT, modules: [...O1_MODULES]};
const dual = {edition: O1_EDITIONS.DUAL_UV, modules: [...O1_MODULES]};
const single = {edition: O1_EDITIONS.SINGLE_UV, modules: []};

test('there are no duplicate capabilities and no preapproved commerce routes', () => {
  assert.equal(new Set(O1_ROUTES.map(r => r.id)).size, O1_ROUTES.length);
  for (const route of listO1Routes(uvdt)) {
    assert.equal(route.checkoutEligible, false);
    assert.equal(route.manufacturingApproved, false);
  }
});

test('UV+DT enables textile processes but never fluorescent UV', () => {
  assert.equal(evaluateO1Route('dtf-transfer-sheet', uvdt).hardwarePossible, true);
  assert.equal(evaluateO1Route('dtg-apparel', uvdt).hardwarePossible, true);
  assert.equal(evaluateO1Route('fluorescent-uv', uvdt).hardwarePossible, false);
  assert.deepEqual(evaluateO1Route('fluorescent-uv', uvdt).blockers, ['O1_EDITION_INCOMPATIBLE']);
});

test('dual UV supports fluorescence but not DTF or DTG', () => {
  assert.equal(evaluateO1Route('fluorescent-uv', dual).hardwarePossible, true);
  assert.equal(evaluateO1Route('dtf-transfer-sheet', dual).hardwarePossible, false);
  assert.equal(evaluateO1Route('dtg-apparel', dual).hardwarePossible, false);
});

test('missing accessories prevent hardware possible assertion', () => {
  const tumbler = evaluateO1Route('rotary-tumbler', single);
  assert.equal(tumbler.hardwarePossible, false);
  assert.deepEqual(tumbler.missingModules, ['or1-rotary']);
  assert.ok(tumbler.blockers.includes('REQUIRED_MODULE_MISSING'));
  assert.equal(evaluateO1Route('uv-rigid', single).hardwarePossible, true);
});

test('the full UV DTF roll route requires BOTH laminator and feeder', () => {
  const partial = evaluateO1Route('uv-dtf-roll', {edition: O1_EDITIONS.SINGLE_UV, modules: ['lm1-laminator']});
  assert.deepEqual(partial.missingModules, ['rf1-roll-feeder']);
  assert.equal(partial.hardwarePossible, false);
  assert.equal(evaluateO1Route('uv-dtf-roll', uvdt).hardwarePossible, true);
});

test('printing a DTF transfer is separate from finishing garments', () => {
  const inventory = {edition: O1_EDITIONS.UV_DT, modules: ['wonderpress-craft-oven']};
  assert.equal(evaluateO1Route('dtf-transfer-sheet', inventory).hardwarePossible, true);
  assert.equal(evaluateO1Route('dtf-finished-apparel', inventory).hardwarePossible, false);
  assert.deepEqual(evaluateO1Route('dtf-finished-apparel', inventory).missingModules, ['wonderpress-heat-press']);
});

test('3D sublimation needs an independent sublimation source', () => {
  const partial = evaluateO1Route('three-d-sublimation', {edition: O1_EDITIONS.UV_DT, modules: ['wonderpress-3d-form']});
  assert.equal(partial.hardwarePossible, false);
  assert.deepEqual(partial.missingModules, ['sublimation-print-source']);
});

test('unknown, missing, invalid or misleading inventories fail closed', () => {
  assert.equal(evaluateO1Route('uv-rigid').hardwarePossible, false);
  assert.equal(evaluateO1Route('uv-rigid', {edition: 'all-models'}).hardwarePossible, false);
  assert.equal(evaluateO1Route('rotary-tumbler', {edition: O1_EDITIONS.UV_DT, modules: 'or1-rotary'}).hardwarePossible, false);
  assert.equal(evaluateO1Route('rotary-tumbler', {edition: O1_EDITIONS.UV_DT, modules: ['or1-rotary', 'made-up-device']}).hardwarePossible, false);
  assert.equal(evaluateO1Route('__proto__', uvdt).known, false);
  assert.equal(evaluateO1Route(null, uvdt).known, false);
});

test('digital delivery does not depend on printer inventory but remains unapproved', () => {
  const digital = evaluateO1Route('digital-art-download');
  assert.equal(digital.hardwarePossible, true);
  assert.equal(digital.manufacturingApproved, false);
  assert.equal(digital.checkoutEligible, false);
});

test('no inventory input can directly unlock checkout or manufacturing', () => {
  const inventory = {edition: O1_EDITIONS.UV_DT, modules: [...O1_MODULES], checkoutEligible: true, manufacturingApproved: true};
  for (const result of listO1Routes(inventory)) {
    assert.equal(result.checkoutEligible, false);
    assert.equal(result.manufacturingApproved, false);
  }
});
