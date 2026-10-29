/**
 * xTool O1 Omni manufacturing CAPABILITY preview registry.
 *
 * Intentionally isolated from Shopify checkout/manufacturing approval.
 * Hardware-fit only; it cannot certify print output, consumable/primer
 * suitability, facility safety, a saleable SKU, or physical production.
 *
 * Evidence: xTool O1 materials/edition guide, O1 FAQ and WonderPress FAQ
 * (see docs/O1_OMNI_FULL_STACK_PRODUCT_ROADMAP_20261029.md).
 */

export const O1_EDITIONS = Object.freeze({
  SINGLE_UV: 'single-uv',
  DUAL_UV: 'dual-uv',
  UV_DT: 'uv-dt',
});

const ALL_O1 = Object.freeze(Object.values(O1_EDITIONS));
const UV_DT_ONLY = Object.freeze([O1_EDITIONS.UV_DT]);
const DUAL_UV_ONLY = Object.freeze([O1_EDITIONS.DUAL_UV]);

export const O1_MODULES = Object.freeze([
  'lm1-laminator', 'rf1-roll-feeder', 'or1-rotary', 'garment-tray',
  'wonderpress-heat-press', 'wonderpress-craft-oven', 'wonderpress-3d-form',
  'sublimation-print-source', 'fdm-printer',
]);

const route = (id, name, category, editions, modules = [], notes = '') => Object.freeze({
  id, name, category, editions: Object.freeze([...editions]),
  modules: Object.freeze([...modules]), notes,
});

export const O1_ROUTES = Object.freeze([
  route('uv-rigid', 'UV direct printed rigid goods', 'rigid-goods', ALL_O1, [], 'Substrate-specific preparation and adhesion tests required'),
  route('uv-dtf-sheet', 'UV DTF decal sheets', 'maker-transfers', ALL_O1, ['lm1-laminator'], 'Requires compatible A/B transfer films'),
  route('uv-dtf-roll', 'UV DTF roll runs', 'maker-transfers', ALL_O1, ['lm1-laminator', 'rf1-roll-feeder'], 'Requires approved roll films'),
  route('foil-decal', 'Gold / silver / holographic foil decals', 'special-effects', ALL_O1, ['lm1-laminator'], 'Requires specialty foil and transfer media'),
  route('lenticular-flip', 'Lenticular image flip', 'lenticular', ALL_O1, [], 'Needs lens sheet and per-batch LPI measurement in xTool Studio'),
  route('lenticular-animation', 'Lenticular tilt animation', 'lenticular', ALL_O1, [], '5–12 frames; interlacing is not yet validated by this registry'),
  route('lenticular-depth', 'Lenticular multi-view 3D effect', 'lenticular', ALL_O1, [], '8–20 viewpoints; optical depth, not physical embossing'),
  route('uv-raised-texture', 'Raised UV textured print', 'special-effects', ALL_O1, [], 'Up to manufacturer-specified relief limits, pending calibration'),
  route('fluorescent-uv', 'Fluorescent specialty UV print', 'special-effects', DUAL_UV_ONLY, [], 'Requires dual-UV specific fluorescent ink paths'),
  route('rotary-tumbler', 'Rotary UV tumbler / bottle', 'drinkware', ALL_O1, ['or1-rotary'], 'Use suitable coatings; avoid direct food/drink contact surfaces'),
  route('vinyl-roll', 'Vinyl or compatible continuous roll printing', 'maker-transfers', ALL_O1, ['rf1-roll-feeder'], 'Substrate/film profile is material-specific'),
  route('dtf-transfer-sheet', 'Fabric DTF transfer sheet', 'apparel', UV_DT_ONLY, ['wonderpress-craft-oven'], 'DTF film, ink, powder and curing must be qualified'),
  route('dtf-finished-apparel', 'DTF applied to finished apparel', 'apparel', UV_DT_ONLY, ['wonderpress-craft-oven', 'wonderpress-heat-press'], 'Requires textile compatibility and wash tests'),
  route('dtg-apparel', 'Direct-to-garment apparel', 'apparel', UV_DT_ONLY, ['garment-tray', 'wonderpress-heat-press'], 'Requires proper pretreatment/curing and fabric qualification'),
  route('vacuum-formed-packaging', 'Vacuum-formed product packaging', '3d-products', ALL_O1, ['wonderpress-3d-form'], 'Uses WonderPress, not O1 printing; material safety qualification required'),
  route('three-d-sublimation', '3D vacuum sublimated goods', '3d-products', ALL_O1, ['wonderpress-3d-form', 'sublimation-print-source'], 'A separate sublimation print source is required'),
  route('fdm-uv-hybrid', 'FDM printed and UV decorated objects', '3d-products', ALL_O1, ['fdm-printer'], 'Test dimensional compatibility, fixtures and ink adhesion'),
  route('digital-art-download', 'Downloadable original artwork and STL', 'digital', [], [], 'No machine required; digital licensing/delivery are separate gates'),
]);

const ROUTES_BY_ID = new Map(O1_ROUTES.map(item => [item.id, item]));

/**
 * Evaluate hardware/process plausibility from a trusted operator inventory.
 * This is NOT a production certification. Missing or malformed configuration
 * is conservatively treated as unavailable. Never use this result to turn on
 * commerce, pricing, or manufacturing on its own.
 */
export function evaluateO1Route(routeId, inventory = {}) {
  const requested = typeof routeId === 'string' ? ROUTES_BY_ID.get(routeId) : null;
  if (!requested) return {
    id: null, known: false, hardwarePossible: false, missingModules: [],
    blockers: ['UNKNOWN_ROUTE'], manufacturingApproved: false,
    checkoutEligible: false, status: 'UNVERIFIED',
  };

  const edition = inventory && typeof inventory === 'object' ? inventory.edition : null;
  const rawModules = inventory && typeof inventory === 'object' ? inventory.modules : null;
  const modulesValid = Array.isArray(rawModules) && rawModules.every(mod => typeof mod === 'string' && O1_MODULES.includes(mod));
  const providedModules = modulesValid ? new Set(rawModules) : new Set();
  const isDigital = requested.id === 'digital-art-download';
  const editionValid = ALL_O1.includes(edition);
  const editionAllowed = isDigital || (editionValid && requested.editions.includes(edition));
  const missingModules = requested.modules.filter(mod => !providedModules.has(mod));
  const blockers = [];
  if (!isDigital && !editionValid) blockers.push('O1_EDITION_UNCONFIRMED');
  else if (!editionAllowed) blockers.push('O1_EDITION_INCOMPATIBLE');
  if (!modulesValid && requested.modules.length) blockers.push('MODULE_INVENTORY_UNVERIFIED');
  if (missingModules.length) blockers.push('REQUIRED_MODULE_MISSING');
  const hardwarePossible = editionAllowed && missingModules.length === 0 && (requested.modules.length === 0 || modulesValid);
  return {
    id: requested.id, known: true, category: requested.category, name: requested.name,
    hardwarePossible, missingModules, blockers,
    manufacturingApproved: false, checkoutEligible: false,
    status: hardwarePossible ? 'HARDWARE_POSSIBLE_NOT_QUALIFIED' : 'UNVERIFIED',
    notes: requested.notes,
  };
}

export function listO1Routes(inventory = {}) {
  return O1_ROUTES.map(item => evaluateO1Route(item.id, inventory));
}
