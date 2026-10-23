# Objective 34L — Mobile 3D concept gesture safety (offline only)

This objective addresses a confirmed source-level mobile defect in the preview-only Design Works 3D concept editor: the 3D canvas lacked `touch-action: none`, so touch drag could compete with browser scrolling; the old handler also overwrote an active pointer on a new `pointerdown`, had no explicit capture-error fallback, and could retain stale drag state across tab blur or editor mode changes.

## Changes

- Add pure `beginConceptPointerDrag`, `moveConceptPointerDrag`, `endConceptPointerDrag` functions in `src/viewer3d.mjs`. They reject invalid identifiers, nonfinite coordinates, nonprimary pointers, second-pointer hijacking, and mismatched releases. Camera orbit deltas are clamped to the existing safe action bounds; a released mouse button cancels a ghost drag.
- Use the gesture functions from `demo/static-preview.mjs`. Capture exceptions fail closed with visible guidance to use existing keyboard/button controls. Pointer capture is released on matching end, tab blur, document hidden, product selection, reset, and 2D mode switch. No storage, authentication, upload, cart, checkout or order behavior added.
- Apply `touch-action: none` only to the 3D canvas, not the document body, to preserve scrolling outside the interactive preview.
- Regenerate local browser/static asset manifests and staging candidate; retain all existing product categories, editor functionality, GLB/calibration pathways and original theme separation.

## Verification and limitations

Focused `node --test tests/objective34l-pointer-lifecycle.test.mjs` checks valid gestures, adversarial identifiers/coordinates, pointer hijacking, stale release, clamped camera movement, capture fallback hooks, generated isolated staging assets and loopback HTTP commerce denial. Full suite: `npm test`. Asset checks: `npm run preview:assets:check`, `npm run preview:static:assets:check`, `npm run preview:staging:check`.

These are Node contract, generated-asset, and loopback HTTP tests only. No claim of native mobile browser, actual Shopify Liquid compilation, CDN loading, hosted authentication, customer storage, manufacturing approval or commerce acceptance. **No Shopify writes, deployments, customer data or secrets.** Main Engineering must review and integrate independently after the Captain authorizes any staging work.
