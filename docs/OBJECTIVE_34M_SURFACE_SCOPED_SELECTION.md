# Objective 34M — Surface-scoped lettering selection (offline only)

## Reproduced customer defect

The static Design Works preview supports multi-surface merchandise (for example front/back/sleeve). Before this objective, selecting text on the front and switching to the back left the invisible front text selected. Rotation, resizing, and removal controls could then edit or remove work on a different surface. The layer picker also listed text from every surface without identifying which surface it belonged to.

## Implemented fix

- `src/static-preview-contract.mjs`: switching surfaces clears the selection when the selected layer is not on the destination surface; a forged `SELECT_LAYER` request targeting a layer on a different surface fails closed with `LAYER_NOT_ON_ACTIVE_SURFACE`. Same-surface selection remains intact. All layers remain in memory and are included in privacy-preserving concept review.
- `demo/static-preview.mjs`: the layer picker shows only text on the active surface, matching the editor canvas. This applies to all concept products and both 2D and 3D modes.
- `tests/objective34m-surface-layer-guard.test.mjs`: adversarial state, cross-surface editing, multi-product, review and generated staging-bundle tests.
- Browser/static/staging asset manifests regenerated for changed modules. Staging candidate remains offline only, with checkout, customer storage, uploads, and authenticated revisions disabled.

## Acceptance and remaining gates

Run `node --test tests/objective34m-surface-layer-guard.test.mjs`, `npm test`, `npm run preview:assets:check`, `npm run preview:static:assets:check`, `npm run preview:staging:check`. No claim of real browser acceptance, Shopify Liquid compilation, storefront CDN resolution, manufacturing approval, or hosted authentication. Main Engineering must independently reconcile this candidate before any staging installation. No Shopify writes are authorized by this document.
