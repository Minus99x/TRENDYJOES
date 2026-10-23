# Objective 35AO — Accessible 2D concept-layer positioning

**Offline engineering only.** No Shopify writes, hosted acceptance, product approvals, checkout, or customer data.

The existing local-first editor allowed mouse dragging but had no precise keyboard equivalent for positioning text or private artwork. The local editor now exposes four labelled, keyboard-focusable movement buttons and a focusable 2D preview surface. Arrow keys move the selected layer by 1% of its normalized design zone; Shift+arrow moves by 5%. Browser-owned Ctrl/Alt/Meta shortcuts are never intercepted. Live status announces moves and refused zone exits.

`src/preview-keyboard-position.mjs` is a pure, immutable positioning reducer. Every movement validates the full existing composition, including rotated bounds; invalid actions, a different selected surface, or boundary collisions preserve the original layer array and all private artwork IDs. This is a **concept-only** normalized coordinate system; it does not calibrate any real blank or approve a manufacturing print zone. Selection, revision invalidation and disabled checkout continue through the existing editor.

The new styling is isolated in `demo/studio-editor-nudge.css` so the 13-asset static staging candidate and protected Main/Night divergence remain untouched. `integrations/shopify/preview-asset-manifest.json` tracks the additional offline browser source. A package-version-only offline staging bundle manifest refresh may be made, but no protected staged JS/CSS/Liquid asset is merged or replaced.

Verification: 12 new Node tests, 79 focused cross-component Node tests, 16 native Chromium UI assertions executed through an in-memory module import map (no external HTTP requests). The full corpus was attempted but exceeded the execution window after 2,860 reported passes; it is **not** claimed complete. Real hosted storefront and mobile acceptance remain untested.

Remaining gates: manual resolution of the four Main57A 13-asset staging differences, read-only live source acquisition with verified bytes, GLB calibration, physical print zone approval, and authenticated design/cart/order provenance.
