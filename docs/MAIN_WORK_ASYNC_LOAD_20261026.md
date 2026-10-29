# Main Engineering: transactional design loading
Date: October 26, 2026 (America/Phoenix)
Foundation package version: 0.30.172; this change is identified by its Git commit.
Baseline: 24feb7d7f2cedb793879a576330057314be70299.
Validated candidate: d7ad9ed057eda32d4736d0bf3a24f4653516c20d.
CI: https://github.com/Minus99x/TRENDYJOES/actions/runs/40287185056

## Delivered behavior
- A pending upload, JSON import, device-draft load, or tab recovery owns one operation token. New requests supersede older ones.
- Editing, product/surface changes, undo/redo, starting a fresh design, cancellation, and page exit invalidate pending results.
- Stale completions and errors cannot overwrite customer work, attach artwork to another surface, or clear a newer operation's busy state.
- Cancel pending load preserves the current design. Inputs expose aria-busy.
- Review, save, JSON/PNG export, and brief export wait until pending data has completed or been cancelled.
- Canvas pointer selection focuses without scrolling, preserving drag coordinates.

## Exact production and test changes
- website-preview/app.js
- website-preview/index.html
- website-preview/verify_20261024_advance.py
- This handoff: docs/MAIN_WORK_ASYNC_LOAD_20261026.md

## Verification
GitHub Chromium 141 / Playwright 1.56:
- Previous source fails the new assertion: Late upload cannot attach itself to a different surface.
- Patched verify_preview.py: PASS (desktop/mobile, draft recovery, navigation, exports).
- Patched verify_20261024_advance.py: 57 checks PASS, no uncaught page errors.
- 166 bounded security/manufacturing regression tests pass, zero fail.
- 40 offline assets and 13 static assets match integrity manifests.
Local Node syntax and Python compilation checks pass.
The isolated branch retains CI diagnostics, including a corrected shallow-checkout issue and viewport-coordinate evidence. The old drag test started outside the visible viewport; it now scrolls the canvas into view before using physical mouse coordinates, preserving original position/undo/redo assertions. No tests were removed.

## Continuity and limitations
The isolated validation workflow is not part of this integration. Existing scheduler and worker files are unchanged.
No Shopify theme, catalog, checkout, orders or production settings were modified. This is development-preview code, not staging deployment or hosted/manufacturing acceptance.
External Shopify CDN images are blocked by the browser fixtures; these runs do not verify those hosted images.
The next integration objective is mapping the development preview's local concept state to the existing product/surface and artwork persistence contracts, with product-specific geometry and hosted storage still requiring verification.
Before further edits, re-read development HEAD because GitHub automation can advance it.

## Implementation reference
Stale-result suppression follows the established asynchronous cleanup pattern documented at https://react.dev/reference/react/useEffect#fetching-data-with-effects. The implementation is independent plain JavaScript: no React dependency or copied upstream source.
