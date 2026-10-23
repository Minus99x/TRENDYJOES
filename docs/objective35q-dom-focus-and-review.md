# Objective 35Q — Offline multi-design review DOM focus continuity

Scope: local-only Universal Studio prototype. No Shopify API, cart, order, customer, or production authorization.

## Fixed defect

Rebuilding the saved-design list with `replaceChildren()` discarded the currently focused checkbox or Remove button. Keyboard users could lose their position during selection/removal, including while an earlier asynchronous review was invalidated. Disabling the Review or Clear button could also leave focus on the document body until a later completion.

## Implementation

- `src/preview-multidesign-dom-focus.mjs` captures the active list control's saved-reference and action, performs the list replacement, and restores focus to the matching new control. If a row was removed, it chooses another surviving control with the same action, otherwise the first enabled control, otherwise the live status paragraph.
- `demo/studio.mjs` tags only review reference and action on each checkbox/Remove button. Owner tokens are not added to DOM attributes, selectors, labels or status. No customer-controlled string is interpolated into a CSS selector.
- Review and Clear actions explicitly focus the existing `role=status`, `tabindex=-1` message after disabling their triggering control. The existing 35P generation gate still prevents stale asynchronous completion or rejection from rewriting a later UI state.

## Evidence boundaries

The focused Node tests use DOM-shaped in-memory doubles to execute the actual focus coordinator and synthetic asynchronous review promises, plus source wiring assertions. They are not native browser or mobile device tests. Native Chromium 144 probe on this runner timed out without DOM output; browser acceptance remains OPEN. A real keyboard Tab/Shift+Tab/Escape and screen-reader pass must precede any deployment.

Reproduce offline:

```sh
node --test tests/objective35q-dom-focus-and-review.test.mjs
npm test
node scripts/build-preview-asset-manifest.mjs --check
node scripts/build-static-preview-assets.mjs --check
node scripts/build-staging-static-bundle.mjs --check
node scripts/build-main-staging-reconciliation.mjs --check
```

Do not install the generated candidate in Main or staging without Main Engineering's independent reconciliation and the Captain's authorization.
