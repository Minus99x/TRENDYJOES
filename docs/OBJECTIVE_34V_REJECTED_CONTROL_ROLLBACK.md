# Objective 34V — fail-closed control rollback (offline-only)

## Reproduced defect

The static concept editor rejected forged or stale color, size, and lettering-layer IDs at its model boundary but left the DOM select value on the rejected choice. This could show an impossible selection while 2D/3D output continued using the last committed state. A forged front-layer ID could also remain visibly selected on the back surface after the model rejected it. This is a client-side model/view integrity issue, **not** a bypass of server authorization.

## Implementation

`demo/static-preview.mjs` now restores the rejected select's value from the last committed state after a failed `SELECT_COLOR`, `SELECT_SIZE`, or `SELECT_LAYER` action. Successful actions continue through the existing `updateStaticPreview` contract and render path. Rejected actions do not erase the private unadded wording or mutate design state; generic feedback never echoes customer content. No storage, network, checkout or Shopify operations were added.

## Adversarial acceptance

`node --test tests/objective34v-control-rollback.test.mjs` exercises the real DOM handlers using an isolated offline fake browser: forged color IDs for all seven product concepts; forged size; rollback to a nondefault color; nonexistent and cross-surface layer IDs; valid recovery after a rejection; private composer retention and redacted error; no commerce/persistence calls.

The staged Liquid candidate remains **not installed**. Native browser/mobile/assistive-tech, hosted authentication and storage, approved manufacturing geometry/GLBs, authoritative prices, Shopify Liquid/CDN/CSP, cart, checkout and order acceptance remain outside this objective.
