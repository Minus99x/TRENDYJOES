# Objective 5 — Shopify staging integration bridge (v0.5)

**Status:** Completed local engineering objective. **NOT deployed to Shopify.** The six mapped production templates remain `DRAFT`, cost profiles and production approval remain unresolved, and checkout is disabled. The published Horizon theme and unpublished staging theme have not been modified by this package.

## Evidence baseline

Read-only connected Admin catalog check: 2026-10-14 on `gucgmp-bc.myshopify.com` (trial plan). Six manufacturing draft templates map to six real Shopify product GIDs and six variant GIDs. The other eight digital products are deliberately left outside the manufacturing registry; unsupported products can be brought into the same architecture with explicitly reviewed profiles. The included `fixtures/shopify-draft-manufacturing-2026-10-14.json` is a **point-in-time development snapshot**: never treat it as a current cart authorization, price, stock, shipping or approval fact.

## Implemented

1. `src/shopify-bridge.mjs`: normalizes Admin product/variant identities, checks complete variant snapshots, maps reviewed process profiles to universal product manifests, and prevents accidental family inference from generic product titles. All dimensions and UV regions default to unverified. Five manufacturing templates become conceptual customizable manifests. The sixth (`Ready-to-Ship 3D Printed Decor`) remains a catalog-only product, not a fake editable surface.
2. Product configurations remain extensible: reviewed `profiles` can describe future apparel, mugs, drinkware, bags, signage, blankets, specialty merchandise and any new manufacturing process permitted by the universal engine. The six fixture handles are examples, not a global limit. Configurable GLB `storageKey`, SHA-256, and surface binding references require strict validation and remain `UNVERIFIED` until model inspection and calibration approval.
3. `src/local-store.mjs`: accepts additional manifests alongside all seven original concept families; adds checksum-and-structure integrity revalidation for stored artwork at design-to-product binding time. Existing private recovery, conflict control and immutable revisions remain intact.
4. `src/shopify-intents.mjs`: authenticates the private design owner token, checks exact design revision and product manifest identity, validates the chosen Shopify variant and composition, and issues an **opaque, non-purchasable staging binding receipt** without owner tokens or artwork bytes.
5. `src/local-server.mjs`: `GET /api/shopify/staging-products` exposes only a local snapshot and safe manifests; `POST /api/shopify/preview-binding` requires the local owner bearer token. Neither endpoint sends Admin API requests or modifies carts or orders.
6. `demo/studio.mjs`: optional read-only Shopify draft entries augment the editor's existing product list; a saved design can be checked against a specific draft Shopify variant. Original 2D/3D concept editor, GLB inspection, physical measurement worksheet, and private draft recovery remain available. Any unsupported physical geometry is rendered as a **2D concept**, not a fictitious product-accurate 3D model.
7. `signOrderMetadata` / `verifyOrderMetadata`: **future server-side contract primitives** for HMAC-SHA256 over private line item properties. Staging preview bindings cannot be signed into an authorized checkout object. Signed properties alone are not a payment, price, shipping, customer-authentication, or fulfillment authorization.

## Demo and local API (developer-only)

Node.js >= 20, no dependency installation required:

```powershell
npm test
$env:TJ_STAGING_FIXTURE = 'fixtures/shopify-draft-manufacturing-2026-10-14.json'
npm run serve
```

Open `http://127.0.0.1:8000/demo/` on the **same computer**. Five extra `SHOPIFY DRAFT` design options should be appended under the existing concept families. Save a draft, then use *Check saved design binding* with the pre-filled draft variant. The local staging receipt must show `checkoutEnabled:false`, `cartLine:null`. To run the original seven demo manifests only, omit the `TJ_STAGING_FIXTURE` environment variable. The fixture is inert JSON; no live Shopify access occurs from the local demo.

The local API accepts a configurable `shopifySnapshot` as an array of authenticated Admin product nodes **supplied by the calling developer**, not by untrusted shoppers. Never expose this loopback-only development server to the internet; it uses capability-based local tokens, not a production Shopify customer-auth model.

### Private binding request (developer example)

`POST /api/shopify/preview-binding` with JSON `reference`, `expectedRevision`, `productGid` and `variantGid`, plus the local `Authorization: Bearer <private design owner token>` header. Successful response includes exact identities, revision, composition digest, and blockers, without any owner token. An expired/stale revision (409), wrong/missing owner token (403), wrong product (409), unavailable variant (400), missing/corrupted artwork (409), unsupported manufacturing routes or print bounds fail closed. Never send this bearer token in a Shopify cart property or a storefront analytics event.

### Order and cart metadata boundary

Future validated Shopify Ajax cart format uses `id` = numeric variant ID and a `properties` map, with private keys such as `_TJ Design Reference`, `_TJ Design Revision`, `_TJ Product GID`, `_TJ Variant GID`, `_TJ Composition SHA256`, `_TJ Binding HMAC`. Shopify private properties **remain accessible in cart APIs and Liquid**; theme code must explicitly hide them from visible cart output. None of those properties control variant price. A production Shopify backend must re-fetch the product/variant, verify allowed processes, artwork ownership, persistent design revision, physical measurements, manufacturing eligibility, the authoritative price, and the order's actual line item before creating a production job. The future HMAC mechanism requires server-secret storage, expiry/replay controls, checkout/order reconciliation and independent security testing. The present development server issues **no authorized checkout binding**.

Shopify platform reference: https://shopify.dev/docs/api/ajax/reference/cart

## Verified failures and hold points

Tests cover exact live snapshot GIDs, mismatched variant, SKU/type collision, duplicate GIDs, missing/partial variant lists, invalid price, wrong print zone, out-of-bounds rotation, unsupported process, wrong owner, stale revision, altered artwork bytes, unauthenticated access, and forged HMAC metadata. The existing v0.4 tests still pass. Direct Chromium browser visual testing could not complete in the execution environment; this is **not** evidence of a passed desktop/mobile QA run. There is no customer account authentication, hosted secure artwork backend, supplier-calibrated GLB, cost-approved pricing, installed live Shopify app, cart interaction, checkout, payment, order, or fulfillment evidence.

## Next controlled objectives

- **Objective 6 (engineering):** read-only authenticated Shopify app backend design and owned asset storage/security, current-catalog refresh with complete variant pagination, product-specific physical GLB acceptance, measured surface calibration, and cross-device browser QA.
- **Staging deployment gate (Captain-authorized):** explicit unpublished-theme-only change control, asset/theme backup and rollback, reviewed production pricing and machine acceptance, customer-flow testing and security validation. Do not change live theme, draft status, app purchases or plan without approval.
