# Objective 7 — complete read-only catalog captures and trusted identity seam (v0.7)

**Status:** Offline implementation and regression tests only. No Shopify reads or writes were performed during this objective. The existing Shopify fixture is a dated, read-only snapshot of six draft manufacturing templates, **not** an authenticated catalog or an entire store inventory. No customer authentication service, production API, checkout or order processing was deployed.

## Delivered code

- `src/catalog-refresh.mjs` — assemble an explicit, bounded, page-by-page offline capture of a Shopify Admin GraphQL product query. Both product and nested variant connections require cursor continuity (`requestAfter`, `endCursor`, `hasNextPage`), termination, unique cursors and unique GIDs. Every product must carry `variantsCount.count`; partial, omitted or repeated variant pages reject. A caller-supplied expected count applies to the **exact filtered query scope**, never automatically to the entire store. Cross-product variant reuse, malformed products, bad prices, stale/future captures, wrong shop and unrecognized scope reject. Captures are deeply frozen and receive a SHA-256 digest for change detection, **not** provenance authentication.
- `validateCatalogTransition` — a pure anti-rollback and same-timestamp equivocation contract for a future durable catalog store. It does not provide distributed locking or persistent compare-and-swap. A future backend must persist the last accepted revision and atomically compare-and-swap before replacing it.
- `src/customer-identity-contract.mjs` — a server-only adapter for a separately cryptographically verified customer or guest token. It refuses operation without an injected verifier, checks issuer, audience, exact shop, subject type, session identity, issuance/not-before/expiry and maximum lifespan. It returns only a minimal frozen principal; no raw token or owner capability is included. A caller-provided `verified` flag is not recognized. The verifier must independently validate the token signature, key source, token type and revocation; none is implemented here.
- `src/local-server.mjs` — optional `catalogCaptureOptions` validates a fully paginated offline capture before creating the local registry. The loopback-only `GET /api/shopify/catalog-evidence` returns the capture digest and explicit `sourceAuthenticated:false`, `checkoutEnabled:false`, `productionReady:false`. Existing fixture mode and all prior local preview endpoints remain intact. No checkout route was added.
- `tests/objective7-catalog-identity.test.mjs` — adversarial offline tests for product/variant cursor gaps, duplicates, count mismatches, tenant substitution, expiration, rollback, malformed data, HTTP integration, untrusted identity assertions and expiry.

## Backend collection contract (future implementation, not executed)

1. Authenticate a **server-side** Shopify app installation for the exact expected shop. Never put Admin access tokens or customer credentials in the browser, fixtures, cart line properties or release archives. Use minimum read-only scopes and rotate/revoke secrets appropriately.
2. Capture an immutable query scope and expected count for that exact query. For each `products(first:N, after:cursor, query:...)` response, retain edge cursors, `pageInfo.hasNextPage`, `pageInfo.endCursor`, the requested cursor, and a query-specific count. Never claim that a filtered six-template subset is the full fourteen-product catalog.
3. For **each** product, capture its first `variants(first:N)` page, the declared `variantsCount.count`, then retrieve *all* additional variant pages with the returned `endCursor`. Keep the exact parent product GID on each continuation. The offline assembler accepts only a complete and consistent capture.
4. Revalidate Shopify read credentials, pagination boundaries, consistency across pages, price/currency/inventory/availability at actual transaction time, and the latest product/variant membership. A page sequence may still reflect concurrent Shopify edits; a successful local digest does not prove a coherent transactional snapshot. For production, use server-issued revision metadata and explicit re-fetch/ETag or version checks as supported by Shopify APIs.
5. Store the accepted capture and last revision in a protected, durable, tenant-scoped database with atomic compare-and-swap, not a JavaScript process variable. Never allow a stale capture to overwrite a newer one. Distinguish DRAFT, ACTIVE and ARCHIVED, and never use a fixture price as checkout authorization.

## Authenticated customer/guest architecture (future implementation, not executed)

- Establish an app backend with server-side Shopify installation identity and explicit session boundary. A real trusted verifier must validate Shopify Customer Account or an appropriate signed app/session token according to the chosen Shopify auth flow, including cryptographic signature, allowed algorithms, JWKS/issuer, audience, expiry, tenant, session revocation and replay. **This prototype does not implement Shopify JWT verification** and does not assert a particular provider token format.
- Keep browser session handling, CSRF/origin protection, rate limits and guest-to-customer linking in the backend. Do not treat an arbitrary customer GID, browser JSON, URL parameter, or local bearer design token as verified identity.
- Use a server-side mapping `(shop, verified principal subject, design reference, immutable revision)` with authenticated authorization checks and secure ownership migration rules. Validate the exact current design, product, variant, artwork checksum and manufacturing profile at every sensitive transition. Do not return bearer grants in cart or order metadata.
- Keep the v0.6 five-minute preview capability local-only. Production requires durable atomic replay storage, key rotation, explicit token issuer/audience and trusted principal binding. Future timed order metadata and webhook reconciliation require independent authorization and idempotency; preview receipts do not authorize checkout.

## Verification and non-claims

- Baseline v0.6: **67/67** passing tests after SHA-256 verification and ZIP integrity check.
- v0.7: **83/83** passing tests; **16 new tests**, zero npm dependencies added.
- Local-only static and Node.js regression verification; no browser/device QA, hosted authentication, live Shopify API verification, catalog consistency proof, payment/order testing, or production security audit.
- No live theme, app, catalog, price, checkout, customer, order, fulfillment, settings, billing, staging, or production mutation. No real customer data or secrets.

## Next objective suggestion

Objective 8: manufacturing profile/print-zone approval provenance and GLB asset approval enforcement (separate *reviewed* geometry from draft worksheet; preserve offline-only and fail-closed checkout), followed by simulated cart-to-order reconciliation with authenticated webhook/idempotency contracts. No machine output until real calibrated evidence and Captain approval.
