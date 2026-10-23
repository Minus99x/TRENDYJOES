# Night Watch Objective 9 — offline order/webhook reconciliation (v0.9)

**Scope:** Offline source and synthetic tests ONLY. No Shopify HTTP traffic, checkout, order creation, payment verification, machine output, production authorization or deployment. The v0.8 editor, universal catalog architecture, 2D/3D, GLB intake, calibration and mid-century identity remain unchanged.

## Delivered contracts

`src/order-reconciliation.mjs` provides two deliberately disconnected pure/injected backend seams:

1. `authenticateOfflineOrderWebhook({rawBody,headers,webhookSecret,expectedShop})` verifies a Shopify-style HMAC-SHA256 base64 signature against **unaltered raw bytes** using timing-safe comparison, requires exact expected shop and `orders/create` topic, bounded body, a UUID webhook ID, exclusive lowercase normalized headers, valid UTF-8/JSON, and no duplicate JSON object keys. A private WeakSet prevents forged `authenticatedFixture` objects from bypassing verification. The verified order graph is frozen to prevent post-auth mutation. **No actual Shopify signing secret, Shopify network request or trusted HTTP adapter is included.** An eventual adapter must normalize and reject duplicate headers and verify webhook subscription/app provenance, timestamp/replay policy, key rotation, and provider documentation.

2. `reconcileOfflineOrder({verifiedWebhook,metadataSecret,lookupDesign,claimOnce})` checks a Shopify-shaped synthetic `orders/create` body, safe numeric order and line identities, authenticated customer GID, exact product/variant numeric-to-GID mapping, exclusive `_TJ` metadata fields, legacy order-metadata HMAC, canonical revision/digest, and **fresh server-side** design ownership/identity/revision/`CURRENT` status. Unrelated plain line items may coexist; partial `_TJ` metadata, duplicate customized references, cross-customer or cross-tenant records, stale revision, invalid signatures and missing design records fail closed.

The injected `claimOnce({eventKey,bodySha256,orderGid})` must be a **durable atomic cross-process** operation, returning `acquired`, `duplicate` (only identical event/payload/order), or `conflict`. A conflict rejects. Tests use an in-memory mock for deterministic concurrency, not a real durable database. The ledger is called only after full validation. Ledger failure rejects. No manufacturing jobs are ever created.

Returned evidence always has `paymentVerified:false`, `checkoutEnabled:false`, `productionApproved:false`, `fulfillmentAuthorized:false`, `manufacturingJobs:[]`. The fixture's `financial_status` string is intentionally not payment proof. No checkout endpoint is added.

## Important security and integration limitations

- The v0.5 legacy `_TJ Binding HMAC` was **never** an online checkout authorization: it lacks tenant, owner, nonce, expiry, key ID, checkout session and verified purchase binding. It is used here only to validate fixture metadata consistency against a trusted design lookup. A future design must replace it with a versioned authenticated order protocol.
- A Shopify webhook HMAC proves possession of a configured secret, not the authenticity of a customer, the payment state, delivery or manufacturing authorization. This code does not verify real Shopify delivery behavior.
- The `lookupDesign` adapter must be a protected backend source with current revision, owner identity, composition/artwork integrity and shop scoping; never use request JSON as a design record. The eventual database must coordinate revision freshness with idempotency/fulfillment transitions atomically.
- Real webhooks may use API-specific schemas, optional customer IDs, more than 250 lines, and extra line properties. This conservative contract intentionally rejects unsupported cases rather than guessing. Guest checkout needs a separately designed verified guest ownership path.
- Webhook request size, HTTP body encoding, raw-body capture, headers, secret rotation, subscription verification, data retention and denial-of-service controls require production adapters and security review. JSON object key duplication is rejected locally; this is not a comprehensive JSON security audit.
- No actual Shopify Admin, Storefront, customer auth, checkout, pricing, inventory, tax, order status, payment provider, fulfillment, browser or production tests occurred. No customer data or secrets are bundled.

## Reproduction

Node.js >=20 (verified using v22.16.0):

```bash
npm test
node --test tests/objective9-order-reconciliation.test.mjs
```

## Next recommended Objective 10

Offline adversarial contract tests for **cross-process durable atomic replay and revision CAS**, authenticated cart-to-order transition semantics, webhook key rotation/tenant binding and immutable signed design-reference versioning, without Shopify writes. Consider a local SQLite fixture only if available without external dependencies; otherwise build a deterministic fault-injected durable adapter contract and tests. No real fulfillment authorization until separate production gates are satisfied.
