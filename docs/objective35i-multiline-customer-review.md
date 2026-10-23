# Objective 35I — Offline multi-design customer review and synthetic observation

**Scope:** local prototype, synthetic fixtures, zero Shopify reads/writes, no hosted auth, checkout, payment or production permission.

`createOfflineMultiReviewObservation` composes existing local saved-design review, independently authenticated synthetic V2 receipt issuance, authenticated multi-line event verification, and the existing durable atomic ledger transition. The caller supplies server-owned adapters; none of the local owner capabilities are copied into signed cart properties or observed-order ledger records.

## Contract

- Requires 2–25 unique, ordered line IDs and saved-design references; every line must exactly match the authenticated synthetic event's product, variant and revision before any receipt is issued.
- Rejects plain-object copies of signed events before issuance using the private event-authentication WeakSet. A valid event HMAC is necessary, not sufficient, for authorization.
- Issues synthetic receipts one line at a time using the existing 35H owner/revision/digest checks and independently resolved principal. No nonce is consumed during issuance.
- Re-reads every saved design after all asynchronous issuance to catch a draft revised while another line was prepared. The server-owned durable ledger performs its own design CAS and nonce replay check atomically with order observation; this final ledger check is essential because the local reread is not a transaction lock.
- The observed event's checkout/session identity and each signed receipt are independently verified by the existing multi-lineage adapter. Replays of an identical authenticated event are idempotent; a new event cannot reuse claimed designs or nonces.
- Output contains only the synthetic order identifier, line count, action, outcome and explicit no-commerce flags. It never returns a Shopify cart line, checkout URL, payment authorization, local owner token or production approval.

## Reproduce

`node --test tests/objective35i-multiline-review-observation.test.mjs`

`npm test`

`node scripts/build-staging-static-bundle.mjs --check`

`node scripts/build-main-staging-reconciliation.mjs --check`

## Boundaries and release gates

This is not a Shopify webhook, actual Shopify order, hosted authenticated session or durable production storage. Synthetic event signing keys and local ledger are temporary offline test fixtures. The existing adapter dependencies must remain server-owned and must never be supplied by an untrusted browser request. No storefront assets are changed by this objective. Live catalog/variant eligibility, pricing, manufacturing geometry/GLB approval, customer private storage, real checkout and browser acceptance require separate Main Engineering verification and explicit authorization.
