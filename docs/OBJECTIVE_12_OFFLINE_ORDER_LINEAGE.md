# Objective 12 — Synthetic checkout/session lineage and atomic observed order transitions

**Version 0.12.0. OFFLINE PROTOTYPE ONLY. NO SHOPIFY READS OR WRITES.**

This objective adds an independent v2 cart-to-order **observation** contract. It does not
connect to Shopify checkout, customer login, order/payment webhooks, production storage,
fulfillment or manufacturing. The test HMAC event format `TJ-SYNTHETIC-LINEAGE-EVENT-1`
is **not** Shopify's webhook protocol and must never be passed off as such.

## Source and trust boundaries

- `src/versioned-cart-metadata.mjs`: v2 verification now optionally accepts a
  server-supplied `expectedIdentity` containing the exact shop, subject and session ID.
  It compares these with the separately resolved trusted principal *before* consuming
  the receipt nonce. The signed v2 receipt still carries pseudonymous owner/session
  tags, not raw customer/session IDs.
- `src/offline-order-lineage.mjs`: verifies a synthetic, domain-separated HMAC event
  with strict canonical JSON, bounded body, tenant and UUID. The HMAC explicitly
  binds the tenant and event UUID header to the raw body (not just the JSON). An internal WeakSet
  rejects caller-fabricated "verified" event objects. The injected checkout resolver
  must return a **server-owned** `BOUND_OFFLINE` record with exact checkout ID,
  owner, session, shop, expiry, and all authorization flags false. For a new
  `ORDER_OBSERVED`, it checks event fields against server-expected binding, then
  calls the real v2 cart authority's `verify` with `expectedIdentity` and the
  current design/nonce CAS adapter. A cancellation uses a separately authenticated
  synthetic event and an existing durable observed lineage, not a new cart receipt.
- `src/offline-durable-ledger.mjs`: new `lineage` and `lineageEvents` arrays migrate
  old v0.11 snapshots on write. `commitLineageTransition` uses the **same single-host
  lock** as revision CAS, nonce consumption and legacy claims. Enforces one
  checkout/order/design revision, exact owner/session digest/product/variant/line,
  replay conflicts, and only `OBSERVED -> CANCELLED` state transition.
  The older v0.9 `claimOnce` path now rejects any design revision already
  observed by v2, preventing cross-protocol double-claiming. Replays
  of an already committed identical event can be acknowledged idempotently without
  consuming a second cart nonce. A signed event with a different body and same ID
  fails closed. No payment/fulfillment state exists.

## Exact states and limits

`ORDER_OBSERVED` and `CANCELLATION_OBSERVED` mean a synthetic event was accepted
and its binding recorded. **They do not prove checkout completion, payment capture,
fraud review, inventory allocation, or manufacturing readiness.** There is no
`PAID`, `APPROVED`, `READY_TO_PRINT`, or `FULFILLED` transition.

The first offline lineage contract is **one custom design per synthetic order event**.
Multi-line reconciliation, partial refunds, edits, real Shopify event identity,
customer vs guest identity, and multiple checkout sessions are NOT implemented.

## Critical unresolved transaction gap

The v2 receipt nonce is consumed in one durable transaction; the observed order
lineage is committed in a **separate** transaction. A crash after nonce consumption
but before lineage commit requires a **new signed receipt**. A crash after atomic
lineage commit but before acknowledgement can be retried with the identical signed
synthetic event; the persisted event is recognized without consuming the nonce.
This is intentionally tested and is **not production-safe exactly-once delivery**.
A future production backend must atomically bind receipt consumption, checkout
session, order line, design revision and event ID in a multi-host transactional DB,
or provide a durable recoverable reservation protocol. Do not paper over the gap.

## Security review / production holds

- Both checkout resolver and principal verifier are injected **synthetic test
  adapters**, not hosted Shopify identity. Only a trusted backend may supply
  these adapters, HMAC keys, and expected identity/binding.
- Synthetic HMAC event fixtures contain raw subject/session IDs; this is test-only.
  Production privacy, storage retention, PII handling, and signing key lifecycle
  require separate design and review.
- The filesystem ledger is single-host only; no distributed transaction, lock
  fencing, process lease recovery, encryption at rest, or production KMS.
- Event replay acknowledgement is bounded by the synthetic event's five-minute
  freshness and the checkout resolver's expiry; real webhook retries may arrive
  later and require a different durable authentication/acknowledgement policy.
- The older v0.9 `orders/create` HMAC reconciliation remains separate and is **not**
  connected to v2 lineage. Neither legacy metadata nor v2 cart metadata authorizes
  a checkout or proves payment.
- Production GLB approval, physical print-zone calibration, artwork scanning,
  pricing, inventory, shipping, real checkout/payment reconciliation and mobile
  device QA remain blocked pending independent verification.

## Reproduce

```bash
node --version
node --test tests/objective12-order-lineage.test.mjs
npm test
```

No external npm dependencies, Shopify access, secrets, deployments or store writes
are required or performed.
