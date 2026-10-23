# Objective 15 — Offline atomic multi-line synthetic order lineage

**Status:** v0.15 offline security fixture only. No Shopify network requests, checkout,
payment, manufacturing approval, fulfillment authorization, or deployment.

## Implemented contract

`src/offline-multiline-order.mjs` accepts an HMAC-authenticated, canonical JSON,
synthetic multi-line event. Domain separation is
`TJ-OFFLINE-MULTILINE-EVENT-1\0<shop>\0<event-id>\0<raw-body>`.
The event must include 2–25 **distinct** line IDs and design references, each with
exact product GID, variant GID, immutable design revision, and composition SHA-256.
It also binds tenant, owner, session, checkout, order, timestamp, and event ID.
HMAC secrets are test-only and are never written to cart metadata or ledger state.
This protocol is distinct from the Objective 12 single-line synthetic protocol;
its signatures are not interchangeable.

`createOfflineMultiLineage` checks a trusted, offline checkout/session record and
prepares a separate Objective 11 authenticated cart receipt for **each** line.
The expected bindings must match the event exactly in line order; there are no
partial/extra items, implicit variant substitutions, or caller-supplied owner claims.
The adapter must be server-owned and must supply the genuine
`authority.assertPreparedForAtomicLineage` validator to the ledger; it is not a
browser-facing API. Never trust an arbitrary caller-supplied validator in a hosted
service. Synthetic cancellation requires exact original lines and cannot accept
cart receipts or authentication context.

`createOfflineDurableLedger` adds `multiOrders` and `multiEvents` to its v1 JSON
state. Old v0.14 snapshots without these arrays are read and migrate only on
first successful write. Under one filesystem lock, the new
`commitMultiLineageWithReceipts` method validates **every** server-authenticated
prepared receipt, checks nonce uniqueness, owner/session, exact design CAS,
existing legacy and multi-order claims, then atomically writes all receipt nonces,
one multi-line order, and one event. No partial line acceptance is permitted.
Cancellation changes the observed multi-line order to `CANCELLED`, preserving
its nonce/design claims; cancellation does not release designs for another order.

Cross-protocol guards prevent multi-line and older single-line/order-reconciliation
records from claiming the same order, event ID, checkout (when available), or
design revision. Unrelated older single-line records continue to work. The new
state validator also rejects conflicting/corrupt snapshots before writing.

## Adversarial coverage

`node --test tests/objective15-multiline-order.test.mjs` exercises multi-product
commits, canonical-HMAC tampering, duplicate lines and references, forged objects,
owner/session/checkout substitution, variant/digest mismatch, stale revisions,
replayed nonces, simultaneous writers and independent Node processes, before/after
rename faults, duplicate event IDs, cancellation, legacy cross-protocol claims,
corrupt state, migration, and Linux kernel-lock mode.

## Boundaries and remaining gates

- This is a **synthetic offline fixture**, not a Shopify webhook implementation.
- One trusted Linux/local filesystem only; no distributed transaction or NFS proof.
- `lockMode:'kernel'` requires the Objective 14 Linux `flock` path; old `mkdir`
  mode is retained for compatibility and has documented abandoned-lock risks.
- Process crash/rename tests do not certify physical power-loss durability.
- Neither synthetic order observation nor cancellation proves payment, stock,
  shipping, production capability, approval, or authorized fulfillment.
- Hosted identity, production key management, external webhook verification,
  real checkout/cart-to-order reconciliation, manufacturing calibration, and
  independent deployment/security review remain required.
- There is no price calculation or approval in this module.

## Reproduction

```sh
node --version
node --test tests/objective15-multiline-order.test.mjs
npm test
```
