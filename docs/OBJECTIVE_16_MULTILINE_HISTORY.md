# Objective 16 — Offline multi-line historical reconciliation and cancellation integrity

**Release:** v0.16.0. **Scope:** Synthetic offline fixtures only. No Shopify reads or writes.

## Threat model and implementation

The v0.15 atomic multi-line ledger recorded observed orders and cancellation events,
but accepted inconsistent historical snapshots (for example an order with no
observed event, an orphan cancellation, or a `CANCELLED` state without a cancellation
record). These inconsistencies could allow downstream offline reconciliation to
misinterpret the state of an order after storage corruption or operator error.

`src/offline-durable-ledger.mjs` now checks the following on **every load** before
any read or write proceeds:

- Every multi-order has **exactly one** `ORDER_OBSERVED` event.
- Each event refers to an existing multi-order in the same shop.
- The observed event precedes every cancellation in append order.
- `OBSERVED` has zero cancellations; `CANCELLED` has one or more.
- No multi-order has more than **32 total events** (one observation plus at most
  31 distinct cancellation-event IDs). Duplicate retries of previously recorded
  events remain idempotent even at capacity.
- Previous v0.15 cross-protocol, nonce, owner/session, immutable design/variant,
  event-ID, checkout, and order-claim guards remain in place.

The new `getMultiLineageHistory({shop,orderGid})` returns a **deeply frozen,
read-only** snapshot of the multi-order lines, state, and ordered event headers,
including cancellation count. It returns null for unknown orders. It never
returns a payment, checkout, manufacturing, or fulfillment approval. It is a
trusted local ledger API, **not** an authenticated customer-facing endpoint.

The existing atomic cancellation commit continues to mutate only the whole
order state and append one cancellation event under a single local lock and
single rename. No design claims or receipt nonces are released. The new
per-order event limit is enforced before persistence; malformed/over-capacity
histories fail closed without overwriting the source file.

## Evidence and regression cases

`node --test tests/objective16-multiline-history.test.mjs` covers immutable
historical views; missing, duplicated, orphaned, misordered, and invalid-action
events; mismatched order state; partial line corruption; owner/checkout/order
substitution; three-line cancellation; concurrent cancellation; simulated
before-/after-rename interruptions; 32-event flood cap and duplicate retry;
previous-version empty-history migration; and cancellation after checkout
expiry. Run `npm test` for the complete suite.

## Explicit limitations

- Semantic state validation **does not cryptographically authenticate** the
  persisted JSON ledger. An adversary with write access to the local directory
  could coherently rewrite events and hashes. Production needs authenticated,
  append-only or transactionally audited persistence and key management.
- The ledger is a single-host local fixture. Linux kernel locks are opt-in and
  require a trusted local filesystem. No NFS, distributed ACID, power-loss,
  backup/restore, or production durability guarantee is made.
- Historical event headers contain SHA-256 of previously authenticated synthetic
  event bodies; the original raw event bodies are not stored. This is not a
  forensic reconstruction of Shopify traffic.
- Existing offline v0.15 ledgers with **more than 32 events for one order** now
  fail closed and require offline review before migration; there is no automatic
  truncation or silent event deletion.
- No hosted customer identity, real Shopify webhook, checkout/payment
  verification, fulfillment, production GLB, physical calibration, or sales
  authorization has been tested or enabled.

## Reproduction

```sh
node --version
node --test tests/objective16-multiline-history.test.mjs
npm test
```
