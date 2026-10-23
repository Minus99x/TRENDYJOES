# Objective 17 — Lossless, offline multi-order history compaction

**Version:** v0.17.0. **Scope:** Synthetic single-host fixtures only. **Shopify writes: NONE.**

## Implemented

`createOfflineDurableLedger({directory})` exposes
`compactMultiLineageHistory({shop,orderGid})` for a **CANCELLED** synthetic
multi-line order. Under the same existing local ledger lock and atomic file
replacement, it converts the full order's uncompressed `multiEvents` headers to
`multiArchives: [{shop,orderGid,entries:[[eventId,bodySha256], ...]}]`.
The first tuple is `ORDER_OBSERVED`; subsequent tuples are
`CANCELLATION_OBSERVED`. Each original UUID and authenticated event-body SHA-256
is retained. No event ID, design claim, receipt nonce, order, checkout ID,
product/variant binding, or immutable revision is discarded. This is **lossless
encoding**, not retention deletion or garbage collection.

The method returns `acquired` after a successful atomic compaction, `duplicate`
if already compacted, and fails closed on an unknown/uncancelled order or unsafe
state. A before-rename fault leaves the original event history intact; a
post-rename lost acknowledgment can be retried idempotently. The existing
single-host `mkdir` and optional Linux kernel locks still control concurrency.

All historical lookups, authenticated synthetic replay checks, and cross-protocol
event collision guards consult both uncompressed and archived event IDs. A new
synthetic cancellation after compaction appends to the compact archive while
preserving the existing **32 events per order** limit. The combined uncompressed
and archived multi-event count remains limited to 5,000. Archived histories
must belong to existing `CANCELLED` orders, contain at least one observation
and one cancellation, never coexist with uncompressed events for the same
order, and contain valid, unique event identities. Corrupt snapshots fail
closed before further writes.

## Verification

`node --test tests/objective17-multiline-compaction.test.mjs` exercises 24
adversarial cases: exact before/after history equality, storage-size reduction,
retained nonce/design/variant/owner claims, observed/cancel replay, conflict
rejection, additional cancellation, history flood cap, concurrent compaction,
pre-/post-rename fault injection, three-line orders, malformed/orphaned/duplicate
archive rejection, legacy and single-line protocol collisions, and oversized
storage failure. `npm test` reruns all earlier objectives.

## Limitations and explicit production gates

- JSON state is not cryptographically tamper-evident or physically append-only.
  A local filesystem attacker with write access can coherently rewrite history.
- Compact tuples still retain every UUID/digest: the 2 MiB file limit and 5,000
  combined-event limit **remain**. This objective does not enable indefinite
  retention or safe replay tombstone deletion. Historical order claims are never
  released. Long-term retention requires a trusted transactional database,
  immutable authenticated audit log and formally defined expiry/retention policy.
- This is a single-host, trusted local-filesystem fixture, not distributed ACID,
  NFS-safe, power-loss-proof, hosted identity, or production recovery.
- All event bodies are synthetic and HMAC-authenticated by injected offline
  adapters; no real Shopify webhook, checkout, payment, fulfillment, manufacturing
  approval, physical calibration or deployment is represented or enabled.
- Existing snapshots without `multiArchives` remain readable and are upgraded
  only when a write is made. v0.16 ledgers already failing the 32-event cap
  still fail closed; no silent migration or truncation.

## Reproduce

```sh
node --version
node --test tests/objective17-multiline-compaction.test.mjs
npm test
```
