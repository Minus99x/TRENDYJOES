# Objective 18 — Authenticated offline ledger and external rollback anchor contract

**Scope:** local-only, optional audit protection for the existing single-host
`createOfflineDurableLedger`. This is a testable **integration contract**, not a
hosted trusted service, a production key vault, a distributed database, or a
Shopify checkout/payment/fulfillment implementation.

## New opt-in API

```js
const ledger = createOfflineDurableLedger({
  directory: scratchDirectory,
  lockMode: 'kernel', // optional Linux single-host lock; 'mkdir' remains default
  audit: {
    keys: [{id: 'audit-2026-01', secret: keyBytes32OrMore}],
    activeKeyId: 'audit-2026-01',
    readAnchor: async () => externalAnchorOrNull,
    compareAndSetAnchor: async (expectedAnchorOrNull, nextAnchor) => boolean
  }
});
```

The `secret` is a Node.js `Buffer` of at least 32 bytes. It stays in memory;
never serialize it into `ledger.json` or store it alongside the ledger.
An anchor is `null` (no prior commit) or `{sequence: positiveSafeInteger,
mac: lowercase64Hex}`. `readAnchor` must return the current **independently
trusted** anchor, and `compareAndSetAnchor` must be an atomic compare-and-swap
that returns true only after a durable external update. The sample tests use
an in-memory fake **solely to verify the interface**; they do not demonstrate
rollback protection against a compromised machine or a process restart of that
fake anchor.

## Commit / verification

For each changed snapshot, compute SHA-256 over JSON serialization of the
ledger state without its `audit` envelope, then compute domain-separated
HMAC-SHA256 over `TJ-OFFLINE-LEDGER-AUDIT-1\0keyId\0sequence\0previousMac\0stateHash`.
Persist an envelope `{schema,sequence,previousMac,keyId,mac}` in the same
atomic `ledger.json` rename as the rest of the ledger. The MAC commits to
all replay tombstones, owner/revision/variant claims, multi-order history and
compacted archives. The `previousMac` links each changed snapshot to the prior
commitment. After fsync/rename, compare-and-swap the external anchor from the
old sequence/MAC to the new sequence/MAC. Reads require a valid HMAC and an
**exact** match against the external anchor. Missing, older, newer or malformed
anchors fail closed. Missing ledger with an existing anchor is a rollback.

This is a **chain of snapshot commitments**, not a retained per-event
append-only journal or independently replay-verifiable complete history. The
latest MAC and external anchor alone cannot prove the entire prior history
without retaining earlier trusted snapshots/commitments.

## Fail-closed limits and recovery

There is an unavoidable two-resource crash window: the local ledger rename
can succeed while the external anchor CAS has not. Such a state is deliberately
**unavailable** on subsequent reads/writes (`LEDGER_AUDIT_ROLLBACK`) until a
trusted operator reconciles both sides from independent evidence. There is
**no automatic acceptance**, no automatic anchor rewind, and no unauthenticated
recovery endpoint. Do not call this distributed atomicity. A CAS failure or
anchor outage can leave the same fail-closed condition. A before-rename failure
leaves both old state and old anchor intact and permits retry.

Legacy unaudited snapshots are readable only in the default unaudited mode.
Enabling audit for a preexisting ledger fails closed; there is no silent
legacy adoption or signing of potentially tampered history. Conversely, an
unaudited adapter refuses an audited ledger. The unaudited mode is retained
solely for backward compatibility; deploying it alongside audited writers
would defeat this optional protection and is forbidden for any real service.

Key rotation uses a new `activeKeyId` with the previous key still present for
verification of the prior snapshot. The key ID is bound in the envelope and
HMAC is verified with the corresponding supplied key. A missing current key
fails closed. Old snapshots still require their signing keys to verify. Keys,
anchors, durability, backups and recovery authorization are **not supplied**
by this local prototype.

Read-only queries are not protected by a transaction lock and may fail closed
while a concurrent writer has renamed the ledger but not yet advanced its
external anchor. Retrying after a completed writer is permissible; never
ignore the mismatch. The optional kernel lock still only protects a trusted
single Linux host/filesystem. File system power-loss behavior, distributed
storage, key theft, trusted remote anchor implementations, and production
identity are **not validated**.

## Reproduce

```sh
node --version
node --test tests/objective18-audited-ledger.test.mjs
npm test
```

Adversarial tests cover semantic tampering, HMAC forgery, missing/old/future
anchors, restored prior snapshots, missing ledger, key rotation, fail-closed
CAS/read outages, before/after rename crash injection, legacy downgrade
rejection, audited multi-line order cancellation/compaction and replay
preservation. The test adapter is synthetic and uses no customer data or
external network.

**NO Shopify writes, no live traffic, no production authority.**
