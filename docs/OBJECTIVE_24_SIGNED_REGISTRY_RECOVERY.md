# Objective 24 — Signed offline private-registry recovery

Status: **offline prototype only**. No Shopify access, hosted customer authentication, external production trust anchor, protected signing service, encryption, or manufacturing approval.

## Purpose

A private-registry write first persists and fsyncs an authenticated local JSON snapshot, then performs a compare-and-set on an **independently supplied** trust anchor. A process failure between these steps leaves a newer local snapshot and an older anchor. Ordinary reads and writes fail closed with `REGISTRY_ROLLBACK`. Recovery is a distinct operator-only method, never automatic.

## Security contract

The caller configures `createOfflinePrivateRevisionRegistry({directory,secret,readAnchor,compareAndSetAnchor,recovery:{registryId,publicKey}})` where `publicKey` is an Ed25519 public `KeyObject`. Keep the private signing key **outside** this process and outside the registry directory. The recovery method is `recoverInterruptedRegistry({authorization})`.

The exact signed payload has these insertion-ordered keys:

`schema`, `registryId`, `authorizationId`, `issuedAt`, `expiresAt`, `expectedAnchor`, `targetAnchor`, `reason`.

`schema` is `TJ-OFFLINE-PRIVATE-REGISTRY-RECOVERY-1`. Sign UTF-8 bytes of `schema + "\\0" + JSON.stringify(payload)` using Ed25519 (`crypto.sign(null, ...)`). Encode the 64-byte signature as canonical base64url in a separate `signature` field. The permit requires a 12–80-character safe registry ID and authorization ID, integer Unix-millisecond issue and expiry times, and a validity window no longer than 15 minutes. The reason must be 8–200 printable characters.

A trusted independent operator must verify both the actual persisted snapshot and independent anchor before signing. Merely calling this API or generating a permit in the same untrusted process does **not** provide independent authorization.

The local v0.24 snapshot adds HMAC-authenticated `previousMac`. Recovery first validates the entire registry, PNG hashes, revision identity and HMAC; then under the existing Linux kernel lock it requires:

1. Exact signed target `{sequence,mac}` equals the local state.
2. Exact signed expected anchor equals the independently read anchor.
3. Target sequence is exactly one greater than the expected anchor (or 1 from genesis).
4. Local authenticated `previousMac` equals the expected anchor MAC (or 64 zeroes from genesis).
5. External compare-and-set succeeds and independent readback matches the target.

The operation never modifies the registry file, revisions, artwork bytes, revocation tombstones, or consumed replay IDs. A repeated valid permit after a successful CAS returns `already-recovered` without a second CAS. Concurrent recovery is serialized by the existing lock. A failed CAS, invalid signature, malformed state, rollback, stale/forged anchor, or readback outage never returns `recovered`.

## Legacy compatibility and limits

Fully anchored v0.23 snapshots without `previousMac` **remain readable**. A normal authorized v0.24 mutation from such a snapshot records `previousMac` and upgrades the chain. However, a v0.23 snapshot already interrupted after local rename **cannot** prove its predecessor MAC and is deliberately rejected by this new recovery method with `REGISTRY_RECOVERY_LEGACY_UNPROVEN`. It needs a separate, independently verified out-of-band restoration procedure. Do not bypass the failure by rewriting the anchor, recomputing HMACs, or deleting records.

The trust anchor is injected and only simulated in tests. These guarantees are for one Linux host and a trusted local filesystem. A compromised signing key, HMAC key, independent anchor, or malicious operator is outside the demonstrated guarantees. No durable multi-host transactions, production-grade key custody, hosted identity, actual checkout, physical calibration, or production approvals are provided.

## Reproduce

```sh
node --version
node --test tests/objective24-registry-recovery.test.mjs
npm test
```
