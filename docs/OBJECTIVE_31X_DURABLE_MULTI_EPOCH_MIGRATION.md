# Objective 31X — durable multi-epoch export-receipt witness migration

**Offline prototype only.** This does not enable Shopify, hosted authentication, manufacturing, checkout, or production authorization. It does not deploy independent witnesses or manage signing keys.

## Purpose

`src/offline-export-receipt-multi-epoch-registry.mjs` adds an opt-in continuation of the Objective 31V/31W single-rotation receipt registry. It verifies the existing `.witness-cutover.json` and all existing `0001.json`–`NNNN.json` receipts, then commits later policy transitions as non-overwriting `.witness-cutover-0002.json`, `.witness-cutover-0003.json`, etc. The original 31V bytes are not rewritten. Each new epoch requires a newly signed transition with outgoing quorum approval and every incoming witness's proof of possession. Witness IDs and Ed25519 keys may never recur across configured epochs.

Every `inspect`, `rotate`, and `append` requires a **caller-supplied independent receipt-head pin**, **exact current epoch**, and **full transition-chain SHA-256 pin**. `rotate` additionally requires the independently retained **new** chain pin. The caller must provide the complete, trusted policy key set in advance; this module snapshots the public keys and quorum to prevent subsequent mutation of the supplied configuration. It does **not** discover keys or attest the independence of pins. The epoch-specific receipt signatures, full history digest chain, strict sequence, replay identities, historical transition signatures, policy boundaries and timestamps are rechecked on each operation. Append additionally validates the exact signed acquisition archive before accepting a receipt.

All operations use the same Linux `/usr/bin/flock` lock as the existing receipt registry, owner-only files, no-follow opens, exact canonical JSON, `O_EXCL` pending files, `fsync`, and non-overwriting hardlink commits. Real child-process SIGKILL and concurrent-writer regression tests cover the durable transition boundary.

## Fail-closed crash boundary

An interrupted `.pending-multi-cutover.json` or `.pending.json` blocks **all** operations, whether or not a destination hardlink already exists. The module deliberately has **no automatic repair**. The 31W supervisor recovery API only covers the old single-epoch files and **must not** be used on the new multi-epoch pending marker. Recovery of the new marker is the next separately authenticated engineering gate. Preserve the directory and external pins; do not manually delete the marker or guess which state committed.

## Compatibility and isolation

This is a separate opt-in migration API. Existing Objective 31V/31W source and tests remain unchanged. After a second transition is committed, the old single-cutover API deliberately rejects the new file as unknown rather than silently continuing to write under retired witnesses. The v0.5 editor, universal merchandise templates, 2D/3D rendering, model import/calibration, and Main Engineering's independent UI development are unchanged.

## Reproduction

```sh
node --test tests/objective31x-multi-epoch-durable-migration.test.mjs
node --test --test-concurrency=4 tests/*.test.mjs
```

## Outstanding safeguards

Multi-epoch **supervised crash recovery** is not implemented. Independently deployed witnesses, hardware-protected keys, trusted timestamps, offsite immutable evidence, same-UID attacker resistance, network filesystem semantics, atomic multi-resource recovery, production auth, manufacturing approval, and live cart/order reconciliation remain unverified. Historical signed attestations do not prove underlying physical observations.
