# Objective 32H — Portable, signed witness-history checkpoints (offline QA only)

Release v0.30.35. This is a read-only contract, **not** a hosted witness, publication system, live Shopify integration, checkout authorization, or manufacturing approval.

## Implemented

`src/offline-portable-witness-history-checkpoint.mjs` provides:

- `offlineWitnessHistoryCheckpointSigningBytes(body)` — domain-separated canonical Ed25519 signing input.
- `encodeOfflineWitnessHistoryCheckpoint(checkpoint)` and `decodeOfflineWitnessHistoryCheckpoint(bytes)` — strict, bounded, deterministic JSON transport; reject duplicate fields, extra fields, malformed signatures, noncanonical bytes, sparse/accessor-bearing signature arrays.
- `offlineWitnessHistoryCheckpointAuditorPolicyDigest({auditors,quorum})` — dedicated domain-separated digest of sorted, unique Ed25519 public keys and strict-majority quorum; never embeds private keys.
- `offlineWitnessHistoryCheckpointDigest(checkpointOrBytes)` — digest of the **signed** portable bytes, including auditor signatures.
- `offlineWitnessHistoryAnchorCandidate(checkpointOrBytes)` — a *candidate* anchor for separate trusted retention. It does not publish or authenticate an anchor's origin.
- `verifyOfflineWitnessHistoryCheckpoint({...})` — checks auditor signatures, independently supplied auditor policy pin, complete Objective 32G receipt-history evidence, exact signed checkpoint/window/receipt bindings, and supplied anchor continuity. It never writes, repairs, accepts a disposition, or authorizes checkout.

A checkpoint binds registry ID, genesis digest, contiguous receipt window start/end, predecessor receipt digest, final receipt digest, domain-separated window history digest, previous checkpoint digest, auditor policy digest and auditor-attested timestamp. The full 32G evidence (including 32F audit bundles and policy transitions) must be supplied separately to verify the checkpoint; portable checkpoint bytes alone **do not** prove history.

## Supplied anchor semantics

The caller MUST independently retain the `anchor` and `expectedAuditorPolicyDigest`. The module cannot establish that the caller actually did so. For a checkpoint whose end sequence equals the supplied anchor sequence, the signed checkpoint digest, receipt head and timestamp must match exactly; a signed fork is rejected. For a later checkpoint, its verified window must start exactly one receipt after the anchor, and its previous receipt digest and previous checkpoint digest must equal the anchor's pinned values. Gaps, stale checkpoints, mismatched genesis/registry, timestamp rollback and mismatched optional candidate digest pins fail closed.

**Important:** A candidate extending a supplied anchor is not thereby independently published or proven unique. Two conflicting, validly signed successors could both extend the same anchor until an external monotonic authority chooses and publishes a successor. The optional `expectedCandidateCheckpointDigest` verifies equality to a caller-supplied value, not its independent custody. Anchors can be locally fabricated, so verification does **not** establish external anti-rollback unless their provenance is independently trusted. No independent timestamp authority exists. Auditor policy rotation is intentionally not supported in this contract; a mismatched auditor policy fails closed.

## Regression and attack coverage

`tests/objective32h-witness-checkpoint.test.mjs` contains 31 new synthetic Ed25519 and filesystem-read tests: valid successor and same-sequence matches; canonical byte roundtrip; malformed/duplicate-key/noncanonical JSON; forged/minority/duplicate/reordered auditor signatures; swapped/duplicated keys; missing/altered anchor, wrong registry/genesis, stale candidate, same-sequence fork, re-signed fork, sequence gap, wrong predecessor checkpoint/receipt, timestamp rollback, altered candidate pin; forged/omitted historical witness evidence, locally recomputed unpinned history; forbidden production claims; sparse/getter signature arrays, unexpected fields; truncated local file and replaced local file with externally retained anchor. The file tests are **read-only verification** after local fixture mutation; they are not crash-injection or real independent publication proof.

```sh
node --version
node --test tests/objective32h-witness-checkpoint.test.mjs
npm test
```

## Explicit remaining gates

External monotonic anchor publication/custody, protected auditor and witness private keys, deployed independent witnesses, trusted timestamps, immutable offsite retention, actual hostile-host race protection, auditor-policy migration, atomic cross-resource recovery, hosted identity, actual cart/order flow, approved physical GLBs/print geometry, prices and manufacturing validation. `independentlyPublished:false`, `externalPinPublicationVerified:false`, `trustedTimestampVerified:false`, `fullGenesisHistoryVerified:false`, `authorizesRemediation:false`, `authorizesCheckout:false`, `productionApproved:false` remain false.

## Next coherent objective

32I — offline multi-checkpoint ancestry verification with pinned predecessor anchors, strict fork detection across multiple independently supplied checkpoints, and auditor-policy transition authorization. No network publication, no Shopify writes, no deployment.
