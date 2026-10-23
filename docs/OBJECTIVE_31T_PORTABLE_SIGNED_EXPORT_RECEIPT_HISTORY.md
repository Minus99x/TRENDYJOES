# Objective 31T — Portable signed export-receipt history (offline only)

This module adds canonical, independently pinned, read-only transport and verification of the **Objective 31S** durable export-receipt registry. It is not a Shopify integration, payment/checkout authorization, production signing system, or proof that the underlying forensic observations were true.

## API and trust model

- `registry.exportHistory({expectedHead})` takes an **independently retained** `{count,headDigest}` and reads the entire local signed registry under its existing cross-process lock, rejecting uncertain pending commits, unsafe filesystem state, altered records, missing records and a stale external head. Returns canonical UTF-8 JSON `Buffer`; no files or network calls are made by the exporter.
- `verifyOfflineExportReceiptHistory({bytes,expectedHead,registryId,witnesses,quorum})` validates canonical bounded transport, the exact externally supplied head, the independently supplied Ed25519 witness policy, all historical receipt signatures, record hashes, predecessor/sequence links, nondecreasing issue times, and replayed export/acquisition/archive/nonce identifiers. It does **not** check historical expiration against the present time, since historical validity does not authorize a new action.
- `compareOfflineExportReceiptHistories({leftBytes,rightBytes,leftExpectedHead,rightExpectedHead,registryId,witnesses,quorum})` verifies **both** full histories before comparing them. `IDENTICAL` and `CONSISTENT_PREFIX_EXTENSION` are not conflicts. `SIGNED_RECEIPT_EQUIVOCATION` identifies differing valid quorum-signed receipt bodies at the same sequence under the same trusted policy. `SIGNED_HISTORY_ENCODING_FORK` indicates differing signed-record encodings without contradictory signed receipt bodies; different valid signer subsets for the same body are not mislabeled equivocation. The returned `conflictEvidence` includes both signed receipts and their record digests, but any independent reviewer must verify both complete bundles and their independent pins.
- `encodeOfflineExportReceiptHistory(...)` is a pure helper for constructing a portable bundle from already validated signed entries. It is not a substitute for `registry.exportHistory` when reading durable local files.

**Trusted inputs must be supplied independently:** exact registry ID, witness public keys and quorum, and each expected head. The module cannot establish that pins are external merely because arguments are supplied. A locally reconstructed pin is insufficient for rollback detection. Signature validity authenticates witness attestations, not the physical facts they describe. A malicious authorized witness quorum may sign conflicting branches; comparing independently retained bundles can expose this, not prevent it.

## Limits and failure behavior

- Maximum 2,000 records, 32 MiB canonical JSON bundle; strict schema keys, exact canonical JSON round-trip and UTF-8 validation; no arbitrary path extraction, filesystem writes, untrusted decompression, network or Shopify access.
- Receipt record hashes bind exact signatures and body; all receipt signatures must verify against independently supplied trust. Unknown fields, malformed keys, replayed identities, missing/altered records, rollback, bad pins, forged or minority signatures, noncanonical transport and truncated bundles fail closed.
- Historical receipts do not confer new approval. Results explicitly set `productionApproved:false`, `readOnly:true`; no manufacturing or checkout authority is created.
- Offline process/fsync behavior remains subject to host filesystem and same-UID compromise limits. Portable bundles do not provide a trusted timestamp, protected witness key custody, offsite immutable storage, actual witness deployment, or atomic multi-resource recovery.

## Reproduce

```sh
node --test --test-concurrency=4 tests/objective31t-export-receipt-history.test.mjs
node --test --test-concurrency=4 tests/*.test.mjs
```

Night Watch and Main Engineering coordinate only through explicit Library handoffs. Preserve separate Main Engineering v0.32 UI development and all v0.5 editor, 2D/3D, GLB import/calibration, universal merchandise, and mid-century branding files.
