# Objective 32B — pinned multi-directory orphan evidence classification (offline)

`src/offline-pinned-orphan-classifier.mjs` adds `classifyOfflinePinnedArchiveOrphans({...})` as an **opt-in, read-only** inspection companion to Objective 32A's stricter complete-inventory verifier. It accepts the same pinned manifest, signed receipt head, witness epoch and transition digest, registry instance and directories. The caller **must** acquire and retain these pins through a genuinely independent channel; computing them from the directory at inspection time provides no independent trust.

## Trust boundary and behavior

1. Require exact canonical inventory bytes and independently supplied SHA-256, reject directory aliases/overlap and public/symlinked roots, enforce 64 directories and 64 MiB aggregate signed-archive scan budget.
2. Call the existing registry's **full authenticated historical witness/epoch verification** with the external pins, then independently read every canonical signed registry record and verify hash-chain continuity, acquisition identity, archive digest, size and sequence against the pinned manifest.
3. Read each private archive directory twice, classify missing/tampered/unsafe signed archive evidence, and record separate **unverified** classifications for extra archives, pending coordination markers, quarantine markers, unknown files and unsafe filesystem entries. Never follow symlinks or hardlinks. Valid signed archives are re-read and checked against their complete forensic export structure and identity. Zero-byte private `.coordination-lock` is allowed.
4. Compare both snapshots, all original signed registry records, root directory identities, and the authenticated registry inspection again. Any observed change **fails closed** rather than returning an apparently authoritative report.
5. Return a deeply frozen canonical report with `reportDigest`, authenticated registry pins, record-history digest, per-directory observations, explicit supervisory review requirement and `mayDelete:false`, `mayRepair:false`, `mayManufacture:false`, `mayAcknowledge:false`, `productionApproved:false`.

**Classification is NOT authentication of unknown evidence.** A SHA-256 of an orphan or marker is an observation, not a witness signature or proof of ownership. `reportDigest` is a local unkeyed SHA-256 of the report, **not a digital signature** and not an independent timestamp. No supervisor decisions are performed, and no files are repaired, quarantined, deleted or moved. Operators must retain the report/pins outside the inspected host and separately authenticate any proposed remediation. Anomalies never authorize manufacturing or Shopify checkout.

## Reproduce

```sh
node --version
node --test tests/objective32b-orphan-classification.test.mjs tests/objective32b-multi-epoch-orphans.test.mjs
npm test
```

Tests include genuine Ed25519 quorum-signed receipts across three witness-policy epochs; forged manifest/epoch/transition pins; modified signed registry; extra, missing, tampered, pending and quarantined files across multiple directories; symlinks, hardlinks, unsafe permissions, untrusted filenames; changed files and new orphans between scans; and no-write preservation.

## Known limitations

This is Linux owner-only local-filesystem QA, not distributed or cross-resource ACID. The registry object and signer policy configuration must themselves be trusted. Same-UID adversaries can race or manipulate this process; two scans cannot prove a stable snapshot under hostile filesystem mutation. Aggregate scan cap is deliberately conservative and may require a future streaming protocol for larger legitimate archives. No protected signing keys, trusted timestamps, independent witness deployment, offsite immutable retention, atomic cross-resource recovery, hosted customer identity, production GLB approval, or real Shopify cart/order processing has been established.

**Next objective 32C:** independent supervisor-decision envelope that cryptographically binds an externally retained 32B report digest, signed receipt/witness pins and exact orphan classification, with replay/expiry protections and *read-only* decision verification. No remediation execution or Shopify writes.
