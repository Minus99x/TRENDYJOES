# Objective 32A — independently pinned multi-archive completeness (offline QA)

`src/offline-pinned-multi-archive-inventory.mjs` adds a **read-only** complete receipt-to-archive inventory verifier. It supports a shared multi-archive directory or multiple legacy single-archive directories, without changing their bytes or relaxing orphan rejection. It is deliberately separate from Objective 31Z's one-shot archive staging and supervisory recovery.

## Trust and invocation

The caller provides an existing, trusted, fully authenticated `registry` instance (`createOfflineExportReceiptRegistry` or `createOfflineMultiEpochExportReceiptRegistry`), its private directory, the registry ID, the exact set of private archive directories, a canonical inventory manifest, **an independently retained SHA-256 of that manifest**, an independently retained signed registry head, the independently retained witness-transition digest and epoch, and an evaluation timestamp. Never derive the trusted pins solely from the directories being checked.

`encodeOfflinePinnedArchiveInventory({registryId,expectedHead,expectedEpoch,expectedTransitionDigest,archives})` creates a candidate canonical manifest. Its digest must be independently held before verification; merely hashing a manifest at verification time is not an independent trust anchor. Manifest entries are ordered by consecutive signed receipt sequence and bind directory index, acquisition ID, archive SHA-256 and byte count. The registry must already have been populated with signed receipts by an authorized offline workflow; the verifier does not append any.

`verifyOfflinePinnedArchiveInventory({...})` requires all external pins, checks the full signed registry history using the existing registry's witness-policy verification, validates each canonical on-disk record and hash chain, binds every receipt to exactly one manifest entry and evidence export, and rejects missing, extra, quarantined, or pending archive files. All archive bytes are read twice; the registry records, directory enumerations, directory identities and pinned authenticated registry state are rechecked. It rejects symlinks, hardlinks, non-private files/directories, and directory overlap. Results are informational, frozen, and explicitly `productionApproved:false`.

## Reproducible tests

```sh
node --version
node --test tests/objective32a-pinned-multi-archive-inventory.test.mjs tests/objective32a-multi-epoch-inventory.test.mjs
npm test
```

Tests exercise two real Ed25519-quorum signed receipts across shared and legacy archive layouts, real three-epoch witness migration and receipts, manifest and signed history rollback, forged pins, mismatched identity/size/digest, altered archives, symlinks/hardlinks, extra orphan files, pending and quarantine markers, and mutation during the verification window.

## Non-guarantees and next gates

This is **not** an atomic multi-resource transaction or an automatic orphan repair mechanism. No files are deleted or repaired. A local same-UID adversary or a compromised process/registry dependency is outside the trust boundary; repeated reads cannot eliminate all races, and this is not validated on network filesystems. External SHA/head/transition pins must be genuinely independent, not merely computed by the process that verifies them. There is no trusted timestamping, hardware-backed signing key custody, offsite immutable retention, or independent witness deployment. No manufacturing, Shopify auth, checkout, orders, themes, store mutations, or production authorization is performed.

Next Objective 32B: a read-only externally pinned reconciliation report that classifies multiple archive-directory orphan/uncertain states with cryptographic evidence and explicit supervised dispositions, without silently accepting or deleting orphan evidence.
