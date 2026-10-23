# Objective 33Q — Independently pinned 33O registry-record evidence

**Offline-only local prototype; no Shopify reads or writes.**

## New interfaces

- `offlineConflictAcquisitionRegistryRecordBytesDigest(bytes)` — domain-separated SHA-256 pin for canonical 33O registry-record bytes; caller must store the digest independently of the target filesystem.
- `verifyOfflineConflictAcquisitionRegistryRecordEvidence(args)` — validates the complete ordered 33O record sequence from independently reconstructed genesis against at least two signed, independently pinned 33P publisher assertions. Requires independently retained publisher identities, keys, signed receipt digests, namespace/scope/host/registry identity, directory inode pin, initial 33J inventory head, 33N observer public key, record byte digests and a caller-supplied verification clock. Does **not** read a filesystem.
- `acquireOfflineConflictAcquisitionRegistryRecordsReadOnly({directory,checkpoint,...args})` — Linux-local descriptor-anchored, no-write file acquisition plus the same cryptographic verifier. `checkpoint` is a **test-only** race injection hook, not a production trust primitive.

## Fail-closed rules

Signed publication assertions must reconcile to a single identical registry and inventory head; unequal-height or same-height split views remain unresolved. All numbered records must be present from genesis (no suffix-only proof). Every record must have exact canonical UTF-8 JSON, an externally pinned byte digest, the correct index, predecessor, namespace, host and observer, and a valid domain-separated record hash. Every embedded 33N receipt must revalidate its Ed25519 signature, canonical source-record bytes, head transitions, expiry at the original admission time, observer identity and unique nonce/digest across the full supplied history. The final 33O registry head and inventory head must match the independently signed 33P claims. Bounded to 64 records, 3 MB each and 16 MB cumulative; larger histories fail closed pending a future streaming verifier.

The optional local Linux acquisition requires the externally pinned directory inode/device, owner-only directory and file permissions, a complete exact numbered file list, no hardlinks/symlinks, stable file-descriptor and directory metadata before and after reads, and no `.pending.json`, lock, or unknown file. It never repairs interrupted commits or writes to disk. Observable rename, symlink and replacement races fail closed; there is **no claim of eliminating every kernel-level TOCTOU scenario**.

## Reproduction

From a clean extracted release on Node 22.16.0:

```sh
node --test tests/objective33q-acquisition-record-evidence.test.mjs
npm test
```

## Non-goals and remaining gates

Externally supplied pins are trusted inputs, not evidence of independent publication. The verifier authenticates signed publisher claims and the supplied or locally acquired record bytes, but cannot establish remote filesystem truth, trusted time, actual off-host publication, protected private keys, global consistency, multi-host durable replay admission, or production/checkout authority. Neither 33O nor 33P writes to Shopify. No hosted auth, manufacturing approval or deployment is implied.

**Next Objective 33R:** authenticated, independently pinned multi-host acquisition manifests that bind 33Q verified record-byte roots to observer identities and explicitly expose split-view/rollback states without claiming remote filesystem proof.
