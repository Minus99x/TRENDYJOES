# Objective 31Z — offline cross-resource archive/receipt coordination

**Status:** QA-only local Linux prototype. No Shopify integration, hosted authentication, manufacturing approval, payment or checkout authority.

## Problem and delivered boundary

A signed export receipt can be durably appended while its referenced forensic archive lives in a separate directory. Neither resource's local `fsync` makes the pair an atomic distributed transaction. The new `createOfflineArchiveReceiptCoordinator` makes this gap explicit and fail-closed: it stores and verifies the archive bytes, persists a canonical intent marker, delegates to the existing cryptographically verified receipt registry, and requires a separately pinned supervisory finalization. It does **not** silently treat a signed receipt as proof of physical acquisition observations.

## Contract

- `stage({receipt,archiveBytes,expectedBeforeHead,expectedAfterHead,expectedTransitionDigest,expectedEpoch,nowMs})` requires a genuine current witness-quorum signature, valid expiry, authenticated export archive, matching acquisition/digest/length, a independently pinned before-head, independently pinned *calculated* after-head, and the current transition chain/epoch pins. Stage writes archive via fsynced temporary file and non-overwriting hardlink, fsyncs the directory, and persists an owner-only intent marker with its SHA-256 returned for independent custody. The archive directory must be initially empty except for its lock.
- `commit({...pins,expectedMarkerDigest,expectedArchiveDigest})` re-verifies every byte, signed intent, exact marker hash, independent pins, the complete existing receipt history, and the absence of the target receipt slot. It invokes the actual registry append and leaves the intent marker present even after successful append. No implicit retry is allowed after a crash.
- `reconcile({...pins,decision})` requires `finalize-committed` **or** `quarantine-uncommitted`. It verifies the externally pinned before/after receipt head through the existing registry and verifies the exact committed signed receipt file when finalizing. Quarantine retains archive bytes and a `.orphan-<digest>.json` forensic record; it blocks further use until independently adjudicated. Finalization removes only the validated coordination marker and fsyncs its directory. There is no automatic deletion of evidence or fabricated missing record.
- `expectedTransitionDigest`/`expectedEpoch` are passed to the existing multi-epoch registry for cryptographic transition-chain validation. The generic adapter also supports the legacy single-policy registry for controlled fixture testing. It is **not** a replacement for the underlying authenticated registry.

## Adversarial test coverage

Valid legacy and **actual multi-epoch** registry integration; retired witness policy and stale transition rejection; forged signatures, altered archive bytes, incorrect after-head, substituted marker, missing/symlink/hardlinked archive, symlinked marker, unsafe directories, concurrent staging, orphan detection, replay and ambiguous decisions. Actual independent Node child processes receive SIGKILL after archive temporary fsync, archive hardlink fsync, coordination marker fsync, before receipt append, after signed receipt append, and after supervisor finalization. No Shopify traffic is performed.

## Limits / security gates

This coordinator is intentionally **one acquisition per archive directory**: it refuses all untracked files, including archives from earlier completed transactions. Do not clear quarantines automatically. No same-UID hostile-process or malicious parent-directory guarantee, no network filesystem semantics, no independent witness deployment, hardware key protection, trusted time, offsite immutable storage, or true atomic cross-resource commit. `fsync` durability is only as strong as the local filesystem/hardware and external trust pins. A crash between archive persistence and marker persistence leaves an orphan that is intentionally blocked pending manual forensic supervision. This is not production recovery or checkout proof.

Reproduce: `node --test tests/objective31z-cross-resource-coordination.test.mjs tests/objective31z-multi-epoch-cross-resource.test.mjs`, then `npm test`.
