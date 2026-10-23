# Objective 31Y — supervised multi-epoch pending recovery (OFFLINE ONLY)

This module extends the Objective 31X local Linux witness-policy registry. It does **not** perform Shopify operations, hosted authentication, manufacturing approval, or checkout. The API is `createOfflineMultiEpochExportReceiptRegistry(...).reconcilePending(...)`.

A crash between writing `.pending-multi-cutover.json` or `.pending.json` and removing the marker leaves the registry intentionally fail-closed. Only a supervisor with independently preserved, **precommitted** before/after pins may reconcile the uncertain commit. Never copy pins out of the same possibly compromised registry as proof of authorization. The code cannot verify the independence of a caller's pins.

The supervisor must supply:

- `kind`: `cutover` or `append`; `decision`: `abort-unlinked` or `finalize-linked`.
- `expectedBeforeHead` and `expectedAfterHead`: exact `{count,headDigest}` objects.
- `expectedBeforeTransitionDigest` and `expectedAfterTransitionDigest`: externally retained full signed transition-chain digests.
- `expectedBeforeEpoch` and `expectedAfterEpoch`: externally retained epoch numbers.
- `expectedPendingDigest`: SHA-256 of the **canonical pending JSON bytes**, recorded independently before a crash, not merely calculated from local recovery files.
- `nowMs`: trusted time input, not a trusted timestamp service.

The cutover head remains unchanged and the epoch increases by one. An append increases the receipt count by one and retains the epoch and transition digest. Recovery verifies canonical owner-only files, Ed25519 historical signatures, transition proofs, all prior signed receipt histories, replay/sequence constraints, exact pins, and the pending record. `abort-unlinked` is allowed only if the destination is absent; `finalize-linked` only if destination and pending marker are the same verified two-link inode. The sole filesystem mutation is unlinking the authenticated pending marker and syncing the directory; committed certificates and receipts are never overwritten, synthesized, or silently repaired. Replaying recovery fails closed.

For a cutover the recovered certificate must form exactly the pinned next transition of the pinned preceding chain, including authenticated witness quorum and incoming proof of possession. For a receipt the pending record must be signed by the correct active epoch witnesses, match its record hash and expected previous/next head, and satisfy receipt chronology and uniqueness constraints. A linked receipt is verified in the complete history. **The archived evidence bytes are not independently re-fetched during recovery**: this operation verifies the cryptographic receipt and durable registry, not offsite archive availability, physical observation, or manufacturing authorization.

Fault injection tests use genuine independent Node processes terminated with SIGKILL before and after hardlink fsync, a SIGKILL after marker unlink, and competing recovery processes using the same `flock` lock. Further tests reject forged signatures, wrong pins, substituted hardlinks, unsafe permissions, replayed recovery, and marker replacement before unlink. The API remains Linux-local, not validated on network filesystems, hostile same-UID processes, or untrusted privileged hosts. It cannot atomically reconcile archives and receipts as separate resources.

Run `node --test tests/objective31y-multi-epoch-supervised-recovery.test.mjs` and `npm test` on Node 22.16.0. This work preserves Objective 31X source behavior and the original 2D/3D editor, model import/calibration, and universal product templates. Main Engineering's separate v0.32 UI is not touched.

The complete suite uses `--test-concurrency=4` in `npm test` to bound simultaneous filesystem/child-process fault-injection workloads. An initial unbounded `npm test` attempt exhausted the execution window; the same full suite passed with bounded concurrency. This changes test scheduling, not test selection or production behavior.
