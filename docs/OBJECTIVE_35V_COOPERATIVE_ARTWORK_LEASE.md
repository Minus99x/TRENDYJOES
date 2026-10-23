# Objective 35V — cooperative local artwork lease (offline prototype)

The local-only `withLocalArtworkLease(root, operation)` uses atomic creation of a private `.artwork-retention-lease` directory as a **cooperative cross-process exclusion marker**. The local prototype's artwork publication, design creation, revision append, and read-only retention inventory all participate. An existing lease is waited on for up to three seconds and then fails closed. A stale/crash-left lease is **never automatically removed or stolen**. A symlink or non-directory lease is rejected. Release checks the lease's device/inode identity before removing its own directory; uncertain release leaves the storage blocked for operator review. In a race where the lease disappears between an `EEXIST` response and inspection, acquisition safely retries.

This closes a previously unguarded race between cooperating prototype writers and the two-pass inventory: while inventory runs, participating writers cannot create an artwork or saved design revision. Conversely, an inventory waits for a participating writer to finish. A real separate Node process is used in the regression tests to exercise the filesystem exclusion behavior.

## Safety boundary

This is **not** a production distributed lock, lease with verified owner identity, durable fencing token, or global proof that all processes honor the protocol. Uncooperative filesystem writers, manual file changes, network filesystems with unsuitable semantics, and malicious local actors remain outside the guarantee. A process crash can leave a lock requiring deliberate offline investigation; operators must not remove it without determining whether a writer is still active. There is no automatic repair, quarantine, reclamation, or deletion. The inventory always returns `safeToAutoDelete:false` even when it reports apparently unreferenced artwork. Actual quarantine would require a separate, explicit operator-authorization and storage reference-pin protocol and stronger writer fencing.

## Verification

`node --test tests/objective35v-cross-process-artwork-lease.test.mjs`

`npm test` or the complete test suite partitioned into independently logged nonoverlapping batches. The test suite exercises competing callers, actual child-process contention, lock abandonment, symlink/file attacks, replacement, failure cleanup, inventory exclusion and local saved-design writes. This work is offline-only and does not modify any Shopify theme, product, customer, checkout or order.
