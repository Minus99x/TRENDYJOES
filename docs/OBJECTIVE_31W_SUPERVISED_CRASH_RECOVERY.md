# Objective 31W — externally pinned supervised recovery of uncertain commits

**Scope:** offline Linux local prototype only. No Shopify access, deployment, customer records, production manufacturing, or network calls.

## Implemented

`createOfflineExportReceiptCutoverRegistry(...).reconcilePending({kind,decision,expectedBeforeHead,expectedAfterHead,expectedTransitionDigest,expectedPendingDigest,nowMs})` adds a deliberately **manual** recovery operation to Objective 31V. A trusted external supervisor must obtain and durably preserve the intended receipt-head pin, signed transition digest, and SHA-256 digest of the exact canonical pending record **outside the local registry directory**, and must independently authorize either:

- `abort-unlinked`: only when the pending file has no committed hardlink. The signed pending body is verified against external pins and the old complete signed history is reverified. It removes the pending marker and leaves the old receipt head unchanged. This is **not** permitted once the destination exists.
- `finalize-linked`: only when the pending file and committed destination are the same two-link inode, with matching canonical pinned bytes. The complete committed history and relevant epoch signatures are reverified *before* marker removal. The externally pinned after-head must match exactly; no missing committed record is synthesized.

Both decisions acquire the original Objective 31V Linux OS `flock` lock, verify owner-only directory and files, reject symlinks, extra hardlinks, wrong inode, changed pending bytes, stale head, wrong policy, tampered signatures and unrecognized filesystem entries. The marker is unlinked only after full pre-verification, followed by directory fsync and complete post-verification. The returned object remains read-only and explicitly denies production authority. A crash after the final fsync leaves the same independently pinned history, with no marker. Existing `inspect`, `cutover`, and `append` remain fail-closed on pending markers; **no automatic recovery** is introduced.

## Trust boundary and unresolved work

A supervisor must actually retain trusted pins externally before reconciliation. Pins supplied by the compromised directory itself are not independent evidence. The API cannot prove that the caller obtained pins independently, or that an authorized human reviewed the pending bytes. Pending-append recovery re-verifies signed historical receipts and hash chains, but does **not** independently re-fetch or re-validate the underlying acquisition archive bytes. Same-UID malicious processes, privileged adversaries, remote filesystems, witness-key custody, trusted timestamps, offsite retention, and multi-resource atomicity remain out of scope. **Durable arbitrary multi-epoch policy rotation is not implemented**; this remains a one-transition registry. No hosted authentication or manufacturing approval is implied.

## Tests

```sh
node --test tests/objective31w-supervised-pending-recovery.test.mjs
node --test --test-concurrency=4 tests/*.test.mjs
```

The focused tests cover both pre-hardlink abort and post-hardlink finalization for cutover and receipt append; forged/missing pins; stale head; tampered, symlinked and hardlinked files; forged destination substitution; duplicate recovery; post-recovery replay and stale writer rejection; independent child-process `SIGKILL` at cutover/append/recovery boundaries; and two concurrent independent Node processes attempting the same reconciliation.
