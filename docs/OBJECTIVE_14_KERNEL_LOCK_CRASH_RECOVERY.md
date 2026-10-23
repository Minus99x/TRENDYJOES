# Objective 14 — Linux kernel-lock crash recovery (offline, opt-in)

**Status:** Local synthetic test fixture only. No Shopify access, hosted authentication, production storage, or manufacturing authority.

## Defect and implementation

The v0.13 `mkdir(.atomic-lock)` critical section can remain permanently locked when its owning process is terminated with SIGKILL. Blindly deleting the directory after a time threshold is unsafe: a live but paused owner may resume and write concurrently. PID files and mtime alone do not solve fencing or PID reuse.

`createOfflineDurableLedger({directory, lockMode:'kernel'})` now offers a Linux-only alternative. It opens the persistent `.atomic-lock` **regular file** with `O_NOFOLLOW` and 0600 permissions, checks one link and the opened inode against the pathname, and requires a process-owned directory not writable by group or others. It invokes the fixed `/usr/bin/flock` binary on inherited descriptor 3; the Node parent retains the **same open file description** after the helper exits. The kernel holds the exclusive advisory lock until Node closes the descriptor, including automatic release on SIGKILL. A second writer must acquire the lock before loading and mutating `ledger.json`. The lock pathname is never deleted automatically or on successful release.

The pathname is deliberately the **same** `.atomic-lock` used by the old `mkdir` mode. A v0.13 process cannot acquire a directory lock when the new file exists; new mode refuses to operate on an old directory lock. This is fail-closed cross-version exclusion, **not** a live migration. Run only on a trusted local filesystem that implements `flock` correctly. It is not suitable for NFS, multi-host coordination, shared/untrusted scratch directories, or Windows. All write entry points share the selected mode, including design CAS, nonce claims, webhook claims, lineage transitions and atomic receipt commits. The original `mkdir` mode remains the default for backwards compatibility.

## Operational recovery

For a **kernel-mode** ledger, leave `.atomic-lock` in place forever. When the owner dies, the OS releases the lock automatically; a subsequent writer obtains the same inode and can inspect/retry idempotently. If the owner remains alive, contenders time out and **must not steal** the lock. If a pre-existing `.atomic-lock` **directory** is present from v0.13, the kernel-mode adapter rejects it. An operator must stop all processes using the directory and investigate before any manual migration; do not script deletion of a possibly live lock. Do not unlink or replace a kernel lock file: a second inode could admit concurrent writers.

Crash outcomes depend on rename: a kill before rename preserves the old `ledger.json`, and a kill after rename leaves the committed snapshot; retries use existing idempotency checks. The temporary `.pending-*` file from a killed writer may remain and is not used as ledger authority. Never infer that process termination implies physical power-loss durability or that a successful synthetic order proves payment/fulfillment.

## Reproduction

On Linux with `/usr/bin/flock`, Node 22.16.0:

```bash
node --test tests/objective14-kernel-lock.test.mjs
npm test
```

Tests cover SIGKILL before/after rename, live-lock timeout, post-death recovery, nine competing Node processes, legacy-mode exclusion, stale directory rejection, symlink/hardlink/path permission rejection, state corruption, and mode validation.

## Remaining gates

No distributed transactional datastore or consensus/fencing across hosts; no hosted identity, KMS, real Shopify checkout/webhook/payment, physical calibration, GLB manufacturing approval, pricing, inventory, or fulfillment authority. Production adoption requires a proper transactional backend and operations review. `lockMode:'kernel'` is an offline Linux development option only.
