# Objective 29 — Signed offline encrypted-registry backup and no-clobber restore

**Local Linux single-host test fixture only. No Shopify writes, deployment, hosted auth, customer data, checkout, or production recovery.**

## Contracts

- `computePrivateRegistryBackupDigest(action,request)` accepts exactly `export-backup` or `restore-backup` and canonical, strict requests. The action-specific SHA-256 digest is **not** a permission grant.
- `exportAuthenticatedBackup({operatorToken,permit,request})` requires configured `adminAuthorization`, AES-256-GCM encryption, a verified operator session, an Ed25519-signed action-specific permit, and exact independent anchor equality. It checks every encrypted historical asset, including revoked ones, using the configured key resolver. It returns an in-memory `TJ-OFFLINE-PRIVATE-REGISTRY-BACKUP-1` bundle containing a SHA-256 digest, the exact authenticated registry snapshot bytes (base64), anchor, sorted historical key-ID inventory, and counts. It does **not** write backups to disk, transfer to cloud, certify durability, or consume a replay ID (read-only exports may be repeated while valid).
- `restoreAuthenticatedBackup({operatorToken,permit,request,backup})` requires an independent operator and a distinct signed `restore-backup` permit binding **exact backup SHA-256, independent expected anchor, registry identity, and a fresh operation ID**. It validates strict bundle shape, byte hash, HMAC, snapshot structure, all encrypted assets, historical keys, revision and revocation counts, and the external anchor. It restores **only when the local registry file is missing**. It never overwrites a present file, including a symlink. A no-clobber hard link installs the restored state; the restore op ID is consumed in a newly anchored transaction with an incremented sequence. Concurrent or replayed restoration fails closed.
- Crash **before** destination creation allows retry with an unexpired signed permit. Crash **after** creation but before anchor CAS blocks normal operations until separately signed `recoverInterruptedRegistry` catches up the independent anchor. Restoration cannot recover an old backup after any newer mutation/revocation/rotation; the independent anchor must still match the exact backup. Never bypass this requirement or manually roll back the anchor.

## Security boundaries

- Backup bundle includes **ciphertext and sensitive identity/metadata**, not raw encryption keys. Keep the bundle confidential; no transport, backup-at-rest encryption envelope, offsite retention, deletion/secure erase, restore audit logging, or key escrow is implemented.
- The caller must separately preserve **all** historical AES keys, the HMAC secret, the independent trusted anchor, and the operator signing/verification trust. Missing or wrong keys fail closed. Key retirement remains **unsafe** without externally verified backup lifecycle evidence.
- Signed permits expire within 15 minutes and are verified against an independent operator session and the exact action. The issuer must independently inspect the backup and anchor before signing; this code does not implement that issuer.
- Single-host `flock`, filesystem permissions, and independent-anchor adapters are offline abstractions, not multi-host transactional guarantees. External anchor CAS and local filesystem updates are not one distributed atomic operation.
- Restore is for **missing-file disaster recovery only**, not reconciliation, merge, rollback, or restoring an older snapshot. When an external anchor has advanced beyond the latest backup, manual independently authorized recovery of the missing history is required; this fixture refuses to fabricate it.
- `adminAuthorization` remains optional for legacy local fixtures. Never expose unconfigured instances or backup APIs to untrusted callers. No physical manufacturing, GLB approval, pricing, or checkout is authorized by a backup.

## Reproduction

```sh
node --version
node --test tests/objective29-signed-backup-restore.test.mjs
npm test
```

All tests use synthetic local PNGs, keys, sessions, and an in-memory anchor. No network traffic or Shopify writes are needed.
