# Objective 30 — Cross-process registry coordination and authenticated audit snapshots

**Offline Linux single-host fixture only. No Shopify writes, hosting, deployment, checkout, manufacturing authorization, or real customer data.**

## Changes

- The existing `/usr/bin/flock` single-host advisory lock continues to serialize registry operations across Linux processes. Objective 30 adds **independent-process lock-contention tests** for signed audit export and signed missing-file restore. A timeout must not create a restore destination or advance the independent anchor.
- The critical section now binds both the lock file and registry directory to their original inode/device identities. It checks these after lock acquisition, before the durable rename/link, after asynchronous pre-write authorization, and before independent anchor CAS. This fails closed on detected pathname substitution; it is **not** a defense against a fully compromised same-UID process or all filesystem races.
- `AsyncLocalStorage` isolates each asynchronous lock holder's identity, preventing a timed-out concurrent call on the **same registry object** from erasing another call's lock context.
- `computePrivateRegistryBackupDigest('export-audit', request)` signs the same strict `opId` and expected-anchor shape as read-only backup export, but is cryptographically action-separated. It does not itself grant permission.
- `exportAuthenticatedAudit({operatorToken,permit,request})` requires the independently injected operator verifier, Ed25519 signed action-specific permit, a currently valid session, exact independent anchor, complete encrypted asset authentication, and the current registry HMAC. It returns counts and SHA-256 commitments to the **current** anchored state, immutable revision list, encrypted asset list, revocations, and consumed operation IDs, plus the current anchor and immediate `previousMac` link. It returns no artwork bytes, operator token, raw operation IDs, or signing key.
- This audit is an **authenticated current-state snapshot**, **not** a durable append-only event log, third-party timestamp, proof of all intermediate operations, or proof of offsite backup retention. Comparing consecutive externally retained snapshots can show immediate anchor continuity when no states were skipped; a single snapshot cannot establish missing history.
- Read-only audit export is repeatable with an unexpired signed permit; unlike restore it does not consume an operation ID.

## Security boundaries

- All identities, keys, signatures, and anchors in tests are synthetic; no production identity provider, key manager, distributed lock, durable offsite anchor, or trusted operator-signing service is present.
- Linux `flock` is advisory and applies only to cooperating processes using the same filesystem and lock inode. Do not deploy this fixture to multiple hosts or untrusted filesystem locations.
- The local state file is HMAC authenticated; the independently injected anchor detects rollback. A signed audit snapshot is not a substitute for retaining the independent anchor or for independently verifying an operator.
- A crash after local state installation but before anchor CAS still blocks normal operations until separately signed recovery. No automatic rollback or recovery bypass was introduced.
- Backup data remains ciphertext with sensitive metadata, and secure backup storage, retention, encrypted metadata, and key custody remain unimplemented.
- The legacy unconfigured registry remains a local-only fixture and must not be exposed to untrusted callers.

## Reproduce

```sh
node --version
node --test tests/objective30-audit-cross-process.test.mjs
npm test
```

26 adversarial tests exercise authenticated audit binding, expiry, forgery, authorization, anchor mismatch/outage, revocation/revision continuity, cross-process contention, lock/directory substitution, and same-instance lock-context isolation. Existing tests must also pass.
