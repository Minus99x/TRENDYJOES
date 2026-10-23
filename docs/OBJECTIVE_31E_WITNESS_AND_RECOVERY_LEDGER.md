# Objective 31E — independently signed offline witness + one-time recovery ledger

**Night Watch v0.30.5; opt-in Linux-only local test infrastructure.** Nothing in this module constitutes hosted/offsite custody, a production authorization service, Shopify integration, or a secure machine deployment. Main Engineering's separate v0.32 UX release is not included or modified.

## Trust and threat model

`src/offline-recovery-witness.mjs` provides `verifyOfflineWitnessQuorum` and `createOfflineWitnessedRecoveryGuard`. It accepts at least two **distinct** pinned Ed25519 witness public keys and a strict-majority quorum. Every witness must implement `readLatest({challenge,registryId,anchorType})` and sign a **fresh caller-generated 256-bit challenge** in a canonical `TJ-OFFLINE-ANCHOR-WITNESS-1` receipt. The receipt binds witness identity, registry, anchor type, committed event count, current history digest, exact current anchor, issued/expiry times (max five minutes), and challenge. Unknown fields, key reuse, identity duplication, invalid signatures, stale/wrong anchors, inconsistent histories and replayed responses fail closed. A concurrent anchor change during the asynchronous witness read is detected by a second local snapshot inspection. All configured witnesses are required to respond; quorum alone does not override a conflicting signed response.

A trusted independent witness must itself maintain an authenticated **monotonic latest head**, with its signing key protected independently of the local host. This release supplies only an interface and synthetic, process-local witness fakes for tests. It **does not** provide or verify offsite custody, witness publication or distributed consensus. If the witness serves an old but freshly signed head, this module cannot detect that independently. Challenge binding prevents replaying a cached signed receipt from an earlier request, not malicious re-signing of stale state by a compromised witness.

`src/offline-recovery-authorization-ledger.mjs` provides `createOfflineRecoveryAuthorizationLedger({directory,registryId,anchorType,lockTimeoutMs,injectFault})`. The append-only, hash-chained, fsync-backed local ledger records the exact authorization ID, SHA-256 of the complete signed permit, and pending-byte digest. Cooperative Linux `flock` serializes reservations across processes. It refuses duplicate IDs or permit hashes, torn pending entries, gaps, altered records, unsafe files and lock tampering. `inspectPinned({count,headDigest})` compares against an **externally retained** exact head; without that independent pin, a privileged actor can roll the entire ledger back to a valid earlier prefix. A reservation is committed **before** any anchor recovery attempt; a crash after reservation burns the permit rather than blindly retrying. A crash during reservation leaves an unresolved pending record that blocks all ledger operations until separate forensic recovery tooling exists. **No automatic deletion/repair of reservation pending files is implemented.**

`src/offline-durable-anchor-adapter.mjs` adds two read-only seams: `inspectRecoveryState()` reports the last committed anchor and SHA-256 of pending bytes without making normal pending-state reads available; `validateRecoveryAuthorization(permit)` checks the independent Ed25519 signature/expiry without changing state. `createOfflineWitnessedRecoveryGuard({adapter,ledger,registryId,anchorType,witnesses,quorum})` offers `readVerified()` and `recoverOnce({authorization})`. Recovery checks the permit signature, exact pending digest/committed head, fresh independent witness quorum, second snapshot continuity, then burns the authorization ID in the ledger before calling the existing signed anchor recovery. Invalid signatures and stale witnesses do not consume permits; a failure **after** reservation does consume the permit conservatively. Committing a pending anchor requires witness re-attestation before a subsequent trusted read. This wrapper is opt-in; direct use of the lower-level anchor adapter still bypasses its extra protections.

## Remaining hard gates

1. Production witness service(s), independently protected keys, monotonic current-head custody, and independent replay-ledger pinning are absent. All tests use disposable keys and local fakes. Neither the witness keys nor ledger are protected against privileged host compromise or full local rollback.
2. The adapter and witness guard are not yet enforced as the sole OS/process-level path to anchor reads and recovery. Direct lower-level callers remain available; production complete mediation is **not** established.
3. The ledger and anchor are not one atomic transaction. The design intentionally burns a permit on an ambiguous failure; it cannot promise liveness after a crash without a separate, independently signed operator reconciliation workflow. Multi-anchor registry/journal coordination remains non-atomic.
4. Single-host Linux `flock`, filesystem permissions, and fsync do not establish remote distributed consensus or tamper-proof/WORM storage. A forged/compromised witness that re-signs stale data defeats the trust premise. The witness call itself does not provide a secure transport.
5. No real customer auth, approved manufacturing calibration, cart/checkout, payments, production key management, Shopify writes, or deployment.

## Reproduce

```sh
node --check src/offline-durable-anchor-adapter.mjs
node --check src/offline-recovery-authorization-ledger.mjs
node --check src/offline-recovery-witness.mjs
node --test tests/objective31e-witness-replay.test.mjs
node --test tests/objective31d-durable-anchor.test.mjs
npm test
```

The 31E tests cover signed quorum verification, independent rollback pins, challenge replay, expired/forged receipts, duplicate keys/IDs, witness unavailability, concurrent mutation, local ledger tamper and valid-prefix rollback, in-process and two-process permit races, real child-process crash, signed abort/commit recovery, and fail-closed ambiguous results. Test success proves these synthetic contracts only.
