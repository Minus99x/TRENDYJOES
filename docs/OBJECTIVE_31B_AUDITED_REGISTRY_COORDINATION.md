# Objective 31B — Fail-closed registry mutation / independent audit coordination (OFFLINE)

**Scope:** opt-in local prototype only. No Shopify access, hosted identity, production key custody, distributed transaction guarantee, offsite audit retention, checkout/payment, or manufacturing approval.

The `src/offline-audited-registry-coordinator.mjs` module wraps authenticated private-registry mutation methods with a **separate single-host Linux flock**, checks the independent journal head against the registry head before mutation, executes an existing signed-authenticated registry operation, and requires a fresh independently authorized `exportAuthenticatedAudit` envelope for the exact new registry anchor. It appends a SHA-256-linked event to the existing Objective 31A audit journal and independently checks both heads before returning success. It rejects unlisted/legacy actions and missing signed audit providers. All previously supported editor and manufacturing APIs are unchanged.

## Supported authenticated mutation operations

`commitAuthenticatedRevision`, `revokeAuthenticatedArtwork`, `revokeAuthenticatedRevision`, `migrateAuthenticatedArtwork`, `rotateAuthenticatedArtworkKey`, `restoreAuthenticatedBackup`, and `recoverInterruptedRegistry`. Each action is delegated to the original v0.30 authenticated registry implementation, which enforces its own signed permits, identities, revision constraints, revocation rules and replay checks. The coordinator **does not issue** these permits. The audit provider signs `export-audit` for the post-mutation anchor; no automatic signing or privileged fallback is supplied.

## Crash and recovery matrix

| Failure point | Durable evidence | Required action |
|---|---|---|
| Before registry rename | Registry unchanged | Retry with a fresh valid signed request (subject to underlying operation-ID policy). |
| Registry rename but before registry anchor CAS | Registry file ahead of registry anchor; journal unchanged | Independently signed `recoverInterruptedRegistry` through coordinator, then signed audit append. |
| After registry anchor CAS but before journal file | Registry anchor ahead of journal | `reconcile` with independent Ed25519 permit for **exactly one** sequence step plus operator-signed audit export. |
| After journal file fsync but before journal anchor CAS | One pending journal file, independent journal anchor unchanged | Existing journal's separate Ed25519 `recoverInterruptedAppend` permit through `recoverJournal`; verify current registry anchor. |
| After both anchors committed but before response | Both anchors already match | Reinspect and continue; replaying the consumed mutation opId remains prohibited. |
| External mutation skips more than one registry sequence | Journal history gap | Fail closed; **no fabricated catch-up**. Escalate to independent investigation. |

An existing legacy registry cannot silently enroll into a clean journal. `bootstrap` requires an independent Ed25519 permit binding the exact current registry anchor and empty journal. The first event always records `BOOTSTRAP_UNPROVEN_PRIOR_HISTORY`, never an assertion about previous history. Subsequent event sequence and `previousMac` continuity are checked by the 31A journal. A signed reconciliation permit is domain-separated (`TJ-OFFLINE-AUDITED-REGISTRY-COORDINATOR-RECOVERY-1`), action-scoped, registry-bound, exact-head-bound, and valid for no longer than fifteen minutes. Replay is blocked by the changed head; recovery cannot rewrite previous events or revocations.

## Example integration shape (trusted offline fixtures only)

```js
import {createOfflineAuditedRegistryCoordinator} from './src/offline-audited-registry-coordinator.mjs';
const coordinator = createOfflineAuditedRegistryCoordinator({
  directory: '/private/local/coordinator',
  registry: authenticatedOfflineRegistry,
  journal: independentlyAnchoredOfflineJournal,
  registryId: 'trusted-registry-identifier',
  readRegistryAnchor: trustedRegistryAnchorRead,
  readJournalAnchor: trustedJournalAnchorRead,
  recovery: {publicKey: independentEd25519RecoveryPublicKey}
});
const result = await coordinator.execute({
  action: 'commitAuthenticatedRevision',
  envelope: existingSignedCustomerMutationEnvelope,
  auditEnvelope: async (postCommitAnchor) =>
    obtainIndependentlySignedOperatorAuditEnvelope(postCommitAnchor)
});
```

**Important limitation:** Two independent anchor updates are not a single atomic transaction. The coordinator returns success only after both complete, and otherwise blocks or requires independently signed recovery. Other code that retains a direct registry reference **can bypass** the coordinator. The module cannot prevent external direct writes, compromise of injected anchor callbacks, forged issuer infrastructure, same-UID filesystem attacks, multi-host races, or omitted writes that do not change the registry state. This is a *cooperative opt-in fail-closed integration seam*, not a guarantee that every historical mutation is observed. Production integration must restrict registry mutation access to the coordinator, use genuinely independent durable anchor services and protected signing keys, and formally review cross-service failure handling.

## Evidence

- Previous verified release: v0.30.1 Objective 31A, 939/939 tests.
- Objective 31B targeted tests: 29, including signed authenticated revisions and revocations, cross-instance concurrency, a real separate-process flock contender, untrusted issuer/permit failures, signed legacy bootstrap, registry after-rename crash/recovery, after-registry-commit crash/reconciliation, pending journal fsync recovery, signed backup restoration, replay and rollback/gap protection.
- No new dependencies, no Shopify requests or writes.

Reproduce: `node --test tests/objective31b-audited-registry-coordination.test.mjs && npm test`.
