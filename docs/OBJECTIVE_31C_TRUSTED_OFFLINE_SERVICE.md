# Objective 31C — Trusted offline registry service / audit-guarded reads

**Scope:** OFFLINE opt-in prototype. No Shopify traffic, hosted customer identity, production keys, checkout, live orders, or manufacturing approval.

## Why this exists

Objective 31B's coordinator was opt-in, but callers that retained a raw registry reference could accidentally call unaudited mutation methods. Objective 31C introduces a **construction boundary**: `createOfflineAuditedRegistryService` creates the private revision registry, audit journal, and coordinator inside one closure and returns only an explicit frozen API. The raw registry, its unauthenticated legacy mutations, and the raw audit journal are never returned by this service.

### Exposed API

- `mutate({action,envelope,auditEnvelope})`: only seven preexisting authenticated mutation actions, all through the coordinator. The caller supplies existing independently signed customer/operator permits and a separately signed audit-envelope provider. No implicit signing or bypass.
- `readArtwork({sessionToken,request})`: authenticated, identity-bound, encrypted-artwork read; checks independent registry and journal anchors before and after under the coordinator's single-host lock.
- `exportBackup({operatorToken,permit,request})`: existing operator-signed encrypted-backup export, likewise checked before and after; **sensitive ciphertext/metadata** must be retained privately.
- `inspect()`, `reconcile()`, `bootstrap()`, `recoverJournal()`: existing audited inspection and independently signed recovery interfaces.

Configuration requires an authenticated, encrypted registry with operator, customer, and recovery verification, matching registry identities, shared registry-anchor reader identity, shared journal-anchor reader identity, and separate journal/coordinator directories. Rejects injected raw registry/journal references and unexpected top-level configuration keys. The service exposes no `commitRevision`, `revokeArtwork`, `readPrivateArtwork`, or raw registry/journal handles.

The coordinator also gains an allowlisted `read` method that refuses any unapproved read operation, checks anchored continuity before the read, holds the cooperative lock throughout, and checks unchanged registry and journal anchors afterward. A known unaudited registry transition blocks reads and further coordinated mutations until separately authorized recovery. Read results are not released on a failed post-read check.

### Minimal trusted composition (no keys in code)

```js
import {createOfflineAuditedRegistryService} from './src/offline-audited-registry-service.mjs';
const service = createOfflineAuditedRegistryService({
  registryOptions: { /* private directory, HMAC key, encryption, authenticated issuer, CAS, recovery */ },
  journalOptions: { /* separate journal directory, independently stored CAS, recovery */ },
  coordinatorOptions: { /* private coordinator directory, independent anchor readers, recovery */ }
});
await service.mutate({action:'commitAuthenticatedRevision', envelope:signedMutation,
  auditEnvelope:postCommitAnchor=>obtainIndependentOperatorSignedAudit(postCommitAnchor)});
```

## Adversarial verification

Sixteen new tests cover: no raw mutation capability, configuration fail-closed, signed commit/read, cross-owner/variant denial, signed backup, direct-writer one-step and multi-step gaps, independently signed one-step reconciliation/replay, tampered journal events, unsigned mutation, simulated crash, forged audit, **external anchor-file rollback and substitution**, **actual separate Node process exit code 91 immediately after registry commit**, service reconstruction from disk, signed recovery and permanent revocation. All keys are ephemeral fixture keys; external anchor files are test-only and not production-grade storage.

## Limitations / security boundary

This is **capability isolation**, not OS sandboxing or complete mediation. A separate caller with raw registry HMAC/encryption keys and directory access can still construct the lower-level registry and mutate it. The tests demonstrate this bypass is *detected* when the registry anchor advances, not that it is prevented. The single-host cooperative lock cannot stop malicious same-UID writers, multi-host races, compromised injected callbacks, or all crash windows. The two independent CAS updates remain non-atomic. Signed recovery is required after interruption; no invented missing history is allowed. External anchor files used by tests are synthetic, not independently hosted durable services. Production needs a real trusted process boundary, durable independent anchor service, key isolation, retention, privacy review and end-to-end hosted authorization.

Main Engineering v0.32 remains a separate branch with preview color/size work; this Night Watch release does not merge or overwrite it.
