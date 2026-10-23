# Objective 31A — Independently anchored, append-only offline audit observation journal

**Experimental opt-in integration; OFFLINE ONLY. No Shopify API writes, production auth, customer data, deployment, or real external anchor service.**

This objective introduces `src/offline-anchored-audit-journal.mjs`. It uses the *existing real registry's* `exportAuthenticatedAudit(operator-signed-envelope)` method to collect signed-authorized, state-bound snapshot evidence, then durably creates a numbered, mode-0600 immutable-per-index event file under a separately permission-checked local directory. Each event contains a domain-separated SHA-256 digest of its canonical fields, the previous event digest, the registry anchor, registry `previousMac`, state/list SHA-256 commitments, and counts. It contains **no tokens, raw operation IDs, artwork ciphertext, GIDs, customer/owner IDs, or private keys**.

A **different** injected `readJournalAnchor`/`compareAndSetJournalAnchor` pair commits `{index,digest}` to an *independent* anchor. `readRegistryAnchor` must return the trusted registry anchor, not data supplied by the browser or request. All three callbacks must be backed by trusted services in any future deployment: the test suite's in-memory adapters are **not** durable and are not suitable for production. Append first fsyncs the individual event file and directory, then compares-and-sets the independent head. A failed CAS, anchor outage, or crash between disk and CAS leaves a pending file and blocks future appends; it never silently rewrites or drops an event. A separately signed Ed25519 operator recovery permit can advance **one** independent head only when the complete pending chain matches the expected previous head and the current independently read registry anchor exactly matches its target. Repeated, forged, expired, or wrong-target recovery is rejected.

## Historical proof boundary

- The **first** event may bootstrap from an already valid v0.29/v0.30 registry state at any registry sequence. It is permanently labeled `BOOTSTRAP_UNPROVEN_PRIOR_HISTORY`: no past audit trail is claimed, and existing `previousMac: null` legacy state is eligible for initial bootstrap only.
- After bootstrap, every subsequent journal event must observe exactly the next registry sequence **and** matching registry `previousMac`. A skipped mutation or replay fails `AUDIT_HISTORY_GAP` rather than inventing an event. This includes normal revisions, revocations, encrypted key changes, signed backup restore, or a separately recovered registry write **if each mutation is observed in sequence**.
- The immutable event files can be **changed by a fully compromised same-UID actor**; the independent trusted anchor then detects deletion, truncation or rewriting of *anchored* history. The journal uses a Linux flock and fail-closed inode/path checks, **not** distributed consensus or a general defense against malicious filesystem participants.
- **Critical unfinished integration:** The journal does not automatically wrap or intercept registry mutations. If a producer mutates the registry without immediately appending a signed audit observation, the journal may lag; gaps are detected on the next append, not prevented at write time. An authenticated atomic mutation/audit pipeline or explicit two-stage durable coordinator is needed before claiming complete event coverage. Future independent anchoring and offsite retention services also remain outstanding.
- Signed authenticated audit export remains a *read-only state snapshot*. This journal demonstrates separately stored observations with contiguous sequence checks; it does not prove missing prior history, hidden intermediate states not observed, an untrusted issuer's honesty, secure offsite storage, a trusted timestamp, or production grade durability across machines.

## Offline API

```js
import {createOfflineAnchoredAuditJournal} from './src/offline-anchored-audit-journal.mjs';
const journal = createOfflineAnchoredAuditJournal({
  directory: '/private/local/journal', registry: secureOfflineRegistry,
  registryId: 'trusted-registry-identifier',
  readJournalAnchor: trustedIndependentJournalAnchorRead,
  compareAndSetJournalAnchor: trustedIndependentJournalAnchorCAS,
  readRegistryAnchor: trustedRegistryAnchorRead,
  recovery: {registryId: 'trusted-registry-identifier', publicKey: trustedEd25519PublicKey}
});
const observed = await journal.appendAuthenticatedSnapshot(validOperatorSignedAuditEnvelope);
const verified = await journal.verify();
// On a SINGLE pending event whose disk file was installed before journal-anchor CAS:
// await journal.recoverInterruptedAppend({authorization: independentlySignedRecoveryPermit});
```

**Never substitute untrusted callbacks, in-memory anchors, raw user inputs as snapshots, or application-held production signing keys.** The operator signs `export-audit` under the existing v0.30 registry permit format. Journal recovery uses independent `TJ-OFFLINE-AUDIT-JOURNAL-RECOVERY-1` domain-separated Ed25519 permits with exact expected/target journal anchors, issued/expiry time, authorization ID and reason. Not an authorization to recover or overwrite the registry itself.

## Verification

```sh
node --test tests/objective31-anchored-audit-journal.test.mjs
npm test
```

18 targeted tests include real registry signed export, authenticated revocation continuity, signed backup-restore continuity, legacy bootstrap labeling, forged permits, concurrent-anchor conflict simulation, crash-before-CAS signed recovery, tampered/missing/extra event detection, archive restart and sensitive metadata minimization. The prior 921-test suite remains intact, with no new dependencies.

## Next Stage 31B

Introduce a verified opt-in mutation-to-journal coordination layer and irreversible crash-state handling (including source registry recovery) before making **any** end-to-end uninterrupted audit-history claims. Independently test external anchor custody, offsite retained audit chains, process concurrency and adversarial race behavior. Preserve legacy compatibility and do not touch Shopify production.
