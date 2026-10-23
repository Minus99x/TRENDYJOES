# Objective 31J — Offline certified reviewer transitions and witness publication outbox

**Version 0.30.11 | TrendyJoes Night Watch | Offline only | No Shopify reads/writes**

This release extends v0.30.10 without changing its existing legacy verifier, durable publication store, editor, manufacturing, artwork, cart/order fixtures, or store data.

## 1. Explicit reviewer-policy transition certificates

`src/offline-forensic-transition-certificate.mjs` exports:

- `forensicTransitionSigningBytes(body)` — domain-separated canonical Ed25519 payload.
- `forensicTransitionPossessionBytes(body, oldApprovals)` — separate proof-of-possession domain bound to the outgoing signatures.
- `verifyOfflineForensicTransitionCertificate({...})` — checks one certificate.
- `verifyOfflineForensicPublicationTransitions({...})` — **opt-in** historical publication verifier requiring one certificate per actual reviewer-policy rotation.
- `verifyOfflinePublishedForensicEvidenceWithTransitions({...})` — opt-in composite forensic-evidence verifier plus certificates.

A certificate binds one exact registry, anchor type, previous publication digest, next publication digest, policy indexes/digests, 32-byte challenge, and issuance/expiry window (maximum 15 minutes). It requires a quorum of outgoing reviewer signatures **and signatures by every incoming reviewer key**. This proves that the incoming key holders possess signing authority in the synthetic offline model, not that they are trustworthy humans or that their keys are protected.

Certificates are caller-supplied and must be retained/pinned independently. The pre-existing v0.30.10 verifier remains available for archived evidence, but does **not** require certificates. New integrations requiring this protection MUST call the opt-in strict verifier.

Historical certificates remain verifiable after expiry: the certificate validity interval must include the publication's signed `publishedAt`. Because this timestamp is supplied by the signer, it is **not trusted time**. Future production deployments need independent time attestation and protected reviewer identities.

## 2. Durable witness publication outbox

`src/offline-forensic-publication-outbox.mjs` exports:

- `forensicPublicationAcknowledgementBytes(body)` — domain-separated acknowledgement payload.
- `verifyOfflineForensicPublicationAcknowledgement({...})` — validates majority witness signatures on an exact publication digest, index, registry and anchor.
- `createOfflineForensicPublicationOutbox({...})` — opt-in Linux single-host journal.

The outbox requires a separately configured v0.30.10 `publicationStore`. It maintains a durable, append-only chain of `PREPARE` and `ACK` records with sequence, previous digest, signed publication digest, signed publication timestamp, and acknowledgement. Every mutation is serialized using a persistent inode-checked kernel `flock`, writes a private `.pending.json` with `O_EXCL|O_NOFOLLOW`, fsyncs it, renames to the next numbered record, and fsyncs the directory.

**Safe ordering:**

1. Independently pin both current outbox and publication heads.
2. `outbox.prepare({record, expectedOutboxHead, expectedPublicationHead})` verifies the next signed publication against the current publication history and durably records the intent.
3. `publicationStore.append({record,expectedHead:expectedPublicationHead})` commits the signed publication independently.
4. Receive independently signed witness acknowledgement (synthetic in tests).
5. `outbox.acknowledge({acknowledgement,expectedOutboxHead,expectedPublicationHead})` validates majority signatures and durably appends `ACK`.
6. `outbox.reconcile({expectedOutboxHead,expectedPublicationHead})` returns `verified:true` **only** if the full publication chain and outbox chain match and all publications have acknowledged records.

A crash between any two steps remains **fail closed**: a prepared but absent publication is `FORENSIC_OUTBOX_UNCERTAIN_PREPARE`; a committed publication without acknowledgement is `FORENSIC_OUTBOX_UNACKNOWLEDGED`; a publication with no prepared intent is `FORENSIC_OUTBOX_ORPHAN_PUBLICATION`; an interrupted fsync/rename leaves a pending file requiring manual forensic review. There is no automatic retry, pending-file deletion, replay-permit reissue, or unsafe lock-file removal. Caller must retain trusted externally pinned heads; a locally derived head alone cannot detect a complete valid-prefix rollback.

## 3. Verification

Run from extracted release:

```sh
node --check src/offline-forensic-transition-certificate.mjs
node --check src/offline-forensic-publication-outbox.mjs
node --test tests/objective31j-transition-certificate.test.mjs tests/objective31j-publication-outbox.test.mjs
node --test --test-concurrency=4 tests/*.test.mjs
```

Tests cover forged/duplicate outgoing approvals, missing/forged incoming proof, stale/mismatched policy digests, expired certificates, domain separation, missing/duplicate witness acknowledgements, outbox CAS races, tampered/symlinked/gapped history, external pin rollback, and real child-process crashes at outbox and publication fsync boundaries.

## 4. Explicit unresolved gates

- This is **not** deployed independent witness infrastructure. A signed acknowledgement does **not** prove remote/WORM retention, physical independence, or third-party availability.
- Both stores are local Linux-only fixtures and are **not atomically committed together**. Reconciliation detects ambiguity and refuses success; it does not resolve uncertainty.
- Signing keys in tests are ephemeral and unprotected; there is no HSM, production key custody, trusted timestamp or certificate authority.
- The witness, reviewer policies, certificate history, and expected heads must be independently pinned by a trusted integration.
- No Shopify authentication, live checkout, payment, production design authorization, or manufacturing readiness is established.
- Main Engineering's separate v0.32 UI work is not merged here.

**Next:** 31K — portable, independently retained certificate/outbox evidence bundles and explicitly authorized forensic recovery of uncertain publication windows, without auto-retry or claiming distributed atomicity.
