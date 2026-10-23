# Objective 33B — Offline signed namespace and complete observer-roster commitments

**Scope:** Universal Custom Design & 3D Product Studio only. This is a local, read-only evidence verification contract, not a Shopify integration, production authorization, trusted timestamp, remote witness, or hosted authentication.

## Threat model and design

Objective 33A authenticated each interrupted-claim transcript, then compared independently supplied observer inventories, but a caller could substitute an unauthenticated `journalScopeDigest`, observer name or roster. Objective 33B introduces a domain-separated Ed25519 commitment binding the exact namespace identifier, journal scope digest, monotonically *caller-pinned* epoch, 1-hour-maximum validity window, nonce, externally pinned authority-policy digest, externally pinned 33A reconciliation digest, and a complete sorted roster of 2–8 observers. Each observer entry binds its identity, canonical Ed25519 SPKI public key, 33A inventory digest and claim count. The signing bytes are `TJ-33B-NAMESPACE-COMMITMENT\0` followed by `JSON.stringify(body)` in UTF-8; JSON field order is part of this explicit signing contract.

A separately pinned authority policy contains 3–9 sorted unique Ed25519 authority identities/keys. A strict majority of these authorities **and every rostered observer** must independently sign the same complete body bytes. Authority keys cannot overlap observer keys. Each signature is strict canonical base64url Ed25519, and both signature arrays must be sorted and duplicate-free. The authority policy digest is domain separated and must have been retained through an independent trusted channel; calculating it from the untrusted candidate is not sufficient. Similarly, the expected namespace ID, scope, epoch, commitment digest, reconciliation digest and observer count must be retained externally and supplied separately. The caller-supplied `nowMs` is *not* a trusted timestamp.

The verifier then requires an exact observation set (no missing/extra/duplicate observers), matches each signed inventory digest and claim count, and re-runs the complete Objective 33A reconciliation verifier. That recursively re-verifies every supplied Objective 32Z/32Y Ed25519 transcript and its pinned history. Divergent but possibly legitimate concurrent observations fail closed; no chronology or repair is inferred.

## APIs

- `offlineConflictNamespaceAuthorityPolicyDigest(authorities)` calculates a **candidate** policy digest from sorted `{authorityId,publicKey}` entries; publish/retain the digest independently before trusting it.
- `offlineConflictSignedNamespaceBodyBytes(body)` validates and produces exact signing bytes for independent offline signing. No keys are generated or stored by the module.
- `offlineConflictSignedNamespaceCommitmentDigest(body)` calculates a **candidate** domain-separated commitment pin; independently retain it.
- `verifyOfflineConflictSignedNamespaceRoster({commitment,authorities,observations,expectedAuthorityPolicyDigest,expectedCommitmentDigest,expectedJournalScopeDigest,expectedNamespaceId,expectedEpoch,expectedReconciliationDigest,expectedObserverCount,nowMs})` performs full read-only verification.
- `inspectOfflineConflictSignedNamespaceMembership({...sameArgs,targetObserverId})` performs the same full verification first, then reports membership or nonmembership **only in this exact signed local roster**. It is not proof that no observer exists outside this local roster.

Commitment shape: `{body,authoritySignatures,observerSignatures}`. Body fields in canonical order: `{schema,namespaceId,journalScopeDigest,epoch,issuedAt,expiresAt,nonce,authorityPolicyDigest,reconciliationDigest,observers}`. Observer entries: `{observerId,publicKey,inventoryDigest,claimCount}`. Signatures: `{authorityId,signature}` or `{observerId,signature}`. Keys are canonical base64url DER SPKI Ed25519 public keys; private keys never enter verification arguments. Identifiers are 8–64 ASCII letters/digits/underscore/hyphen, and SHA-256 digests are lowercase hex.

## Verification and adversarial coverage

`node --test tests/objective33b-signed-namespace-roster.test.mjs` includes signed valid evidence built from an actual local interrupted manifest journal, synthetic Ed25519 signers, and full 33A/32Z/32Y verification. Negative tests cover forged/missing/reordered/duplicate signatures, insufficient authority majority, missing observers, altered inventory/counts, duplicate keys, authority-observer key reuse, malformed key encodings, unsigned membership claims, namespace/scope/epoch/reconciliation substitution, expired/not-yet-issued commitments, accessor and sparse-array inputs, and downstream tampered evidence. Run `npm test` for the complete original editor and offline security regression suite.

## Limits and remaining gates

A signature authenticates a namespace/roster claim **relative to a genuinely independent pinned authority policy**. This module cannot establish who should control that policy, prove the completeness of all real-world observers or claims, enforce global epoch monotonicity or replay protection across hosts, or publish an immutable anchor. The externally supplied clock is untrusted; protected private keys, trusted timestamps, independent publication, cross-host consensus, hosted customer identity, manufacturing geometry approval, and live Shopify checkout/order reconciliation remain unimplemented. No filesystem/network/Shopify reads or writes are made by this module; no repair or production permissions are granted.
