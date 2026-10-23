# Objective 33E — Independently pinned signed observer-history reconciliation

**Offline only.** `src/offline-conflict-authority-observer-reconciliation.mjs` verifies two distinct Ed25519 observer attestations to full 33D authority histories. Each observer's public key **and signed-attestation SHA-256 digest must be authenticated and retained independently of this module**. The verifier does not publish those anchors, provision keys, or establish a trusted clock.

## Verification contract

- `offlineConflictAuthorityObserverBodyBytes(body)` produces domain-separated UTF-8 bytes to sign with the observer's Ed25519 key. The body binds namespace, journal scope, first epoch, initial policy/commitment, predecessor transition, genesis, final policy/commitment, terminal chain head, transition count, observed time, expiry and nonce. Strict exact-field validation rejects accessors and unrecognized production/repair claims. The signed view has a maximum one-hour caller-supplied validity window.
- `offlineConflictAuthorityObserverAttestationDigest(attestation)` produces a domain-separated SHA-256 digest over signed body bytes and the signature; this is a **candidate independent anchor**, not a publication service.
- `verifyOfflineConflictAuthorityObserverReconciliation({views,observerPins,...})` requires exactly two sorted, distinct observer identities with independently pinned Ed25519 public keys and attestation digests. It verifies each signature, exact externally supplied genesis/scope/initial anchors, history/attestation binding and each entire 33D history. The 33D verifier recursively authenticates dual-quorum 33C rotations, 33B signed namespace rosters, 33A inventories and 32Z/32Y transcripts.
- Outcomes: `consistent` means both authenticated views contain the same transitions; `extension` means one view is a valid prefix of the other; `equivocation` means both fully signed histories contain conflicting authority transitions at a common predecessor. For equivocation, the result contains frozen textual snapshots of both conflicting signed transitions and both observer attestations, their digests and fork index. These are portable **evidence for review**, not a consensus choice or authority to repair.

## Threat-model limitations

Both observer key and attestation digest pins must originate outside the potentially malicious evidence custodian. If an adversary can replace both external pins, the verifier cannot detect re-pinning. Distinct observer keys alone do not establish independent organizations or prevent key compromise. The module does not guarantee all observers are represented, global completeness, independent anchor publication, global fork prevention, protected signing keys, trusted timestamps, cross-host monotonicity, distributed atomic recovery, hosted authentication, approved manufacturing geometry, Shopify checkout, or production readiness. `nowMs` is supplied by the caller and is not a trusted timestamp. No Shopify reads/writes or network access occur.

## Offline verification

`node --test tests/objective33e-authority-observer-reconciliation.test.mjs`

`npm test`

The test fixtures create a real interrupted local journal, signed inspection transcript and inventory, 33B authority/observer rosters, three signed consecutive 33C rotations, plus independently signed observer views. Adversarial cases cover signed middle/terminal forks, valid extensions, omission, signed re-pinning attempts, forged signatures, cross-namespace substitution, malformed keys, expiry, unexpected fields, and malicious getters. These tests do not prove hosted authentication or global agreement.
