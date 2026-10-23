# Objective 35AF — Offline pinned witness acknowledgements and portable fork evidence

**Development-only cryptographic contract. No hosted observers, Shopify writes, manufacturing approval, checkout, or deployment.**

`src/preview-local-artwork-review-witness-acknowledgements.mjs` adds:

1. `createOfflineWitnessAcknowledgement`: canonical domain-separated Ed25519 signature over an explicitly pinned witness ID, witness key fingerprint, 35AD registry/policy signer, signed predecessor and successor SHA-256, exact single-step revision, externally supplied 256-bit challenge and audience, and bounded issuance/expiry (maximum five minutes). This is a synthetic signing fixture, not independent witness custody.
2. `verifyOfflineWitnessAcknowledgement`: strict canonical byte envelope and Ed25519 verification against an **out-of-band pinned observer public key**; fail-closed trusted clock, expected challenge/audience/identity/revision checks; **mandatory external atomic** `consumeOnce(sha256-token)` callback to reject replays. Missing, failing, or ambiguous replay storage rejects the receipt. Caller must provide durable, cross-host atomic replay protection; this module cannot establish that from a local Set.
3. `inspectOfflineWitnessedPolicyFork`: reuses the Objective35AE verifier for two *policy-signer-valid*, different single-step successors of one independently pinned predecessor, then verifies signed receipts from two different pinned observers with different public keys and challenges. Both receipt bytes and all checkpoint bytes are snapshotted before asynchronous verification. The `portableEvidence` property is a canonical, self-contained transport envelope (excluding the separately pinned parent and trust configuration). One receipt can be consumed even if the second fails; callers must not treat failure as an accepted fork.
4. `verifyPortableOfflineWitnessedPolicyForkEvidence`: imports a canonical portable envelope with two signed candidate checkpoint byte strings and two witness receipts, recomputes its SHA-256, verifies the original parent and all pinned identities, policy signatures and witness signatures, and consumes replay tokens again. Portable evidence is *not* self-authenticating merely because it carries a digest; verifier-supplied pins are essential.

**Security boundaries:** The witness identities and signing keys in tests are synthetic and held in one local process. A malicious operator could fabricate both observers if key custody is not independent. A dishonest or non-atomic `consumeOnce` can accept replays. Trusted time, independent witness service endpoints, durable challenge issuance, independently retained observer key registry, consensus and external checkpoint retention remain unverified. Valid conflicting receipts are evidence of observed split-view, not a decision about which branch to accept. All APIs report `authorizesProduction:false` and `shopifyWritesAllowed:false` when applicable.

Verification commands:

```sh
node --test tests/objective35af-witness-acknowledgements.test.mjs
node --test tests/objective35aa-observer-head-receipts.test.mjs tests/objective35ab-observer-rotation-pins.test.mjs tests/objective35ac-rotation-lineage-revocation.test.mjs tests/objective35ad-policy-checkpoint-monotonicity.test.mjs tests/objective35ae-policy-head-cas.test.mjs tests/objective35af-witness-acknowledgements.test.mjs
npm run preview:assets:check
npm run preview:static:assets:check
npm run preview:staging:check
```

Run complete Node regression in disjoint bounded groups if a monolithic `npm test` is too slow; archive all command lines and TAP results. Do not conflate these tests with hosted authentication, production authorization or Shopify browser acceptance.
