# Objective 33D — pinned multi-transition authority history (offline)

Version v0.30.57. No Shopify access, customer data, secrets, external service calls, production authorization, or deployment.

## Purpose and contract

`src/offline-conflict-authority-history.mjs` exports `verifyOfflineConflictAuthorityHistory()` and `offlineConflictAuthorityHistoryNextHead()`. This **read-only verifier** accepts 2–8 consecutive 33C authority-policy rotations and recursively authenticates the complete underlying 33B signed namespace/observer rosters, 33A inventories, 32Z continuity and 32Y inspection transcripts through the existing 33C verifier. It requires exact independently retained genesis and terminal pins, a caller-supplied observation time, and an independently retained final history head. No network, persistence, signer, publisher or trusted time service is implemented.

Required verification arguments: `entries` (dense 2–8 array of exact `{transition,predecessor,successor}` records), `expectedNamespaceId`, `expectedJournalScopeDigest`, `expectedFirstEpoch`, `expectedPreviousTransitionDigest`, `expectedInitialAuthorityPolicyDigest`, `expectedInitialCommitmentDigest`, `expectedGenesisHead`, `expectedFinalAuthorityPolicyDigest`, `expectedFinalCommitmentDigest`, `expectedChainHead`, `nowMs`. Each entry's 33C predecessor and successor verification must independently carry complete authenticated evidence, and 33C re-verifies all signatures. The chain enforces strict adjacent epochs, predecessor transition digest, authority-policy digest and commitment digest equality across each link. The final head is domain-separated SHA-256 of `[schema,previousHead,transitionDigest,toEpoch,successorCommitmentDigest]` iterated from the independently pinned genesis head. The helper computes a **candidate** head, not evidence of publication.

## Fail-closed cases and test scope

41 new tests use actual Ed25519 signatures, three signed consecutive authority rotations (epochs 3→4→5→6), a real simulated interrupted local manifest journal and authenticated downstream transcript/inventory evidence. Negative tests cover missing external anchors, substituted initial/terminal pins, middle-link omission, truncated history, reverse order, duplicated transitions, sparse/oversized arrays, unexpected properties, malicious getters, forged predecessor/successor signatures, fully signed forked middle/terminal transitions, intermediate commitment rollback, skipped epochs, cross-scope substitution, tampered downstream commitments and expired rotations. `node --test tests/objective33d-authority-history.test.mjs` runs the focused tests; `npm test` runs the complete suite.

## Trust boundary

This verifier authenticates only the **provided** branch against **caller-supplied** independently authenticated anchors. If a malicious custodian re-pins both a fork and its terminal head, the verifier cannot detect globally inconsistent histories. Caller-supplied `nowMs` is not trusted time. No independent authority publication, offsite immutable retention, cross-host epoch monotonicity, global fork consensus, protected private keys, hosted customer authentication, Shopify checkout/order proof, manufacturing authorization, distributed recovery or repair is provided. No mutation is authorized by a successful verification result. Do not use these local tests as production proof.
