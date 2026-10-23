# Objective 33I — Portable signed pending-adjudication transcripts (offline)

**Scope:** Opt-in, offline-only. Extends 33H's read-only adjudication of an interrupted 33G acceptance record. No Shopify calls, production grant, mutation, repair, or remote witness.

## APIs

`src/offline-conflict-pending-adjudication-transcript.mjs` exports:

- `exportOfflineConflictPendingAdjudicationTranscript`: Takes the **result of an already executed** 33H `adjudicatePendingReadOnly` inspection, its dual-reviewer Ed25519 signed decision, both complete reviewer rosters, and a separately held observer Ed25519 signing key. It checks the 33H approval again and signs a canonical domain-separated observation body. Returns portable UTF-8 JSON bytes and a domain-separated SHA-256 digest. Signing keys are not serialized.
- `verifyOfflineConflictPendingAdjudicationTranscript`: Parses exact canonical bytes (strict UTF-8, no duplicate/extra keys or field reordering), checks the independently supplied transcript/namespace/scope/decision/reviewer/pending/pre-head/observed-head/observer identity/key pins, checks both 33H signature quorums, the 33H decision validity at the claimed observation time, the observer Ed25519 signature, bounded expiry against **caller-supplied** time, and optional caller-maintained replay lists. Returns an explicitly non-authorizing read-only verification result.
- `reconcileOfflineConflictPendingAdjudicationTranscripts`: Independently verifies two pinned transcripts, requires distinct observer identities **and public keys**, and rejects divergent decision, scope, pending bytes, predecessor, state, or observed-head assertions. It returns only `consistent` or fails closed; it does not select a winner, repair pending records, or claim a distributed quorum.

## Reproduction

`node --test --test-name-pattern='^33I' tests/objective33e-authority-observer-reconciliation.test.mjs`

`npm test`

Adversarial cases include SIGKILL-created pending-only and pending-linked fixtures, forged observer signatures, signed decision tamper, omitted reviewer approvals, replayed digest/nonce, expired/future observations, substituted external pins, malformed/truncated UTF-8 JSON, duplicate/extra/reordered fields, forged snapshot claims, observer key reuse and read-only filesystem nonmutation.

## Trust boundaries / remaining gates

**Critical:** A signed transcript authenticates **an observer's assertion about a prior local 33H result** and the independently signed inspection decision. It does not independently reconstruct the local 33G filesystem snapshot on the receiving host, prove the observer actually executed 33H, guarantee every historical event was observed, or establish an independent witness. The signer may be compromised or dishonest. The caller must obtain cryptographic pins and observer public keys independently, not by trusting the same unverified transcript.

Time is caller-supplied, not trusted. Replay lists are caller-maintained and are not persistent across processes. The verifier does not publish anchors, protect private keys, prevent global forks, or coordinate distributed atomic recovery. Hosted authentication, real checkout/order verification, approved manufacturing geometry/GLBs and deployment remain separate unresolved gates.

**Shopify reads/writes: NONE. Production deployment: NONE.**
