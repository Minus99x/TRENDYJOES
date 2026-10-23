# Objective 32I — Signed witness-checkpoint ancestry and auditor rotation (OFFLINE)

The opt-in `verifyOfflineWitnessCheckpointAncestry` consumes a caller-supplied independently retained starting anchor, a caller-supplied independently retained terminal anchor, and **all** intervening 32H checkpoint bytes plus full 32G evidence for each bounded window. It verifies signed checkpoints and witness evidence rather than trusting only locally recomputed hashes. Sequence ranges, receipt heads, prior checkpoint hashes, registry/genesis identity and monotonically reported times must be contiguous across every window; the terminal checkpoint must match the complete independently supplied terminal anchor. A missing intermediate window, stale/forked terminal, or forged evidence fails closed. Maximum 16 windows per call; each 32H window is bounded to 32 witness receipts.

Auditor policy rotation is opt-in via `offlineWitnessCheckpointAuditorTransitionSigningBytes` and `offlineWitnessCheckpointAuditorTransitionDigest`. Each transition binds registry, genesis, first sequence of the new window, prior signed checkpoint and receipt, old/new policy digests and an issued-at value. It requires sorted, distinct Ed25519 **majority quorums from both old and new auditor policies** and an independently supplied exact transition digest pin. The new signing keys must be disjoint from every previously seen auditor key in the supplied chain; earlier policy digests cannot recur. Unauthorized or unexplained policy changes, reused keys, forged transition signatures and altered pins fail closed.

**Security boundary:** `verifyOfflineWitnessHistoryCheckpoint` (32H) expects the auditor policy digest in the preceding anchor to equal the candidate policy. After 32I validates a dual-majority rotation, it passes a derived policy-adjusted anchor to 32H **only for that one policy equality check**. The original anchor's registry, genesis, sequence, receipt head, checkpoint digest and timestamp are preserved; 32I independently checks every rotation binding before this adaptation. No externally stored anchor is modified.

**Crucial limits:** The verifier does not contact or establish an independent witness, trusted clock, transparency log, monotonic authority, HSM or immutable archive. The caller can lie about independent pin custody. Even valid quorums may sign competing successors to the same anchor. This is bounded offline evidence verification, **not** proof of globally unique history or deployed independent publication. No hosted customer identity, manufacturing authorization, Shopify checkout, order processing, remediation, or production deployment. All authorization and production flags remain `false`. Never expose this local verifier as a production endpoint or use its results to enable selling.

Reproduce using Node >=20:

```sh
node --test tests/objective32i-checkpoint-ancestry.test.mjs
npm test
```

Next possible objective: independently pinned multi-epoch terminal consistency proofs / adversarial witness split-view and operator-controlled policy-rollback recovery. A deployed external monotonic anchor service remains a separate unsatisfied production gate.
