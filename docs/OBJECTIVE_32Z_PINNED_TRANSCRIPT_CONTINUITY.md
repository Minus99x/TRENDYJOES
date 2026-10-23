# Objective 32Z — externally pinned, read-only inspection-transcript continuity

**Offline prototype only.** This module checks the consistency of a bounded sequence of Objective 32Y signed inspection transcripts for **one interrupted manifest claim**. It neither publishes nor creates an independent witness, trusted timestamp, global history, recovery receipt, or repair authorization.

## Usage and independently retained checkpoints

```js
import {
 calculateOfflineConflictManifestClaimContinuity,
 verifyOfflineConflictManifestClaimContinuity
} from './src/offline-conflict-manifest-claim-continuity.mjs';

// Each entry is a 32Y transcript and ALL externally retained verification pins:
// {bytes, expectedTranscriptDigest, expectedSnapshotDigest, decision,
//  reviewerGroupA, reviewerGroupB, expectedDecisionDigest,
//  expectedReviewerGroupADigest, expectedReviewerGroupBDigest,
//  expectedHead, expectedPendingBytesDigest}
const entries = [firstAuthorizedInspection, secondAuthorizedInspection];
const candidate = calculateOfflineConflictManifestClaimContinuity({entries});
// An independent trusted party MUST preserve candidate.head out-of-band.
// Merely calculating it from the entries being checked is NOT independent proof.
const verified = verifyOfflineConflictManifestClaimContinuity({
 entries, expectedHead: independentlyRetainedFinalCheckpoint,
 expectedPreviousHead: independentlyRetainedPriorCheckpoint // optional, strict prefix
});
```

Every entry is reverified using Objective 32Y's canonical byte parser, its independent transcript/snapshot/policy/decision/head/pending-byte pins, and both Ed25519 reviewer-majority quorums. A domain-separated SHA-256 chain commits to the exact order, entry count, transcript digest, snapshot digest, decision digest, caller-provided observation time, observed state, and observed journal head. The genesis commits to the claim's prior journal head, pending index/digests, and reviewer-policy digests. The independently retained final checkpoint is mandatory; an optional prior checkpoint must match the exact prefix at its recorded count. At most 64 entries are allowed.

Continuity rejects missing or altered externally pinned entries, forked claim identity, duplicate signed decisions, non-increasing observation times, and transitions from `linked-pending` back to `pending-only`. It permits multiple `pending-only` observations followed by `linked-pending` observations for the same claim. The code does not mutate the local journal or perform automatic recovery, clearing, retrying, checkout, production, or Shopify actions.

**Limits:** All observation times are caller supplied and can be dishonest. Strict increasing timestamps are a *consistency rule*, not proof of real chronological order or independent concurrent-snapshot serialization. A verifier cannot detect an omitted historical observation unless an independently preserved checkpoint commits to it. A complete chain cannot prove that all events in the world were observed. Hostile privileged filesystem mutation, compromised reviewer keys, external publication, durable offsite anchoring, distributed atomic recovery, hosted identity and production readiness remain unresolved.

Run `node --test tests/objective32z-manifest-claim-continuity.test.mjs` and `npm test`. Tests use synthetic Ed25519 keys and local temporary journals; no external network access is required.
