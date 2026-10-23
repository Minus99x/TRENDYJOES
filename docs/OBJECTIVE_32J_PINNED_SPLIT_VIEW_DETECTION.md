# Objective 32J — Offline pinned checkpoint split-view and quorum-intersection evidence

**Scope:** Universal Studio, offline read-only evidence analysis. This module does not contact Shopify, publish checkpoints, operate a witness, deploy infrastructure, or authorize downstream activity.

## Entry point

`src/offline-witness-checkpoint-split-view.mjs` exports `verifyOfflineWitnessCheckpointSplitView({initialAnchor, observations})`. Provide exactly **two** observations, each `{terminalAnchor, entries}`. The `initialAnchor` is the shared Objective 32H anchor. Each observation includes a caller-supplied terminal pin and a **complete** 32I evidence chain (signed checkpoint bytes, 32G witness-history evidence, auditor keys/quorum/policy pin, and transition signatures/pins as required). Both branches are verified through `verifyOfflineWitnessCheckpointAncestry` *before* comparison. Missing, forged, stale, incomplete, out-of-order or noncanonical evidence fails closed; one valid branch never excuses an invalid branch.

The API returns a frozen, read-only object. It distinguishes:

- `IDENTICAL_AUTHENTICATED_PATH`: identical checkpoint digests in both supplied histories.
- `AUTHENTICATED_PREFIX_EXTENSION`: one fully authenticated path is a prefix of the other.
- `AUTHENTICATED_SPLIT_VIEW_DETECTED`: two authenticated branches extend the same predecessor checkpoint and receipt head but have **different signed successor checkpoint digests**. The report includes exact predecessor and conflicting checkpoint digests, sequence, auditor policy digests and intersection evidence.

### Cryptographic intersection

When competing signed successors use the **same pinned auditor policy**, the verifier checks their actually present Ed25519 signer identities and public-key digests. Because Objective 32H requires strict majorities, the intersection of two signing quorums is at least `2 * quorum - auditorCount`. At least one auditor must have signed both conflicting checkpoint bodies; the report identifies those signers. This is evidence of a shared signing key, **not** proof of who controlled that key.

When both branches present **different, valid, dual-majority auditor rotations** from the same authenticated predecessor, the verifier instead identifies the intersecting *outgoing* majority signers on conflicting transition bodies. These outgoing quorums share the predecessor's pinned auditor policy, so their intersection is likewise guaranteed. If one branch rotates and the other remains on the previous policy, the verifier reports competing authenticated successors but **does not invent a same-policy signing intersection**.

### Threat model and limitations

- A different grouping of identical witness receipts into differently signed checkpoints can constitute a *checkpoint-level* fork without proving different underlying receipt contents. Do not overstate it as underlying witness fraud.
- The comparison requires the same supplied root; it does not discover omitted third-party observations or independently prove that the supplied terminal pins were ever published. A consistent pair does **not** prove global uniqueness or absence of other forks.
- Two caller-supplied anchors are **not** independently published anchors. Timestamps are signed claims, not independently trusted time. A signature implicates a cryptographic key, not a particular person or independent organization.
- Evidence remains bounded by the 32I limits (16 windows per path, 32 witness receipts per checkpoint window). It does not replace protected keys, offsite immutable publication, independent witness infrastructure, production auth, manufacturing approval, checkout or atomic cross-resource recovery.
- All flags for external publication, global uniqueness, trusted time, checkout, remediation and production remain `false`. The module makes **no writes** and does not initiate any corrective action.

Reproduce with Node >=20:

```sh
node --test tests/objective32j-checkpoint-split-view.test.mjs
npm test
```

**Next engineering objective 32K:** bounded portable conflict-proof envelope with independently pinned evidence inventories and verifier-side omission/substitution rejection. Still offline only; actual independently hosted publication and trusted custody remain external gates.
