# Objective 35AD — signed policy checkpoints and retained-head verification

**OFFLINE / read-only / not Shopify-installed.** The code in
`src/preview-local-artwork-review-policy-checkpoints.mjs` adds a concrete
cryptographic and monotonicity boundary for the 35AC revocation policy. It
neither runs a registry nor grants any production authorization.

A checkpoint binds the exact 35AC revocation policy, its SHA-256 digest,
registry namespace, journal root pin, signing-key fingerprint and predecessor
checkpoint digest into canonical domain-separated Ed25519-signed bytes.
`createLocalReviewPolicyCheckpoint` returns portable bytes, hash and revision;
**creation does not publish, retain or authenticate them**.

`verifyLocalReviewPolicyCheckpointAdvancement` requires a caller-supplied
`readRetainedHead` callback from a separately trusted, durable registry, the
pinned signer public key/fingerprint, root and registry IDs, and an ordered
array containing the pinned predecessor checkpoint followed by 1–16 signed
successors. The verifier snapshots all input bytes before any asynchronous
callback, reads the retained head before and after verification, and rejects
missing/mismatched head anchors, bad signatures, registry/key substitutions,
noncanonical bytes, skipped/repeated revisions, nonmatching predecessor
hashes, and removal of any previously revoked key or transition. It rejects
head changes observed during the read-only verification.

The returned candidate is **not** externally retained. A trusted registry
implementation must separately enforce authenticated compare-and-swap,
monotonic durable head retention, crash recovery, key custody and offsite
replication. Two different forks may each verify against the same unchanged
head; this module does **not** solve global split-view or consensus. An
untrusted `readRetainedHead` callback can lie; this code cannot establish its
independence or the freshness of the data it returns. The retained predecessor
must already have been vetted and pinned out-of-band. There is no trusted
clock, hosted customer identity, manufacturing approval, checkout or order
permission. Revocation is cumulative in this prototype (no un-revocation).

Reproduce the 40 new adversarial tests:

```
node --test tests/objective35ad-policy-checkpoint-monotonicity.test.mjs
```

No Shopify reads/writes, theme changes, deployments, paid services or customer
data are required. Main Engineering's 2D/3D preview and accessibility assets
are not changed.
