# Objective 35AE — offline signed-policy head CAS and fork evidence

**Offline development fixture only.** Not installed in Shopify, not a hosted
registry, not an independent witness, and not manufacturing or checkout authority.

`src/preview-local-artwork-review-policy-cas.mjs` adds three narrowly scoped
capabilities on top of the already-verified 35AD Ed25519 checkpoint verifier:

1. `createOfflineLocalReviewPolicyHeadRegistry` adapts the existing
   `createOfflineDurableAnchorAdapter` Linux-local append-only `flock` + fsync
   registry CAS to exact 35AD head identities. The caller must supply a separately
   authenticated **revision-one** checkpoint head to `initializePinnedHead`.
   The adapter stores revision and SHA-256 digest in its existing registry anchor
   fields. It does **not** verify the bootstrap signature or grant external trust.
   Reopening the same private directory recovers committed state; a pending
   interrupted append fails closed until independent signed recovery using the
   underlying operator-controlled durable-anchor protocol. The wrapper exposes
   inspection only, **not** a self-service recovery bypass.
2. `advanceOfflineLocalReviewPolicyHead` verifies a complete 35AD signed
   predecessor + successor chain, enforces a **single revision per CAS**, calls
   the caller-provided atomic `compareAndSwapRetainedHead`, and reads back the
   committed head. Concurrent or stale writers cannot silently overwrite the
   winner; CAS conflict is not retried. Unknown commit state fails closed.
   The adapter's raw CAS method is low-level and **not authenticated** by itself:
   only a trusted application boundary may expose verified promotion, and
   untrusted local filesystem writers remain out of scope.
3. `inspectOfflineLocalReviewPolicySplitView` verifies two distinct, signer-valid
   successors of the same externally pinned predecessor and returns a canonical
   order-independent SHA-256 evidence digest plus portable signed candidate
   bytes encoded as immutable base64url strings. This detects an **observed** equivocation; it cannot prove global
   uniqueness, independently witness either branch, or choose an authoritative
   fork. The evidence digest itself is not a signature.

The local filesystem owner can rewrite/delete history, clone a registry,
replace trusted pins, or present different directories to different observers.
Single-host `flock` is not distributed consensus or cross-host linearizability.
Power-loss guarantees and network filesystem semantics are unverified. External
registry authentication, independent retained anchors, trusted key custody,
operator recovery and independent observers remain mandatory production gates.
The 35AD policy signer and the separate durable-adapter recovery signer should
be independently administered. Never expose these low-level APIs to customers.

Run adversarial tests with:

```sh
node --test tests/objective35ae-policy-head-cas.test.mjs
node --test tests/objective35aa*.test.mjs tests/objective35ab*.test.mjs tests/objective35ac*.test.mjs tests/objective35ad*.test.mjs tests/objective35ae*.test.mjs
```

The tests cover cross-process concurrent writers, stale and replayed revisions,
invalid signer/registry identity, signature forgery, revocation rollback,
malformed candidate arrays, signed fork detection, pending/committed crash
fault injection, symlinked history and explicit non-authorizing result flags.
All fixtures use ephemeral local keys and synthetic policies. No real customer
information, Shopify traffic, deployments, paid services or store mutations.
