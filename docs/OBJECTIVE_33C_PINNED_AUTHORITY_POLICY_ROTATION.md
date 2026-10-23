# Objective 33C — independently pinned authority-policy rotation (offline)

Version: v0.30.56. Local-only, read-only prototype. No Shopify traffic.

## Contract

`src/offline-conflict-authority-policy-rotation.mjs` exports:

- `offlineConflictAuthorityRotationBodyBytes(body)` — domain-separated UTF-8 signing bytes for an exact, bounded transition body.
- `offlineConflictAuthorityRotationDigest(body)` — domain-separated SHA-256 digest for an externally retained transition pin.
- `verifyOfflineConflictAuthorityPolicyRotation(input)` — verifies both old and new 33B namespace commitments and their complete 33A/32Z/32Y evidence chains; requires a majority of both old and new Ed25519 authority rosters to sign the *same* transition body.

The transition binds a namespace and journal scope, adjacent epochs (N to N+1), predecessor and successor policy digests, predecessor and successor namespace commitment digests, an independently retained prior-transition digest, issuance/expiry bounds (maximum one hour), and a nonce. Every digest and epoch is checked against an **independently supplied expected pin**; the verifier never promotes its own computed digest into a trust anchor. Both 33B commitments must be valid at the caller-supplied `nowMs` and must match the exact transition scope, namespace, epochs and policy/commitment pins.

Signatures use canonical Ed25519 SPKI DER public keys encoded as base64url. Authority rosters have 3–9 members; each majority is verified independently, with strictly sorted unique IDs and unique keys within each roster. Cross-roster overlap is permitted: a gradual rotation can retain a key, but the signed policy digest must change. Missing/forged signatures, changed keys, malformed or sparse arrays, unexpected fields, stale/expired transitions, wrong external pins, skipped epochs and substituted 33B histories fail closed. No key is generated or stored by production code.

## Trust boundary

An external trusted authority must distribute and retain namespace/scope/policy/commitment/transition digests, prior-transition heads and monotonic epochs. This module does **not** publish pins, prevent two externally authorized forks with different independently distributed heads, establish a trusted clock, supply a durable cross-host replay journal, protect signing keys, witness completeness or authorize repairs. The 33B/33A/32Z/32Y verification path remains local, synthetic and read-only. Passing tests does not prove hosted authentication, production manufacturing approval, Shopify checkout/order behavior or deployment readiness.

## Reproduce

```sh
node --test tests/objective33c-authority-policy-rotation.test.mjs
npm test
```

No Shopify reads or writes, real customer data, secrets, external traffic or deployments.
