# Objective 32U — Offline byte-pinned resolution-evidence transport

**Status:** Read-only local prototype, no hosted identity, Shopify integration, independent witness custody, production authority, or external publication.

## New public interfaces

`src/offline-conflict-resolution-transport.mjs` exports:

- `encodeOfflineConflictResolutionTransport(views)` — produce a bounded Buffer containing `{schema,views}` in compact JSON, a domain-separated SHA-256 `byteDigest`, and byte length. This **creates a candidate pin**, not a trusted one.
- `offlineConflictResolutionTransportDigest(bytes)` — compute a domain-separated SHA-256 commitment over **exact input bytes**.
- `verifyOfflineConflictResolutionTransport({bytes,expectedByteDigest,anchors,expectedObserverIds,expectedUnionDigest,nowMs})` — require an **independently obtained** byte pin, validate exact wire bytes, parse fail-closed, and call the existing Objective 32T verifier with **separately supplied** roster, inventory/proof anchors and union digest. Trust data is never read from the untrusted transport.

The wire format is UTF-8, bounded to 1 MiB, with strict JSON syntax and compact `JSON.stringify` roundtrip. JSON object member names must be unique **after escape decoding**, no `__proto__`, `constructor`, or `prototype` member names, no invalid UTF-8, BOM, trailing data, non-normalized escapes, whitespace, unbounded depth, or excessive elements. Encoder rejects accessor/symbol/hidden array entries, sparse arrays, cycles, non-safe-integer numbers, lone surrogate strings, and non-plain objects. The envelope must have exactly `schema` then `views` fields. No signing, network access, filesystem writes, automatic repair, or cross-resource mutation occurs.

**Serialization limitation:** Signed 32S proof digests already depend on `JSON.stringify` *in the original property insertion order*. To preserve verification of existing signed histories, 32U preserves that order instead of globally sorting keys. Thus its normal form is **byte-deterministic for an existing ordered evidence tree**, not an order-independent canonical JSON standard. The exact byte pin intentionally distinguishes alternate key orders. Do not reformat signed proof JSON in transit; externally pin the exact encoded bytes. A transport byte digest without independent custody is merely a self-assertion.

**Adversarial boundaries:** Tests use genuine Ed25519-signed Objective 32T fixtures, then verify independent pins and revalidation of underlying 32S historical signatures. They cover malformed and duplicate JSON keys (including Unicode-escaped aliases), truncated or oversized streams, BOM, invalid UTF-8, noncanonical encodings, replay/omission through observer roster and union pins, forged/replaced evidence, and untrusted production claims. These are offline regression tests only, not proof of an independent network witness.

## Reproduce

```sh
node --test tests/objective32u-resolution-transport.test.mjs
npm test
```

## Remaining gates

Independent publication and immutable retention of exact byte pins, observer custody, hardware-protected signing keys, trusted timestamps, hosted authentication, production GLB/manufacturing approval, Shopify checkout, and distributed atomic recovery remain unimplemented. A verified 32R resolution receipt establishes an authorized **attempt**, not independently witnessed completion. Any uncertain journal state remains fail-closed pending independent manual resolution. No Shopify reads or writes; no deployment.
