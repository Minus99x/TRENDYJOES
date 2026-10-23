# Objective 32F — portable replay audit bundle and independent witness receipt contract

**Scope:** offline, read-only QA prototype. No Shopify access, external publication, remediation, hosted auth, manufacturing or checkout authorization.

## Implementation

`src/offline-portable-replay-audit-bundle.mjs` packages a complete Objective 32E historical checkpoint audit into bounded, canonical UTF-8 JSON bytes. Ed25519 public keys are exported as canonical DER/SPKI base64url, allowing independent offline verification without in-process KeyObject sharing. The package includes genesis bytes, the ordered historical 32C decision/reviewer/report evidence, 32D commit records, 32E auditor-signed checkpoint, all verifier pins, and an explicit count, per-item SHA-256 inventory, and inventory digest. Its bundle digest is domain-separated and covers **every byte** of the package. The encoding function verifies the existing 32E chain and signatures against independently supplied pins before returning bytes.

`verifyOfflinePortableReplayAuditBundle` checks an **independently supplied** bundle digest, strict JSON serialization, complete inventory, externally pinned 32E genesis/checkpoint/predecessor/policy/sequence, and all historic 32C/32D/32E evidence through the existing verifier. It also verifies a separate Ed25519-majority witness receipt, independently pinned by digest, predecessor, sequence and witness policy. The receipt signs the exact bundle digest, checkpoint digest, history digest, genesis, commit count, and monotonic attested observation time. Duplicate, unordered, invalid or insufficient witness signatures fail closed. Witness public keys may not be reused from the auditors or historic reviewers in this bundle.

This API supplies only `offlinePortableReplayWitnessSigningBytes`, receipt digest and witness policy digest helpers. It deliberately does **not** generate or hold witness private keys, publish a receipt, call a remote witness, supply trusted timestamps or persist evidence. Actual independent custody, pin publication, key security and trusted time are **not** established by a local signature. Never derive the supposed independent expected digest from an untrusted received bundle or receipt.

## Threat boundary and operational limitations

- The inventory detects omitted, reordered and substituted entries against separately anchored bundle bytes. Rebuilding an inventory alone cannot bypass the signed 32E history checkpoint.
- A locally generated witness receipt with a locally generated expected receipt digest is **not** proof of independent witnessing. Witness keys are synthetic in tests.
- `issuedAt` is an attested monotonic time claim only; there is no trusted timestamp authority or freshness verification. There is no automatic publication, recovery, retention or replay-commit action.
- The format is an in-memory 32 MiB maximum prototype, not a hardened streaming archive or hostile same-user filesystem defense. It does not provide offsite immutable storage or atomic cross-resource commits.
- Verification returns explicit `independentlyPublished:false`, `externalPinPublicationVerified:false`, `trustedTimestampVerified:false`, `authorizesRemediation:false`, `authorizesCheckout:false`, `productionApproved:false`.

## Reproduce

```sh
node --version
node --test tests/objective32f-portable-replay-audit-bundle.test.mjs
npm test
```

Next: Objective 32G — authenticated **read-only** witness receipt history continuity with independently pinned append-only sequence and multi-epoch witness policy migration, including omission/fork tests. No network publication or Shopify writes.
