# Objective 31U — Offline export-receipt witness-policy rotation

**Local prototype only.** No Shopify writes, customer data, network I/O, production authorization or secret persistence.

`src/offline-export-receipt-witness-rotation.mjs` introduces a portable read-only rotated-history verification seam distinct from the existing Objective 31P acquisition-index witness rotation. The historical export receipts are checked against their epoch's externally supplied Ed25519 public keys, quorum and independently pinned policy digests. Signed transition certificates require outgoing quorum and proof of possession from **every** incoming witness. Witness identifiers and public keys cannot be reused in later epochs. Transition bodies bind registry ID, epochs, policy digests, an exact chain head, issuance/expiry and a unique nonce.

## APIs

- `offlineExportWitnessTransitionSigningBytes(body)` and `offlineExportWitnessTransitionPossessionBytes(body,witnessId)` produce domain-separated bytes for caller-controlled offline signing.
- `offlineExportWitnessTransitionChainDigest({transitions})` computes a deterministic digest. The verifier **requires** its expected value from an independent trust channel. Do not derive the expected digest from untrusted bundle bytes during verification.
- `encodeOfflineExportRotatedReceiptHistory({entries,...options})` serializes a fully verified canonical bounded JSON bundle. Its `options` must include the same independent trust pins as verification.
- `verifyOfflineExportRotatedReceiptHistory({bytes,expectedHead,policies,transitions,registryId,nowMs,expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch,expectedTransitionDigest})` validates canonical transport, external head, transition chain and each signed receipt under the proper epoch. `policies` contain caller-supplied Ed25519 public `KeyObject`s, not private keys. The verifier requires at least one signed receipt in each epoch and strictly increasing anchored counts. Historical receipt expiration is not authorization to reuse expired grants.
- `compareOfflineExportRotatedReceiptHistories({left,right,registryId,nowMs})` fully verifies **both** independently pinned branches before reporting signed receipt-body equivocation, signed policy-body equivocation, benign signature-encoding forks, identical histories or consistent prefix extensions. Both branches must share a genesis policy and final epoch. Results are informational and cannot authorize manufacturing or recovery.

## Threat boundaries

This code does not verify that witnesses are independent, that keys are protected, or that signatures correspond to actual physical acquisition observations. Independently supplied pins and time are trust inputs, not self-attested data. Signed timestamps are not trusted timestamp-service evidence. There is no durable rotated-policy registry, hardware-backed key custody, offsite retention, multi-resource atomic commit, hosted auth or live Shopify integration. Rotated-history format is new; the existing 31S single-policy durable registry is intentionally **not** modified or migrated. Operational cutover requires a separate safe integration design.

## Tests

`node --test tests/objective31u-export-receipt-witness-rotation.test.mjs`

`node --test --test-concurrency=4 tests/*.test.mjs`

Tests cover valid two- and three-epoch histories, external pin substitution, retired key reuse, forged/minority quorum signatures, proof-of-possession forgery, anchor mismatch, replay across epochs, temporal cutoffs, canonical encoding, truncation, oversize, independent child-process verification and signed cross-branch conflict classification.
