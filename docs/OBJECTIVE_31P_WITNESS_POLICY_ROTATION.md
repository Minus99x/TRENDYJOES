# Objective 31P — Witness policy rotation and cross-epoch signed branch review

**Offline diagnostic code only.** No independently operated witnesses, hosted identity, production key custody, trusted time, offsite/WORM evidence retention, atomic recovery, manufacturing authorization, Shopify integration, or deployment.

## Source API

`src/offline-acquisition-witness-rotation.mjs` provides:

- `offlineAcquisitionWitnessTransitionSigningBytes(body)` — strict, domain-separated canonical transition certificate bytes. Fields: `schema`, `registryId`, `fromEpoch`, `toEpoch`, `fromPolicyDigest`, `toPolicyDigest`, `anchorHead`, `issuedAt`, `expiresAt`, `nonce`. Requires adjacent epochs, a non-genesis index head, and a bounded seven-day issuance window.
- `offlineAcquisitionWitnessTransitionPossessionBytes(body,witnessId)` — independent proof-of-possession signing bytes binding each incoming Ed25519 witness key to this exact transition and witness ID.
- `verifyOfflineAcquisitionWitnessTransitionChain({policies,transitions,registryId,nowMs,trustedAnchor,expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch})` — verifies complete signed historical policy chain. Each outgoing epoch requires a strict-majority signature quorum; every incoming key must supply an individually valid proof of possession. Rejects reuse of retired key material or witness IDs, forged certificates, reordered/missing signatures, replayed transition nonces, nonmonotonic transition timestamps, divergent/rolled-back index history, and truncation against independently supplied final epoch/policy pins. Each transition includes complete portable 31N history through its signed anchor head. The original 31N full verification of underlying 31L/31M signatures **remains separately mandatory**.
- `reviewOfflineAcquisitionCrossEpochBranches({...chainInputs,branches})` — verifies epoch-specific signed index receipts, temporal retirement cutoffs, signed transition-anchor prefix, replayed nonces, index structural histories and predecessor binding. Returns either `CROSS_EPOCH_SIGNED_FORK_EVIDENCE` (with earliest conflicting index) or `CONSISTENT_SIGNED_PREFIXES_ONLY`.

Each policy is `{witnesses:[{id,publicKey}],quorum}`. Transition is `{body,outgoingSignatures:[{witnessId,signature}],incomingProofs:[{witnessId,signature}],history}`. Branch is `{epoch,attestation,history}`. All signatures are canonical base64url Ed25519. Signatures must be sorted by witness ID. The incoming proofs must include **every** new witness, not merely a quorum.

## Independent trust requirements

All public keys, policy arrays, expected genesis/final digests, final epoch, trusted index anchor, registry ID, and verification time **must originate outside the evidence host**. Never accept them from an untrusted evidence bundle. Verification of an historical transition certificate at `nowMs` does **not** independently prove the signing timestamp or its claimed key custody. An attacker can withhold an unseen conflicting branch; no local verifier proves global absence of equivocation. Key rollover in this prototype uses wholly disjoint witness keysets and identifiers; overlap is deliberately rejected rather than silently retaining a compromised key. A real-world migration may require a separately reviewed bridge procedure.

**No operational permission:** all successful results are read-only and explicitly set `mayRetry:false`, `mayAcknowledge:false`, `productionApproved:false`. Structural history checks do not authenticate underlying acquisition session signatures, and signed policy transitions do not authorize recovery, deletion, manufacturing, payment, checkout, or store operations.

## Reproduction

```sh
node --test tests/objective31p-witness-rotation.test.mjs
node --test --test-concurrency=4 tests/*.test.mjs
```

Synthetic keys and fixtures only. No dependencies or network access. Main Engineering's separate v0.32 UI, original 2D/3D editor, GLB import/calibration, universal product scope, and mid-century styling are unchanged.
