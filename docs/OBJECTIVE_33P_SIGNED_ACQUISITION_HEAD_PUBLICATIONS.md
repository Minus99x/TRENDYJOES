# Objective 33P — signed acquisition-registry head publication assertions (offline)

**Scope:** Optional read-only, pure Node.js verifier. No filesystem reads, networking, Shopify access, recovery or deployment.

`src/offline-conflict-acquisition-head-publications.mjs` provides:

- `offlineConflictAcquisitionHeadPublicationBodyBytes(body)`: strict, domain-separated, canonical Ed25519 signing payload; the private signing key remains outside the module.
- `offlineConflictAcquisitionHeadPublicationDigest(bytes)`: canonical receipt digest for independently retained pins; digest alone is not authentication.
- `reconcileOfflineConflictAcquisitionHeadPublications({...})`: independently pinned 2–8 signed publisher receipts, with unique Ed25519 keys, exact publisher roster and ordered identities, namespace/scope/target-registry/host/genesis/directory pin bindings, bounded expiry, nonce/digest replay sets, and independently retained minimum registry-head rollback floor. Full signature checks precede result classification.

Each receipt signs `registryGenesisHead`, `registryHead`, `inventoryHead`, and a registry directory inode/device pin, plus scope, registry/host identity, publisher identity, time window and nonce. Caller must independently acquire and protect the publisher keys, exact signed-receipt digests, registry genesis, directory pin, and minimum previously retained registry head. All values are validated on every verification. No signer is trusted merely because its public key appears in the signed receipt.

Outcomes: `consistent-head`, `conflicting-same-height`, `conflicting-inventory-claim`, and `unresolved-different-heights`. An independently pinned floor rejects smaller heads and a different digest at the same count. A higher head does **not** prove it descends from that floor; that remains a future evidence requirement. A same-height fork is reported, never silently reconciled. Caller-supplied replay sets are **not** durable; callers must persist them separately and atomically where required.

## Security and production boundaries

Signatures authenticate **publisher assertions only**. This verifier does not independently read the Objective 33O registry, publish to an external witness, validate a remote host's actual filesystem, prove signer independence, validate historical ancestry, provide trusted timestamps, prevent global forks, or confer recovery, checkout, production, customer-authentication or deployment authority. A compromised publisher can sign a false claim. For production, independent observer enrollment, protected keys, verifiable acquisition, immutable externally witnessed publication, durable multi-host replay consensus and stronger history/ancestry evidence remain necessary.

## Verification

`node --test tests/objective33p-acquisition-head-publications.test.mjs`

`npm test`

Adversarial fixtures cover independently signed split views, unequal heights, inconsistent inventory metadata, forged signatures even with re-pinned digests, omitted/extra publishers, duplicate signing keys, identity and namespace substitutions, stale/rollback/fork against independently pinned floor, replay, expiry, malformed/corrupted/noncanonical JSON, and missing external pins. These are **offline simulated observer receipts**, not hosted or live multi-host proof.
