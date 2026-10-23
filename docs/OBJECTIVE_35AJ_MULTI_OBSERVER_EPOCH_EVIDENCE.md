# Objective 35AJ — Portable multi-observer epoch evidence (offline only)

This module exports **canonical, bounded 35AI epoch-head record chains** and verifies independently pinned SHA-256 genesis, namespace, root, registry, head and evidence digests. It signs/validates **Ed25519 observer receipts** over evidence digest, head epoch/hash, observer identity, key fingerprint, audience, challenge and bounded validity interval. Two or more distinct pinned observers can compare their chains as `AGREEMENT`, `PREFIX`, or `FORK`; the result includes a portable deterministic evidence digest and first conflicting epoch/record hashes.

**This is not hosted witnessing, independently retained evidence, quorum consensus, key custody, trusted time, durable replay consumption, or Shopify authorization.** Signers in the tests are offline fixtures. A caller must obtain independent observer public keys, challenges, receipt SHA-256 pins, expected heads, trusted clock, and independently retained evidence outside the same storage fault domain. The module does not contact observers or write to a network or Shopify.

## API

`src/preview-local-artwork-review-epoch-observer-evidence.mjs` exports:

- `createOfflineEpochChainEvidence({recordBytes,namespacePin,rootPin,registryId,expectedGenesisSha256,expectedHead})` — deterministic portable canonical bytes. Source records must already be obtained under a trusted local snapshot; for real 35AI local registries, use 35AI's pinned registry validation before collecting records. Avoid trusting unverified filesystem contents.
- `verifyOfflineEpochChainEvidence({evidenceBytes,expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedGenesisSha256,expectedHead,expectedEvidenceSha256})` — validates strict canonical JSON, every record's SHA-256 ancestry, contiguous epochs, changed roster hashes, transition hash presence, and externally supplied pins.
- `createOfflineEpochObserverReceipt({...})` — fixture signer only, with an Ed25519 private key provided by caller.
- `verifyOfflineEpochObserverReceipt({...})` — strict canonical receipt and signature validation against independently supplied observer fingerprint, receipt hash, evidence digest, audience, challenge, head, and trusted time.
- `inspectOfflineEpochObserverViews({views,observerPins,expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedGenesisSha256,expectedAudience,trustedNowMs})` — compares 2–16 separately pinned observer views. Rejects duplicated IDs, signing keys and challenges, bad receipts, tampering, stale retained heads, and missing history. `FORK` **never** authorizes choosing a branch.

## Explicit trust boundaries

- The 35AJ portable chain verifies **record hashes and links**, but does **not** re-verify 35AH issuer-signed transition bodies. The 35AI registry performs issuer verification at commit; an offline exported chain cannot independently prove that without retaining signed transition and roster inputs. `transitionSignaturesVerified:false` is intentional. A future objective can add signed transition provenance to portable evidence.
- No stateful consume-once store is called. `replayConsumed:false` means a valid receipt could be replayed to a verifier that reused a challenge or failed to pin fresh receipt hashes. External replay ledger and challenge issuance remain gates.
- `PREFIX` means matching retained hashes on shared epochs, not that a remote observer retained the complete older history. `AGREEMENT` means the provided, separately pinned receipts attest to the same head, not global consensus.
- Independently retained pins are a **caller obligation**, not established by passing pins in one process. A malicious observer with an accepted key can sign false claims; no quorum threshold, independent key custody, trusted time, or production authorization is established.
- No theme, product, price, order, checkout, customer data, network or Shopify operations are performed.

## Reproduction

`node --test tests/objective35aj-epoch-observer-evidence.test.mjs`

`npm test` (full suite, when runtime permits), or execute every test file in bounded groups using `node --test --test-concurrency=2`.

The tests include a real 35AI genesis + 35AH signed roster rotation persisted to a local test directory, multi-observer agreement/prefix/fork, order-independent evidence digests, external-head rollback rejection, identity and key substitution, signature tamper, expiry, replay-risk flagging, noncanonical bytes, missing genesis, broken hash ancestry, and size bounds.
