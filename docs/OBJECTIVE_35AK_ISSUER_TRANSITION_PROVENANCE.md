# Objective 35AK — issuer-signed provenance for portable epoch chains

**Scope: local/offline verification only.** Extends 35AJ's independently pinned hash-linked epoch records with the actual 35AH Ed25519 issuer-signed transition bodies and 35AG roster snapshots. It does not modify 35AJ, 35AI, the editor, theme assets, or any Shopify state.

## API

`src/preview-local-artwork-review-epoch-transition-provenance.mjs` exports:

- `createOfflineEpochTransitionProvenance({evidenceBytes,genesisRosterBytes,transitions})`: deterministic transport envelope. `transitions` is an ordered array of `{transitionBytes,nextRosterBytes}`. Creation **does not authenticate** its contents.
- `verifyOfflineEpochTransitionProvenance({provenanceBytes,expectedProvenanceSha256,expectedIssuerPins,expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedGenesisSha256,expectedHead,expectedEvidenceSha256,expectedGenesisRosterSha256,expectedPolicySignerFingerprint,expectedAudience,trustedNowMs})`: validates canonical transport, all 35AJ record hashes and external pins, each roster hash, each 35AH Ed25519 issuer signature and policy binding, strictly increasing signed cutovers, and the latest roster's current validity. `expectedIssuerPins` must be supplied independently for each step as `{issuerPublicKey,expectedIssuerKeyFingerprint}`. A genesis-only chain requires `[]` and a currently valid genesis roster.
- `inspectOfflineEpochObserverViewsWithProvenance({...})`: first verifies 35AJ observer signatures and independent receipt/head pins, then independently verifies an issuer-provenance bundle for **every** view before returning `AGREEMENT`, `PREFIX`, or `FORK`. A fork is a diagnostic, not a consensus decision.

## Historical validity

For each signed transition, the verifier checks the previous roster at `cutoverMs - 1` and the next roster at `cutoverMs`, using 35AH's existing signed transition and 35AG's roster-policy verifiers. It rejects nonmonotonic/future cutovers and missing, substituted, or misordered transition/roster pairs. The **latest** roster must also be valid at caller-supplied `trustedNowMs`; passing a historical cutover alone is insufficient. This permits legitimate expired historical rosters without mistakenly accepting an expired current roster.

## Trust boundary and limitations

The caller must retain genesis/current-head pins, issuer public keys and fingerprints, policy/audience pins, receipt pins and a trusted clock **outside the evidence being verified**. Providing a value as an argument does not establish that it was independently obtained. A compromised trusted issuer, fraudulent external pin set, unreliable clock, or tampered external custody is outside this module's protection. It cannot verify actual key custody, cross-host agreement, consume-once replay, Shopify customer authentication, manufacturing approval, or production readiness. Results explicitly report these limits and always set `authorizesProduction:false`.

No source ZIP is automatically trusted by this code. Its external SHA-256 and contents must be checked before use. No external network, customer data, secrets, Shopify theme write, checkout, or deployment is involved.

## Reproduce

`node --test tests/objective35ak-epoch-transition-provenance.test.mjs`

`npm test` or complete bounded Node test groups when a monolithic invocation exceeds the environment's timeout. Confirm `npm run preview:assets:check`, `npm run preview:static:assets:check`, `npm run preview:staging:check` and `node scripts/build-main-staging-reconciliation.mjs --check` separately.
