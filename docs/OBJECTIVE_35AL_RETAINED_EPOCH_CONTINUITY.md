# Objective 35AL — retained, issuer-signed epoch continuity (offline)

This module adds an **independent-history acceptance gate** over Objective 35AK's signed epoch provenance. Its trust inputs are deliberately external: for every historical observation, the caller must supply a separately retained SHA-256 provenance digest, evidence digest, epoch head, Ed25519 issuer key/fingerprint pins, and a trusted observation time. The common namespace/root/registry/genesis/roster/policy/audience pins and current trusted time are also external. None are loaded from the transported snapshot as authority.

`verifyOfflineRetainedEpochContinuity({snapshots,retainedPins,...commonPins})` accepts at least two dense ordered snapshots, each `{provenanceBytes: Buffer}` and matching external pin `{expectedProvenanceSha256,expectedEvidenceSha256,expectedHead,expectedIssuerPins,observedAtMs}`. The 35AK verifier checks each signed transition, historical cutover and roster policy at its retained observation time. The 35AJ verifier independently extracts the complete canonical genesis-to-head record-digest chain. Only after all signatures pass are historical digests compared. Shared-epoch mismatches are **EQUIVOCATION** even if both branches have valid signatures. A decreasing head is **ROLLBACK**, a repeated head is **REPLAY**, a missing retained predecessor is **HISTORY_PRUNED**. Missing historical pins or snapshots, non-monotonic observation times, altered issuer keys, changed evidence, forged identities, and unsafe input shapes fail closed.

## Threat model and limits

- A malicious local transport may substitute, truncate, reorder, or replay snapshots. The independent retained pins must be stored and authenticated **outside** that transport. If an attacker controls both pins and snapshots, this module cannot establish continuity.
- An issuer can sign two different historical chains. This verifier detects conflicting signed record identities only when independently retained views of both branches are presented. It does **not** discover undisclosed forks or create consensus.
- The caller supplies observation time and current time; the module does not establish trusted time. A historical roster may have expired today yet be valid at its authenticated observation time. An attacker-controlled clock invalidates the assurance.
- No snapshot can authorize manufacturing, checkout, deployment or Shopify operations. Output flags remain `independentCustodyVerified:false`, `trustedClockIndependentlyVerified:false`, `crossHostConsensusVerified:false`, `authorizesProduction:false`.
- No network requests, production credentials, customer data, Shopify writes, theme edits or external dependencies are used.

## Reproduce

From the extracted release root on Node >=20:

```
node --test tests/objective35al-retained-epoch-continuity.test.mjs
node --test tests/objective35ak-epoch-transition-provenance.test.mjs tests/objective35aj-epoch-observer-evidence.test.mjs
npm test
npm run preview:assets:check
npm run preview:static:assets:check
npm run preview:staging:check
node scripts/build-main-staging-reconciliation.mjs --check
```

For environments where monolithic `npm test` exceeds an execution window, run all `tests/*.test.mjs` in bounded independent invocations, preserve TAP logs, and count only completed passes. A timeout is **not** a passing test.

## Coordination

Main Engineering Objective 55 is a separate offline editor/accessibility and unpublished staging reconciliation effort. This module neither touches those files nor assumes hosted acceptance. Integrate only by explicit Main Engineering review of the versioned Night Watch ZIP and Library handoff.
