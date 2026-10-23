# Objective 35AI — Externally pinned epoch-head registry (offline only)

## Scope

`src/preview-local-artwork-review-epoch-head-registry.mjs` adds an append-only,
single-host epoch-head registry for signed Objective 35AH witness-roster transitions.
All callers MUST obtain and retain `expectedGenesisSha256` and `expectedHead`
from a trusted channel outside the local directory. Values returned by this
module are **not** automatically independently authenticated.

## Flow

1. Prepare a dedicated empty local directory with mode 0700.
2. Create a genesis record using `createOfflineEpochGenesis` and retain its
   SHA-256 pin independently. Initialize once with `initializeOfflineEpochHeadRegistry`.
3. Open using `readOfflinePinnedEpochHead` with namespace, independent genesis
   SHA-256, and independent latest head `{epoch,rosterSha256,recordSha256}`.
4. Advance using `advanceOfflinePinnedEpochHead` with the same pins and complete
   signed transition verification arguments from Objective 35AH.
5. Retain the returned new head in independent custody before any subsequent
   operation; if this cannot be done, do not advance again.

The registry uses O_EXCL, fsync(file), fsync(directory), SHA-256 record chaining,
secure file/directory checks, and rejects gaps, partial records, unexpected
entries, altered chain links, replayed/stale external heads, and forged
transitions. Crash ambiguity is intentionally **not auto-repaired**.

`compareOfflineEpochHeadPins` detects conflicting independently supplied
same-epoch pins; differing epochs remain **indeterminate** without independently
retained history. The module does not implement external custody, distributed
consensus, trusted time, secure key management, hosted authentication,
Shopify acceptance, or production authorization. The filesystem contract
assumes a trustworthy single-host filesystem and does not defend against
privileged local adversaries or all path-replacement races.

## Verification

`node --test tests/objective35ai-epoch-head-registry.test.mjs`

Full suite: `npm test` (may require bounded file-group execution in this
resource-limited environment).

No Shopify writes, deployments, real customers, checkout, or pricing.
