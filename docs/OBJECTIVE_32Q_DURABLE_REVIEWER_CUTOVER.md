# Objective 32Q — opt-in offline reviewer-policy cutover

This is a **single-host, local-only, one-time** cutover marker for the offline 32M/32N exchange journal. It is not a production identity, recovery, payment, checkout, or Shopify integration.

## Activation contract

`journal.activateRecoveryPolicyCutover({history, expectedPriorPolicyDigest, expectedCutoverDigest, expectedExchangeJournalHead})` accepts the fully verified Objective 32P evidence history, exactly one outgoing/incoming majority-signed Ed25519 policy transition, no recovery receipts after the transition, an unexpired signed transition at `history.nowMs`, and independently supplied SHA-256 pins for previous reviewer policy, cutover marker, exchange journal head, transition head, and receipt head. The 32P history itself carries its independently supplied transition, final receipt, and final policy pins. Local 32O receipt inventory and 32M journal are checked under the parent Linux flock lock before writing.

A domain-separated cutover digest binds the genesis exchange, old/new policy digests, transition and receipt heads, and activation timestamp. The marker is written to a 0600 O_EXCL pending file, fsynced, hard-linked to its final pathname, directory-fsynced, and then the pending link is removed and directory-fsynced. The caller must independently retain/pin the cutover digest; a digest computed from the local file is NOT an independent anchor.

`inspectActiveRecoveryPolicy({expectedCutoverDigest})` verifies exact canonical bytes, owner/mode/inode/no-follow, digest, genesis, and external pin. Once activated, `adjudicatePending` requires `expectedActivePolicyPin` and rejects decisions signed by retired reviewer rosters. The existing independent decision signature verification, receipt pin, pending record, and journal head gates remain mandatory. No automatic recovery is performed.

## Fail-closed crash behavior

A leftover `.recovery-policy-cutover.pending` blocks cutover inspection, subsequent activation, recovery adjudication, and new exchange claims. **Do not delete it automatically.** It can mean the final hard link was or was not created before a crash. An operator must quiesce the host and independently reconcile externally pinned evidence before any manual repair. This objective does not implement that repair.

The marker is deliberately one-time: subsequent policy rotations require a future audited migration and must not overwrite it. Missing local marker can be detected only if callers supply their previously independently retained cutover pin. If both local marker and external pin are rolled back or lost, local software cannot prove the earlier activation occurred. Local fsync is not a certified power-loss or distributed durability guarantee.

## Verification

`node --test tests/objective32q-recovery-policy-cutover.test.mjs` covers authentic signed activation, restart, double activation, bad external pins, forged old/new signatures, quorum failure, expiry, forked/omitted histories, tampering, symlinks, rollback, interrupted writes before/after hard-link and after commit, retired-policy rejection, missing new-policy pin, cross-instance concurrency, and pending-cutover mutation denial. `npm test` runs the full historical suite.

No Shopify reads/writes, staging modifications, deployments, secrets, hosted authentication, independent witness publication, trusted timestamps, or real orders.
