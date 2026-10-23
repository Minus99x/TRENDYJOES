# Objective 35AG — Offline pinned witness roster and durable challenge ledger

**Prototype only. No hosted witnesses, external custody, checkout, Shopify writes, deployment, or production authority.**

Module: `src/preview-local-artwork-review-witness-roster-ledger.mjs`.

The canonical roster carries registry, policy signer, audience, bounded validity,
and a sorted unique list of 2–32 Ed25519 witness IDs/key fingerprints with
`active` or `revoked` status. The caller must supply an **independently retained
SHA-256 roster pin** and expected registry, signer, audience, root, and trusted
time. Roster serialization is a test/transport helper, **not** independent trust.

The opt-in challenge ledger uses a pre-existing absolute, owner-private (0700)
local directory and an explicitly initialized namespace marker. It rejects
symlinked, shared-permission or mismatched markers and does not automatically
repair partial initialization. Each challenge is consumed via atomic `open('wx')`
creation of a restrictive (0600) receipt, followed by file and directory fsync.
The replay key binds roster namespace, witness ID, challenge, audience, and
registry. Two differently signed acknowledgements with the same challenge
cannot be accepted by the same trustworthy filesystem ledger. Cross-process
concurrent callers receive exactly one success; a crash after exclusive file
creation leaves an ambiguous partial receipt that blocks reuse. There is no
retry after ambiguous writes.

`verifyOfflineWitnessWithPinnedRoster` first validates roster pins and active
witness identity, then delegates to the existing 35AF Ed25519 verifier with
exact head/candidate/challenge/expiry checks. It uses only a real adapter opened
by this module, not an arbitrary callback, and reports no production authority.

`deriveOfflineWitnessChallengeReceiptPin` returns the deterministic SHA-256 of
one consumed challenge receipt. Retain that pin **outside the local ledger**.
`assertRetainedReceipt` rejects missing, altered, partially written, symlinked,
wrong-permission or mismatched receipts. The optional `pinnedRetainedReceipts`
array supplied at ledger open is checked immediately and before every new
consumption. This catches rollback/deletion of independently pinned receipts.
A caller who fails to supply prior external pins, or whose external pins are
also rolled back, **cannot** rely on this local ledger for rollback resistance.

**Remaining trust gates:** Actual independent key custody, trusted clock,
externally pinned roster distribution/rotation, authenticated challenge issuance,
independent retention of all accepted receipts, crash-proof filesystem semantics
on the chosen hardware, cross-host atomicity/consensus, hosted identity,
manufacturing approval, Shopify staging/browser acceptance, and production
integration. This module does not decide fork outcomes or modify Night Watch
security evidence from 35AF.

Verification:

```sh
node --test tests/objective35ag-witness-roster-ledger.test.mjs
node --test tests/objective35af-witness-acknowledgements.test.mjs
npm test
npm run preview:assets:check
npm run preview:static:assets:check
npm run preview:staging:check
```

All tests use synthetic keys, local temporary directories and offline child
processes. No network or Shopify access is required or performed.
