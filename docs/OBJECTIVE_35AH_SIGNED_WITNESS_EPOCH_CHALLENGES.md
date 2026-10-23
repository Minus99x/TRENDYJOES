# Objective 35AH — Offline signed witness-roster epochs and challenge issuance

**Local synthetic contract only. No hosted issuer, independent key custody,
trusted clock, cross-host replay consensus, Shopify writes or production authority.**

Module: `src/preview-local-artwork-review-witness-epoch.mjs`.

A roster transition is a canonical Ed25519-signed, externally SHA-256-pinned
record binding root, registry, policy signer, audience, previous/next roster
hashes, consecutive epochs, exact cutover timestamp, and pinned issuer key.
The verifier requires independently supplied previous/next roster pins,
issuer fingerprint, previous/next epoch numbers, transition hash, and trusted
clock. It verifies the predecessor roster at the instant before cutover and
the successor roster at the supplied current time; gaps and stale cutovers
fail closed. The verifier does **not** advance or persist an epoch head.
The externally supplied epoch number must be retained in an independent,
rollback-resistant registry in a real deployment.

A challenge ticket is a separate issuer-signed, independently SHA-256-pinned
record binding the verified epoch/transition/roster, witness, challenge,
registry, audience, parent/candidate checkpoint revisions and hashes,
issuer key, and a maximum five-minute validity window. Issuance must occur
after the signed cutover, and the ticket must expire within roster validity.
The witness acknowledgement must be signed within the issued window.

`verifyOfflineIssuedWitnessAcknowledgement` snapshots all caller-supplied
byte buffers before awaiting filesystem replay arbitration. It checks the
signed epoch and ticket before delegating to Objective 35AG's unchanged
pinned-roster verifier and durable one-time challenge ledger. It rejects
old-roster and old-epoch tickets, wrong witnesses, stale revisions, forged
signatures, substituted challenges, replay, and crash-created partial receipts.

This code does **not** distribute issuer tickets securely, prevent issuer key
compromise, prove real-world witness independence, or maintain a global epoch
head. Its safety depends on authentic external pins and a trustworthy time
source; single-host `O_EXCL` replay protection is not cross-host consensus.

Verification:

```sh
node --test tests/objective35ah-witness-epoch.test.mjs
node --test tests/objective35af-witness-acknowledgements.test.mjs tests/objective35ag-witness-roster-ledger.test.mjs
npm test
```

All tests are local, use synthetic keys and temporary filesystem fixtures,
and perform no Shopify or network writes.
