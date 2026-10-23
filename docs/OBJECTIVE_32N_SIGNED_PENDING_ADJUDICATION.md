# Objective 32N — signed offline interrupted-commit adjudication

**Local prototype only. No Shopify access, hosted identity, independent anchor publication, customer data, checkout, or production approval.**

## Scope and safety

Objective 32M deliberately blocks the journal whenever `.pending.json` exists. Objective 32N adds **opt-in** `adjudicatePending` to the same journal. The default `inspect` and `claim` paths remain fail-closed. Recovery is *never automatic* and never derives authority from local journal files.

A caller must obtain an **independently approved**, canonical, signed decision from a majority of at least three distinct Ed25519 reviewers. Reviewers' public keys and the expected journal head must be independently provisioned and pinned; this module does not distribute, certify, or protect them. Signatures cover the action, genesis, pre-commit and post-commit heads, exact pending bytes digest, pending record digest, short expiry and nonce. No single reviewer or reused public key can constitute a quorum. The clock is supplied by the caller and **not** a trusted timestamp.

## API

```js
import {createOfflineConflictExchangeJournal} from '../src/offline-conflict-exchange-journal.mjs';
import {OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA,
 offlineConflictExchangeRecoveryDecisionBytes,
 offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';

// Independent reviewers construct a strict decision body and sign the returned
// domain-separated bytes with their own Ed25519 private keys OFF this host.
const body = {
 schema:OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA,
 action:'finalize', // or 'abort' only for proven pre-link state
 genesisExchangeDigest:externalGenesisPin,
 reviewerPolicyDigest:independentlyPinnedReviewerPolicyDigest,
 preHead:externalPreHead,
 postHead:externalPostHead,
 pendingRecordDigest:externalPostHead.headDigest,
 pendingBytesDigest:externallyVerifiedSha256OfPendingBytes,
 issuedAt:trustedIssuanceMs,
 expiresAt:trustedIssuanceMs+30000,
 nonce:'independently_issued_nonce_1234'
};
const toSign=offlineConflictExchangeRecoveryDecisionBytes(body);
// The two (or more) reviewer signatures are obtained independently and sorted
// by reviewerId, each signature a canonical 64-byte Ed25519 base64url value.
const decision={body,signatures:[
 {reviewerId:'reviewer_0001',signature:reviewer1Signature},
 {reviewerId:'reviewer_0002',signature:reviewer2Signature}
]};
const journal=createOfflineConflictExchangeJournal({
 directory:'/private/offline-exchange-journal',
 genesisExchangeDigest:externalGenesisPin
});
const result=await journal.adjudicatePending({
 decision,expectedReviewerPolicyDigest:independentlyPinnedReviewerPolicyDigest,reviewers:[
  {reviewerId:'reviewer_0001',publicKey:independentlyPinnedPublicKey1},
  {reviewerId:'reviewer_0002',publicKey:independentlyPinnedPublicKey2},
  {reviewerId:'reviewer_0003',publicKey:independentlyPinnedPublicKey3}
 ],
 expectedHead:body.action==='abort'?body.preHead:body.postHead,
 nowMs:trustedCurrentMs
});
```

## Recovery state machine

- **Abort:** Only when the signed pre-commit head matches the complete existing chain, `.pending.json` is an exclusive single-link file, and the numbered successor is absent. The signed post-commit head and pending record must match the exact bytes. The authorized pending file is unlinked and directory fsynced; the journal remains at the pinned pre-commit head.
- **Finalize:** Only when the signed post-commit head matches the complete existing chain, `.pending.json` and the expected numbered successor are **the same two-link inode**, the predecessor matches the signed pre-commit head, and exact pending bytes match the signed digest. The pending name is unlinked and directory fsynced, leaving the committed record intact.
- **All other states:** Refuse, retain pending, do not advance. In particular, a conflicting numbered file, broken inode link, missing file, changed record, changed signed decision, stale external head, forged/insufficient signatures, expired decision, invalid reviewer policy, or tampered history fails closed.
- An interruption before recovery unlink retains the pending barrier. An interruption after unlink and fsync has already resolved the journal, so the same decision cannot replay because pending is absent.

## Important external dependencies and limitations

The reviewer-policy digest is SHA-256 over a canonical sorted roster of reviewer IDs and Ed25519 SPKI key digests, domain-separated as `TJ-32N-REVIEWER-POLICY`; `offlineConflictExchangeRecoveryReviewerPolicyDigest` computes the candidate digest, which must be compared against an independently held trusted pin. The signed decision itself binds that digest.

Reviewer keys, their authorization, journal heads and evidence of whether an exchange was already accepted **must be obtained independently**; supplying values copied from the compromised local journal does not provide independent authorization. In particular, a signed **abort** is unsafe if the exchange was already accepted by an external party, even if the local numbered file is absent. Reviewers must adjudicate this using external evidence before authorizing abort. This code cannot prove global non-publication or eliminate forks outside the single host. No audit event or immutable offsite anchor is automatically published for a recovery decision. The caller must retain the signed decision and outcome independently.

The Linux advisory lock only coordinates cooperative local processes. A hostile same-user process, filesystem compromise, malicious reviewer majority, clock manipulation, storage lying about fsync, and power loss across external resources remain outside this model. No real Shopify writes, independent witness deployment, checkout, or manufacturing approval is provided.

## Tests

```sh
node --test tests/objective32n-exchange-recovery.test.mjs
npm test
```

Tests use synthetic Ed25519 keys and independently supplied test pins, simulated crash points before and after hardlink, forked numbered files, pending corruption, signer substitution, quorum failures, stale/rolled-back heads, expiry, replay, and interrupted recovery. The tests do not establish production identity, protected keys or external publication.
