# Objective 32M — offline durable exchange replay / sequence journal

**Prototype, Linux single-host only. No Shopify reads or writes, production identity, checkout, remediation, manufacturing authorization, independently published cryptographic pins or distributed recovery.**

## Purpose

The Objective 32L exchange verifier accepts a caller-provided in-memory `seenExchangeDigests` list. Objective 32M adds a **separate, opt-in, durable single-host journal** that verifies an independently pinned, signed 32L transcript *inside* a cross-process kernel-locked critical section and atomically claims its sequence and predecessor. No previous API is changed. The journal does not authorize any operation beyond retaining evidence of a verified exchange.

## API

```js
import {createOfflineConflictExchangeJournal,offlineConflictExchangeJournalGenesisHead} from '../src/offline-conflict-exchange-journal.mjs';
const journal=createOfflineConflictExchangeJournal({
 directory:'/private/offline-exchange-journal',
 genesisExchangeDigest:independentlyPinnedPreviousExchangeDigest
});
const genesis=offlineConflictExchangeJournalGenesisHead(independentlyPinnedPreviousExchangeDigest);
const committed=await journal.claim({
 transcriptBytes:exactCanonicalSignedTranscript,
 verificationArgs:{
  proofBytes,expectedPin,expectedProofDigest,senderPublicKey,receiverPublicKey,
  sessionId,senderId,receiverId,senderNonce,receiverChallenge,
  sequence:1,previousExchangeDigest:independentlyPinnedPreviousExchangeDigest,nowMs
 },
 expectedHead:genesis // supplied from independent trusted state, not local disk
});
// Store {count:committed.count,headDigest:committed.headDigest} independently.
```

`inspect({expectedHead})` verifies the entire local hash chain and requires an independently supplied exact head. The API **never reads its own local head as authorization for an update**. Every `claim` verifies the complete signed proof, transcript canonicality, two Ed25519 signatures, independently supplied proof pin, parties, nonces, expiry, exact monotonic sequence and predecessor, and then appends one durable record. Only hashed context identifiers are retained; no signing keys or raw proof bytes are written. The `verificationArgs` clock is caller-supplied and not a trusted time service.

## Persistence and adversarial limits

- Linux `/usr/bin/flock` kernel lock coordinates cooperative processes sharing one local filesystem; the journal requires a private owner-controlled directory, rejects symlink paths, world-readable directories/records, unrecognized files and tampered/truncated/reordered records.
- `O_EXCL|O_NOFOLLOW` creates a pending record with mode `0600`; file and directory are fsynced; a hardlink to the numbered record is created and fsynced, then the pending name is unlinked and directory fsynced. A successful return indicates local durable write under the filesystem's sync semantics. Tests simulate interruptions after each durable phase.
- Any `.pending.json` (including a linked-but-not-cleaned record) **blocks all further reads/claims** as an uncertain commit. No automatic deletion or retry is permitted; an independent recovery adjudication is required in a future objective. If an interruption happens *after* final sync, the new record exists; a caller with only the prior external head cannot retry it, and must obtain a new independently validated pin.
- Every record is domain-separated SHA-256 hash chained. This detects local corruption and, **when a prior head was pinned independently**, rollback or rewritten history. A local attacker who can rewrite files can fabricate a self-consistent new chain; hashes alone are not signatures, immutable storage or offsite anchoring. Do not derive the expected head from the same journal and claim rollback resistance.
- Locks are advisory; no protection from a hostile same-user process, host compromise, malicious filesystem, network filesystems, untrusted clock, power-loss violating fsync semantics, cross-host races, or independent concurrent forks. There is no automatic recovery from pending records and no atomicity across unrelated files or Shopify systems.
- Each journal is capped at 4096 exchanges and each record at 2048 bytes. The genesis predecessor must be independently agreed upon. This feature is intentionally isolated from live storefront and previous Studio editor flows.

## Verification

```sh
node --test tests/objective32m-exchange-journal.test.mjs
npm test
```

The tests include a real two-process race for one pinned sequence, concurrent in-process claims, signed forgery/expiry/pin rejection, predecessor gaps, tamper/truncation/rollback, unsafe filesystem entries, and fault injection after pending/link/final sync. All keys and identities in tests are synthetic. No hosted service or real independent pin publisher is exercised.

## Next gates

External independently trusted head publication and monotonicity, independently provisioned signing keys and hosted identity, trusted clock, host compromise defense, adjudicated uncertain-commit recovery, atomic cross-resource coordination, and approved geometry/GLB/manufacturing and checkout integrations remain outside this objective.
