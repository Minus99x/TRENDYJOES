# Objective 33J — Durable cross-observer adjudication transcript inventory

**Offline prototype only. No Shopify reads/writes, deployment, checkout, repair or production authority.**

`src/offline-conflict-adjudication-transcript-inventory.mjs` provides an opt-in,
append-only, Linux-local registry of **pairs** of independently signed Objective
33I read-only pending-adjudication transcripts. Each admission re-verifies both
observer signatures, both underlying Objective 33H two-group reviewer approvals,
exact independently supplied transcript/decision/snapshot pins, observation
windows, and matching namespace, pending record and journal snapshot. Different
observer identities **and public keys** are mandatory.

## Usage contract

Create with `createOfflineConflictAdjudicationTranscriptInventory({directory,
namespaceId,journalScopeDigest})`. Retain the separately computed
`offlineConflictAdjudicationInventoryGenesisHead(namespaceId,journalScopeDigest)`
**outside the registry directory**. Call `inspect({expectedHead})` or
`accept({left,right,expectedHead})`, where `left` and `right` are the complete
Objective 33I verification arguments, including exact transcript Buffer, all
independent pins and `nowMs`. The returned `{count,headDigest}` must be retained
out of band for the next operation. This library **does not publish the head**.

The inventory stores the exact signed transcript bytes and their supplied pins
in strictly canonical JSON records, each bound to the predecessor record hash.
Every history read re-verifies both signed transcripts and the reviewer quorums;
all previous transcript digests and nonces are checked for duplicates. The
caller-supplied admission times are persisted for historical verification, but
are **not trusted timestamps**.

## Durability and failure behavior

On Linux, a private directory and exclusive atomic `mkdir` lock serialize
cross-process operations. A process killed while holding the lock leaves a
persistent `.inventory-lock`; no automatic stale-lock removal is permitted.
Each append writes `.pending.json` with `O_EXCL|O_NOFOLLOW`, fsyncs the file and
directory, hardlinks it to a numbered journal record, fsyncs again, unlinks the
pending marker, and fsyncs the directory. Pending markers, orphan files,
missing sequence numbers, noncanonical records, unsafe file types, bad
signatures, replayed evidence and independently pinned head mismatch all fail
closed. An interrupted append is **not automatically repaired or rolled back**.

No automatic lock removal, cleanup or pending adjudication exists. A human-led,
independently authorized future recovery protocol must establish the correct
state before any mutation; removing a lock by hand would defeat this guarantee.
This design assumes a trusted single Linux host, local filesystem atomic
hardlinks/fsync, trustworthy process identity and exclusive owner access.
Network filesystems, hostile same-UID processes, disk firmware failures,
external timestamp authority and global consensus are outside this proof.

## Regression evidence

23 new Objective 33J adversarial tests cover valid admission and reopen,
append history, nonce/digest replay, rollback, tamper, missing slots, signature
forgery, reviewer omission, scope substitution, observer duplication,
conflicting signed evidence, unsafe symlinks, stale locks, actual SIGKILL at
three fsync boundaries, and two competing independent Node processes.

`node --test --test-name-pattern='^33J' tests/objective33e-authority-observer-reconciliation.test.mjs`

`npm test`

This is **local cryptographic consistency**, not independent disk witnessing,
immutable offsite publication, globally complete inventory, hosted customer
authentication, real checkout/order reconciliation, manufacturing approval or
production authorization.
