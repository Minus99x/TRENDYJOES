# Objective 33G — single-host durable signed-equivocation envelope acceptance

**Offline-only experimental contract; no Shopify access, hosted identity, independent publication, repair, checkout or production authority.**

`src/offline-conflict-equivocation-acceptance-registry.mjs` adds an **opt-in** append-only registry for previously signed and independently pinned Objective 33F evidence envelopes. It is intentionally not enabled automatically in the editor or server. It accepts only 33F envelopes whose complete nested 33E→33D→33C→33B→33A→32Z/32Y signed histories verify; it binds the exact namespace, journal scope, independently supplied digest, observer identities, signed-attestation and history-head pins, nonce, expiry, and predecessor envelope digest. Every accept requires the caller to supply the expected current journal head from an independently retained source; a locally read head is not evidence of external anchoring.

The registry stores only bounded metadata and SHA-256 digests, not the 33F envelope or signing keys. All historical records are scanned and re-hashed under an exclusive Linux `flock` lock, and durable history is the authoritative replay/nonce inventory (not a caller-supplied `seenEnvelopeDigests` array). Each new record commits via exclusive `.pending.json` creation, file fsync, directory fsync, hardlink to the next sequential numbered record, directory fsync, pending unlink, and final directory fsync. `inspect` and `accept` fail closed if a pending record remains after an interruption. **There is no automatic retry, pending cleanup, branch selection, or recovery method.** Interrupted records require separately authorized, independently evidenced future adjudication.

## Contract

```js
import {createOfflineConflictEquivocationAcceptanceRegistry,
 offlineConflictEquivocationAcceptanceGenesisHead} from './src/offline-conflict-equivocation-acceptance-registry.mjs';
const head=offlineConflictEquivocationAcceptanceGenesisHead(namespaceId,journalScopeDigest);
const registry=createOfflineConflictEquivocationAcceptanceRegistry({
 directory:'/private/offline-evidence-registry',namespaceId,journalScopeDigest});
// First 33F envelope must have previousEnvelopeDigest === head.headDigest.
// verificationArgs is the complete independently pinned 33F verification input,
// including the original signed envelope bytes and caller-supplied nowMs.
const accepted=await registry.accept({verificationArgs,expectedHead:head});
// Retain {count:accepted.count,headDigest:accepted.headDigest} independently
// before attempting a subsequent envelope. inspect requires that same pin.
```

A returned head is **not** independently published. The `nowMs` value is caller-supplied and **not a trusted timestamp**. `flock` coordinates cooperating processes on one Linux host only. Host compromise, loss of independently held heads, NFS semantics, malicious privileged writers, rollback of both disk and external pins, global forks and concurrent distributed writers are outside this guarantee. The design uses strict owner-only directories and records, no-follow file opens, inode and link-count checks, bounded records and count, and fail-closed detection of missing, extra, modified, linked, symlinked or world-readable records.

## Reproduce

On Node v22.16.0 Linux, from the extracted Studio root:

```sh
node --test --test-name-pattern='^33G' tests/objective33e-authority-observer-reconciliation.test.mjs
npm test
```

Tests use real nested signed fork fixtures, independent competing Node processes, **actual SIGKILL** after file/directory sync boundaries, restart/replay, stale head, divergent signed forks, wrong predecessor/scope, re-pinned forged signatures, record tamper, deletion, orphan, hardlink, symlink, lock swap and unsafe permissions. No real customer data, Shopify requests, paid services, deployments or secrets are used.

**Remaining gates:** independently published monotonic head custody; authorized read-only adjudication of interrupted pending claims; protected signing keys; trusted timestamps; offsite immutable evidence; globally consistent observer history; hosted authentication; distributed atomicity; approved manufacturing geometry and GLBs; real cart/order integration. This local registry does not authorize production, checkout, remediation, repair or settlement.
