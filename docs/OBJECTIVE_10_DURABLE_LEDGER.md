# Objective 10 — offline durable replay + design revision CAS (v0.10)

## Scope and verification

**Local synthetic fixture only.** `src/offline-durable-ledger.mjs` implements a file-backed, no-dependency, single-host development adapter. It is not a production database, hosted authentication system, Shopify connector, checkout/payment proof, fulfillment authorization, or machine controller. There are **no Shopify writes** and no real customer data. Existing editor, geometry, GLB, catalog and manufacturing code remain unchanged.

The v0.9 order reconciliation seam now passes `matchedLines` to `claimOnce`. Existing injected v0.9 mock adapters continue to work because additional object properties are optional for JS callbacks. The v0.10 file adapter **requires** these bindings and compares them under the same atomic lock as webhook event and order claims. This closes a stale-lookup-to-claim gap for callers that use this adapter, without implying that arbitrary external adapters have equivalent guarantees.

## Contract

`createOfflineDurableLedger({directory,lockTimeoutMs,injectFault})` exposes:

- `putDesignCAS({design,expectedRevision})`: initial revision must be 1 with `expectedRevision:null`; subsequent revision must be exactly previous+1 and match previous revision; owner GID is immutable; shop/reference/owner/product/variant/composition/status are validated. Each operation serializes with claims.
- `lookupDesign({shop,reference})`: reads an atomic JSON snapshot and returns a frozen record or null. A read may become stale immediately; the claim transaction **rechecks** current revision and product/variant/digest.
- `claimOnce({eventKey,bodySha256,orderGid,matchedLines})`: atomically records event, order and design-revision claims. Identical webhook replay returns `duplicate`, altered payload or order collision returns `conflict`, a second webhook event ID for the same identical order/payload returns `duplicate`, a different order cannot claim the same design revision, and a changed revision fails closed.

Filesystem details: directory-scoped exclusive `mkdir` lock, bounded lock acquisition, immutable old-state read, bounded JSON state, temp file with `wx` mode 0600, file fsync, atomic rename and directory fsync. State reads use `O_NOFOLLOW` and reject symlink/corruption. There is **no automatic stale-lock eviction**: a process crash holding the lock leaves subsequent writes blocked until an operator validates the state and safely removes the orphan lock. A crash before rename leaves the old snapshot; a crash after rename may commit without an acknowledgment, so retry must be idempotent. All transaction faults reject; no manufacturing or checkout flags are enabled.

## Tests

`node --test tests/objective10-durable-ledger.test.mjs` covers 14 independent test cases, including two cross-process race tests, persisted CAS, ownership immutability, revision/variant/digest mismatch, duplicate and conflicting webhook claims, different order double-spend rejection, failure injection before/after atomic rename, orphan lock, corrupted/symlinked/duplicate state, malformed claims, cross-shop substitution, and a synthetic HMAC-authenticated order using the real adapter.

`npm test` runs the complete regression suite including all previous objectives. No external npm packages or live traffic are required.

## Hard limitations and remaining gates

1. **Single-host local filesystem only.** `mkdir`/rename/fsync semantics are filesystem-dependent. Not evaluated on NFS, shared network mounts, Windows, containers with overlay storage, distributed hosts or power-loss hardware. It is not a substitute for a transactional SQL database with backup, retention and recovery procedures.
2. No protection against privileged local modification of ledger JSON, directories, parent-path symlinks or malicious local process access; local scratch storage must be private. This fixture does not provide encryption, ACL audit, per-tenant access control or a production trust anchor.
3. No cryptographic metadata protocol version/key rotation yet. The legacy metadata HMAC remains **insufficient for checkout authorization** because it does not bind tenant, owner, nonce, expiry, checkout session or key identifier. The v0.9 webhook HMAC uses synthetic secrets only.
4. `financial_status` in a synthetic webhook is not payment proof. No actual customer/guest auth, checkout session, real Shopify webhook subscription, verified payment, fulfillment, inventory/pricing or manufacturing approval.
5. No live GLB physical calibration, artwork scanning, device QA, production pricing or output.

**Next objective:** versioned tenant/owner/session-bound signed metadata with key IDs, expiry and rotation, tamper/replay tests and explicit migration boundary from legacy HMAC; keep offline and disabled for checkout/production.
