# Objective 35Y — challenge-bound signed artwork review evidence

**Scope:** offline, local read-only prototype. Nothing here can delete, quarantine,
move, publish, sell, print, or authorize artwork. No Shopify reads/writes.

The prior Objective 35W ticket is HMAC-authenticated with a caller-held key,
expires after at most one hour, and pins the exact root and complete content
snapshot. Objective 35X makes that snapshot depend on actual image bytes and
paired metadata digests, not just file stats.

Objective 35Y adds `src/preview-local-artwork-review-evidence.mjs`:

- `createLocalArtworkReviewEvidence(root,ticket,{reviewKey,signingKey,keyId,challenge,now,ttlMs,...})`
  first re-verifies the 35W ticket and the complete 35X artwork scan under the
  cooperative local lease. Only then does it Ed25519-sign a domain-separated,
  canonical ordered JSON record containing the exact ticket SHA-256, root pin,
  content/reference pin, sorted candidate IDs, count, operator key ID, bounded
  observation/expiry, and reviewer-supplied 128-bit challenge. All authority
  flags are fixed to `false` / `NONE`.
- `verifyLocalArtworkReviewEvidence(root,evidence,ticket,{reviewKey,resolvePublicKey,expectedChallenge,now,...})`
  validates strict fields, size and time bounds, matches the reviewer challenge,
  retrieves the **trusted public key from external caller configuration**,
  checks Ed25519 signature, checks the exact original ticket digest, and finally
  re-scans the local storage via the 35W verifier. It returns a bounded,
  operator-readable report with the evidence SHA-256 and explicit prohibitions.

The module does not create files, mutate the store, or send network requests.
The reviewer must generate a fresh unpredictable challenge outside the signer;
using a different expected challenge rejects replay into another review session.
**Replaying the same evidence with the same challenge during its TTL remains
possible.** There is no durable nonce registry, trusted clock, independent
witness, or production-wide writer fence. An operator must not interpret the
report as permission to delete/quarantine or as proof of hosted identity.

Both signing and verification use caller-injected Ed25519 `KeyObject`s; private
keys are never persisted. The key ID is only a lookup hint and never establishes
trust. A rotated/revoked key must be removed from the external trusted resolver.
No self-asserted public key inside the evidence can authorize its own signature.

By default a record can contain at most 1,024 candidates and 65,536 serialized
UTF-8 bytes. The verification report is independently bounded by the same byte
limit. The signed evidence expires after at most 5 minutes and cannot outlive
its original 35W ticket. Invalid, stale, changed, incomplete or unsafe artwork
fails closed. Verification after a successful scan is still only a point-in-time
observation; uncooperative writers can change bytes afterward.

## Local test-only example

```js
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {createLocalArtworkQuarantineIntent} from './src/preview-local-artwork-quarantine-review.mjs';
import {createLocalArtworkReviewEvidence,verifyLocalArtworkReviewEvidence} from './src/preview-local-artwork-review-evidence.mjs';
const reviewKey=randomBytes(32);
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
const challenge=randomBytes(16).toString('hex'); // reviewer-held, out of band
const ticket=await createLocalArtworkQuarantineIntent(root,{reviewKey});
const evidence=await createLocalArtworkReviewEvidence(root,ticket,{
 reviewKey,signingKey:privateKey,keyId:'offline-operator-1',challenge
});
const result=await verifyLocalArtworkReviewEvidence(root,evidence,ticket,{
 reviewKey,resolvePublicKey:async id=>id==='offline-operator-1'?publicKey:null,
 expectedChallenge:challenge
});
console.log(result.operatorReport); // still NOT deletion authorization
```

The example assumes a previously initialized local `root`; it is not a hosted
API, Shopify integration, production trust service, or machine-output gate.

## Verification

`node --test tests/objective35y-signed-review-evidence.test.mjs`

`npm test` (or complete disjoint batched test-file execution when monolithic
execution exceeds the runner's timeout).

Cross-process tampering, ticket substitution, wrong challenge, expired evidence,
wrong/rotated key, forged authority flags, signed field mutation, byte limits,
unsafe incomplete pairs and busy leases are adversarially exercised.

**Next Objective 35Z:** independently anchored operator-review transcript
lineage and replay-detection fixture (still no mutation authorization), with
crash and rollback tests. Do not reuse signed evidence as a quarantine permit.
