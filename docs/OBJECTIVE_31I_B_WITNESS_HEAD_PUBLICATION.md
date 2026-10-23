# Objective 31I-B — independently signed forensic-head publication (offline contract)

**Release v0.30.10. No Shopify writes. Not production authorization.**

## New implementation

`src/offline-forensic-head-publication.mjs` adds a pure verifier, composite forensic-bundle verifier and opt-in, Linux-only, single-host append-only publication store. It does **not** generate, store or use private signing keys. The caller supplies independently obtained Ed25519 signatures from a strict majority of distinct witness public keys. Witness keys may not equal any current or historical reviewer key.

Each publication commits to an exact forensic journal `{count,headDigest}`, registry and anchor identity, publication sequence, predecessor digest, reviewer policy digest and monotonic **local** publication timestamp. Canonical signatures cover the publication and all policy-transition approvals. A policy change requires quorum signatures from the **previous** reviewer policy and a witness quorum; policy indices may not skip, decrease, or silently switch. Reviewer policies are caller-pinned and checked against retired-key reactivation and cross-identity reassignment. A portable verifier can validate an entire publication history against an **externally pinned** publication head. The composite verifier additionally binds the published forensic head and policy epochs to the Objective 31I-A portable evidence verifier.

The local store uses a private directory, no-follow file opens, file-owner and permissions checks, cross-process advisory `flock`, temporary pending file, `fsync`, atomic rename and directory `fsync`. Pending writes require manual forensic review rather than automatic deletion/retry. Crash **after** a durable commit can leave an uncertain response; reopening and checking an independently pinned head resolves whether the record committed. A valid-prefix rollback is detectable **only** if a separate trusted actor retained the later head. No automatic recovery permits or production operations are granted.

## API and trust boundaries

- `forensicPublicationPolicyDigest({reviewers,quorum})` canonically commits to sorted reviewer IDs and Ed25519 public key digests. Reviewer `readLatest` callbacks are not invoked.
- `forensicPublicationRotationBytes(body)` and `forensicPublicationSigningBytes(body,rotationApprovals)` define domain-separated signature inputs for an external signer. Signatures must come from independently controlled signers, **not** from this prototype.
- `verifyOfflineForensicPublicationHistory({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publications,expectedHead,expectedForensicHead?})` verifies the full signed chain and exact caller-pinned head.
- `verifyOfflinePublishedForensicEvidenceBundle({...})` also validates the underlying complete forensic evidence bytes, reviewer epochs and exact published forensic head.
- `createOfflineForensicPublicationStore({...})` returns `append({record,expectedHead})`, `inspect({expectedHead?})` and `inspectHistory({expectedHead?})`. The append `expectedHead` is a compare-and-swap precondition; it does not prove external trust.

All APIs return `productionApproved:false`. Callers must **not** treat `verified:true` as evidence of independent hosting, a trusted timestamp, offsite retention, protected keys, production checkout or actual recovery authorization.

## Security tests

`node --test tests/objective31ib-head-publication.test.mjs` exercises signed publication, durable restart, valid reviewer rotation, missing/forged approvals, witness forgery/duplicate, cross-domain signature substitution, rollback, timestamp/count regression, external pin mismatch, tampering, numbered-history gaps, symlinks, key-role separation, retired-key reactivation, malformed input, composite epoch binding, cross-process locking, concurrent CAS, and **actual child-process SIGKILL** after both pending-file sync and committed-file sync.

## Unresolved deployment gates

1. No independent witness service, protected witness/reviewer signing keys, certificate chain or authenticated reviewer transition endpoint.
2. No remote publication, immutable offsite retention, trusted timestamp or globally monotonic rollback pin. The local store cannot independently detect deletion of the last valid record.
3. No atomic transaction between the forensic journal, witness publication store, recovery ledger and anchor; no autonomous resolution of ambiguous multi-resource crashes.
4. Compromised historical keys can forge backdated assertions without an independently retained earlier publication and trusted time. Old-quorum approval does not prove consent by a new key holder.
5. No real customer data, Shopify integration, production permission, live orders or deployment. Main Engineering's v0.32 UI remains separate.

**Next Objective 31J:** independently retained, signed reviewer-policy transition certificates with new-key proof of possession, an explicit witness-publication outbox/acknowledgement boundary, and crash-consistent reconciliation. Preserve this release and earlier source archives.
