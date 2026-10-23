# Objective 32C — Authenticated supervisory review of 32B forensic orphan reports

**Scope:** offline verification-only, QA prototype. No Shopify reads or writes, customer data, production, remediation, checkout, manufacturing, authorization, or network calls.

## Threat boundary

`src/offline-orphan-supervisor-decision.mjs` accepts the **complete** Objective 32B read-only report and a separate trusted, externally retained set of pins (`reportDigest`, `manifestDigest`, exact `head`, `epoch`, `transitionDigest`, `recordsDigest`). It recomputes the report's canonical SHA-256 and every anomaly's canonical evidence digest, checks the issue count and status, and rejects changed classifications, archive observations, pins, or report safety flags. The report digest is **unkeyed**; it is not proof of independent custody, underlying observations, or trusted time. Pins must genuinely originate from a different trusted channel. A caller copying pins from the same untrusted report has NOT gained independent authentication.

A supervisory statement is domain-separated Ed25519-signed by a strict majority quorum of **independently trusted** reviewer public keys. It binds the report digest, exact manifest/receipt-chain/witness-epoch pins, a canonical digest of **every** anomaly including its class, directory and observed evidence bytes, the complete reviewer-policy digest, disposition, short validity window (at most five minutes), decision ID, nonce and replay-snapshot digest. Every signer ID and signature must be unique, canonical, ordered, and verifiable. The reviewer policy digest must also be supplied from a separately trusted source as `expectedReviewerPolicyDigest`; a caller-controlled signer list is not a trust anchor.

Only `REQUIRE_INDEPENDENT_REVIEW` and `REJECT_EVIDENCE` are allowed when issues exist. `NO_ANOMALIES_REVIEWED` is permitted only for a no-issue report. No disposition authorizes deletion, repair, quarantine, manufacturing, acknowledgement, checkout or release.

## Replay and concurrency — important limitation

The caller supplies canonical replay-snapshot **bytes** and a separately pinned SHA-256. The snapshot includes all consumed decision IDs and nonces, sorted and unique. A decision is rejected when its ID or nonce is already consumed or when its signed replay digest is stale or does not match the independently pinned snapshot. Missing clock, missing pins, altered snapshot, replayed ID/nonce, expired statement and forged quorum all fail closed.

**This is read-only verification, NOT an at-most-once reservation.** Re-verifying an unchanged signed statement against the **same unchanged snapshot** can succeed again. A separate, atomic, durable, independently supervised replay-commit protocol is REQUIRED before any downstream operation can be considered. This module does not implement that protocol, consume a nonce, store decisions, or authorize actions. A same-UID attacker, stale external pin, forged clock, or compromised reviewer key remains out of scope.

## API

- `offlineOrphanSupervisorPolicyDigest({reviewers,quorum})` — deterministic public-key policy digest; accepts Node Ed25519 public `KeyObject`s.
- `offlineOrphanReportIssueDigest(report)` — digest of exact anomalous evidence entries, sorted by directory and name digest; excludes informational signed archives and safe coordinator locks.
- `offlineOrphanSupervisorDecisionSigningBytes(body)` — canonical domain-separated signing bytes; rejects unknown fields and unsafe dispositions.
- `encodeOfflineOrphanReplaySnapshot({registryId,consumed})` — canonical bytes, consumed sorted by decision ID, unique nonces.
- `verifyOfflineOrphanSupervisorDecision({report,expectedPins,decision,reviewers,quorum,expectedReviewerPolicyDigest,replayBytes,expectedReplayDigest,nowMs})` — verifies signatures, pins, anomaly classes, freshness and replay membership; returns frozen **non-authorizing** evidence.

`decision` is `{body,signatures:[{reviewerId,signature}]}`; signature is canonical base64url Ed25519 (64 bytes). The `body` has `schema`, `registryId`, `reportDigest`, `manifestDigest`, `head`, `epoch`, `transitionDigest`, `recordsDigest`, `issueDigest`, `issueCount`, `disposition`, `decisionId`, `nonce`, `issuedAt`, `expiresAt`, `replayDigest`, `reviewerPolicyDigest`. Signature entries are sorted by reviewer ID. The replay snapshot is canonical JSON `{schema,registryId,consumed:[{decisionId,nonce}]}`.

## Tests and remaining gates

`node --test tests/objective32c-*.test.mjs` exercises real signed export-receipt archives through the existing 32B classifier, plus adversarial report tampering, altered pins, quorum forgeries, changed dispositions, clock edges, duplicate reviewers, replay ID/nonce collisions, rollback, noncanonical snapshots and read-only preservation. `npm test` runs the full editor/2D/3D/GLB/security regression suite.

Unfinished: independently deployed witnesses and supervisors, protected keys, trusted timestamps, offsite immutable retention, atomic replay consumption and cross-resource recovery, manufacturing geometry approval, hosted customer authentication, production GLBs, and real Shopify integration. This verifier does **not** change any of those statuses.
