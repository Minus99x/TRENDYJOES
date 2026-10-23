# Objective 35H — Offline customer review → signed metadata → synthetic observation

This change adds `createOfflineReviewReceiptBoundary` as a **non-authorizing local integration seam**. It composes the actual saved-design readiness contract with the existing offline V2 metadata issuer, re-reads the design after asynchronous issuance, and fails closed if revision/product/variant/composition changes. It returns a strict allowlisted, frozen result containing only the design binding and two signed receipt properties. Local owner capabilities and auth context are never returned or passed to the issuer as design fields.

**Trust separation:** local owner token authorizes reading a *local* draft only. It is not Shopify customer authentication. The injected V2 issuer must independently resolve a synthetic trusted principal and current server-owned design record. Its HMAC and replay ledger are offline fixtures, not hosted services. This boundary's receipt shape checks are not cryptographic verification: the existing V2 authority verifies the signature and current design again at the synthetic observation seam, where durable atomic nonce/order claiming occurs. The second local review narrows—but cannot eliminate—the update race; final verification remains mandatory.

The 18 new tests cover real local saved-design creation, Shopify draft snapshot review, synthetic principal and design ledger binding, receipt issuance, synthetic observed-order transition, idempotent retry, owner and variant substitution, stale revisions, between-read updates, tampered readiness/issuer flags, unsafe property injection, and forbidden cart/checkout output. These tests do **not** prove a live Shopify cart, checkout, order, payment, hosted customer identity, or production manufacturing approval.

No store or network mutations are introduced. The only storage writes in tests are local temporary design/ledger fixtures. No static preview, 2D/3D editor, GLB import/calibration, theme or manufacturing geometry files were changed.

Reproduce: `node --test tests/objective35h-review-receipt-boundary.test.mjs`; `npm test`.
