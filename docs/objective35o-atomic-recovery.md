# Objective 35O — atomic local multi-design review restoration

This release introduces `createLocalMultiDesignReview().restore(entry, selected)` for the customer-facing recovery callback. It validates the complete private design binding, the requested selection and capacity **before one map insertion**. Unlike the previous two-step `add` then `select`, a failed selection or duplicate cannot leave a partially restored design. The existing `add`/`select` editing APIs remain unchanged.

The local checklist recovery seam also treats an explicit `false` acceptance result as a refusal rather than consuming the receipt. The callback must remain synchronous and transactionally fail before side effects. This is a local prototype, not a hosted customer authentication, production order or Shopify checkout guarantee.

Reproduce: `node --test tests/objective35o-atomic-recovery.test.mjs && npm test`.
