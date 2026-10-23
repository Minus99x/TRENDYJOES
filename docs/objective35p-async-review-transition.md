# Objective 35P — fail-closed async multi-design review UI transitions

The local review readiness gate can take time. Previously an earlier review
rejection could overwrite the status shown after the customer cleared, removed
or reselected drafts. Two overlapping reviews could also present out of order.

`createLocalMultiReviewTransition` introduces a single-flight, generation-bound
presentation contract. Mutations invalidate the current generation, and both
fulfilled and rejected readiness results must match the current ticket before
touching UI. An older request cannot clear the busy state of a newer one.
The editor integrates invalidation on selection, removal, addition, clear and
atomic private receipt restoration. Review results remain non-authorizing.

No hosted customer authentication, Shopify cart, order, checkout, manufacturing
approval, production model approval or deployment is implied.
