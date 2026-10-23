# Objective 35M — per-receipt customer confirmation (offline only)

Source release: v0.30.109; parent v0.30.108 (35L). No Shopify reads or writes.

## Customer flow

1. Import a non-authorizing 30-minute multi-design review checklist. It contains
   no private grants and never restores saved designs on import.
2. Reopen a PRIVATE local saved-design receipt using the loopback editor. This
   loads a preview but **does not** add it to the multi-design review.
3. Select **Confirm reopened private receipt for local review**. The ephemeral
   consent controller checks the exact public checklist binding and the local
   readiness API checks owner, revision, product/variant and design digest twice.
4. The editor shows confirmed and remaining receipt counts; each receipt must
   be independently confirmed. **Cancel receipt confirmation** forgets the staged
   grant without consuming the checklist entry.
5. Clearing the checklist invalidates pending confirmations. Import and receipt
   file-read races are rejected; stale responses cannot reopen earlier selections.

## Security and accessibility

`src/preview-multidesign-confirmation.mjs` stores a private grant only in closure
memory, never exposes it via status, DOM, export or order metadata. All statuses
are non-authorizing. Cancellation during asynchronous readiness prevents review
mutation; duplicate confirmation and consumed-reference replay are rejected.
The browser interface provides `aria-live` progress, disabled-by-default confirm
controls, explicit cancellation, keyboard focus after receipt staging and after
confirmation, and generic refusal text that does not expose server exception data.
Any provisional artwork object URLs are revoked on failure.

## Verification

Run `node --test tests/objective35m-multidesign-recovery-confirmation.test.mjs`,
`npm test`, and the four offline asset/staging checks. Local synthetic loopback
owner grants do not constitute hosted customer authentication. Browser-native
acceptance, manufacturing approval, authoritative catalog/pricing, persistent
customer storage, cart/order integration, and Main Engineering staging acceptance
remain open.
