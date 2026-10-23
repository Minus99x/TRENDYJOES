# Objective 34T — Visual-integrity protection for customer wording

**Offline-only Studio v0.30.90. No Shopify reads or writes, no hosted authentication, no durable customer storage, no manufacturing approval, no cart/checkout.**

## Reproduced failure in v0.30.89

The temporary text editor accepted Unicode bidirectional override/isolate controls, zero-width-only wording, C1 control characters, unpaired UTF-16 surrogates and combining-only text. These could appear blank or visually misleading while still enabling a design review. The original review boundary also accepted forged layer values without rechecking text validity.

## Implemented

`src/static-preview-contract.mjs` now validates customer wording at addition, review, and accessibility-summary boundaries. It rejects bidirectional formatting controls, select invisible format characters, DEL/C1 controls, malformed surrogate pairs, and text without any visible letter, number, punctuation or symbol. It preserves ordinary Arabic, Hebrew, Persian ZWNJ within words, Japanese, combining-accent sequences, and emoji ZWJ families. Customer wording remains local-only; no wording is added to summary output or accessibility announcements.

This check prevents visual deception in a **concept preview**, not all possible Unicode confusables or production artwork issues. It is not a substitute for server-side authentication, rendering proofs, supplier calibration or manufacturing inspection.

## Reproduce

`node --test tests/objective34t-unicode-visual-integrity.test.mjs` and `npm test` on Node 22.16.0. The focused test suite was first run against v0.30.89 and failed as expected on unsafe inputs. Rebuild the static-preview assets and offline integration manifest before packaging. Browser acceptance remains unverified if Chromium cannot navigate in the local execution environment.
