# Objective 34X — Uncommitted wording / review boundary

Local-only Universal Studio v0.30.94. No Shopify reads/writes, production deployment, storage, checkout, or manufacturing approval.

## Defect reproduced

When a customer already had committed lettering, the Review button stayed enabled while additional private wording remained in the composer. A prior open review summary also remained visible after the customer began typing. Consequently, the UI could show a review of older committed layers while the customer mistakenly believed the unadded wording was included.

## Repair

The review gate now requires both a valid committed design and an empty composer. Input immediately invalidates an open review summary and updates the disabled state and accessible explanation. Adding valid wording or clearing the composer restores review eligibility. A direct event-handler invocation is guarded separately, rather than relying solely on disabled button semantics. Existing privacy protections remain: uncommitted wording is not copied to summaries, status, storage, cart or network. All merchandise families retain the same behavior.

## Evidence boundary

The regression tests execute the actual static client event handlers against a deterministic offline DOM stand-in. They do not constitute native browser acceptance. Chromium/Playwright was attempted but localhost navigation was blocked by the execution environment (`net::ERR_BLOCKED_BY_ADMINISTRATOR`). Browser acceptance and native screen-reader behavior remain unverified. Generated staging files are offline integration candidates only, not installed.
