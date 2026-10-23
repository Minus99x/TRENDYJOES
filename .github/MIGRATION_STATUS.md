# TrendyJoes — private source migration checkpoint

**Source migrated:** 626 of 626 files from the independently SHA-256-verified v0.30.172 ZIP to `dev/universal-studio-migration`. Source Git tree SHA-1: `3adb200de5db14e100e6010ab90ad0da83fa07af`. GitHub commit: `f07a480139521d553d09c007dadba70d7a8b11bc`. Check `.github/SOURCE_PROVENANCE.json` for hashes.

`main` remains the stable administrative baseline. The offline Studio and tests are on the development branch. The history prior to this import remains preserved in Library Git bundles; the new GitHub import commits do not retain the original local commit IDs.

Protected 13+13 staging assets are the same bytes as in the source ZIP, but hosted Shopify staging has **not** been reconciled. Main57A's four protected differences are unresolved. This repository has no production/deployment authority.

CI runs offline Node regression and asset SHA-256 checks only, without Shopify credentials, API writes or deployment.
