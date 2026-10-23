# Preserved pre-GitHub TrendyJoes local histories

The four Git bundles below were verified locally with `git bundle verify`, uploaded as original binary Git blobs, and their Git blob SHA-1s matched the independently computed local values. Each bundle has its own historical graph; **these graphs are not a single linear ancestry**. The newly imported v0.30.172 snapshot is committed separately on `dev/universal-studio-migration`. No local historical commit ID is falsely represented as a GitHub branch commit.

| Recoverable Git bundle | Local history HEAD | Exact bundle SHA-256 |
|---|---|---|
| [TRENDYJOES_LOCAL_GIT_18_CHANGES.bundle](../.migration-history/TRENDYJOES_LOCAL_GIT_18_CHANGES.bundle) | `fa16d46cf48eb4465e64e09794560da5724f5c5e` | `6ea4b2a3af2040f57e90c0d9a851db91b77cdf5776117a2834e1811988891224` |
| [TRENDYJOES_35AY_35BB_LOCAL_11_COMMITS.bundle](../.migration-history/TRENDYJOES_35AY_35BB_LOCAL_11_COMMITS.bundle) | `ce5a4a9ba9c297fa86d1536ef2e651d4eeafccca` | `97269d3d754a4e4f21acd7705d70ed1515f0770abf9593d979612afdc11c13ab` |
| [TRENDYJOES_35BC_35BJ_LOCAL_GIT.bundle](../.migration-history/TRENDYJOES_35BC_35BJ_LOCAL_GIT.bundle) | `3407fd5809fba8d5514a1921a68e19a1bf52bc8f` | `d68d1281047da9da47ec4922d8d13d19b14218dc66688398ae1491da116be30a` |
| [TRENDYJOES_35BK_35BZ_LOCAL_GIT.bundle](../.migration-history/TRENDYJOES_35BK_35BZ_LOCAL_GIT.bundle) | `558c2f802833a01fab65eb52f5b1abc5db1a8e2a` | `0b0430ca48f6cd188545ba13a63fb65bd2671e9a7a80d2fa457b0b1b91b7929b` |

Recovery: download a bundle, run `git bundle verify <file.bundle>` inside an initialized repository, then `git clone <file.bundle> <destination>` to examine its original local history. These are offline development records, not checkout authority, deployable releases, or Shopify production evidence. The original library copies remain at `/TrendyJoes Night Watch/`.
