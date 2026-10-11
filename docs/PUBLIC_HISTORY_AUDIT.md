# Public branch and history audit

Audit date: 2026-10-11. Scope: all 31 local and `origin/*` branch refs and all 46 commits reachable from those refs. The audit was read-only and did not print candidate secret values.

## Checks

- inspected every branch-tip tree for committed `.env` files, key/certificate containers, databases, `data/`, secret directories, generated evidence/export directories, and obsolete runtime-copy instructions;
- searched every reachable commit for private-key markers and common high-confidence token prefixes using path-only output;
- reviewed branch containment for every match;
- reviewed the default branch for tracked runtime state and generated dependency/build directories.

## Findings

1. No branch tip contains a committed credential `.env`, private-key file, certificate container, SQLite/database file, `data/` directory, or secret directory. `.env.example` is the expected placeholder-only exception.
2. Two reachable historical compiled-test blobs contain private-key marker text at `dist/test/signingKeyEnv.test.js`: commits `80db0ccf17476897241ee7c5086a6762e640b2ed` and `c963a1951607a9af27bbc1eeffaf13ff38b8bf1a`. Both contain explicit fixture/test markers. They are test material, not evidence of a live private key. The former is reachable from `origin/release/grid-auth-github`; the latter is reachable from `origin/release/chatty-auth-production-handoff` and `origin/release/grid-auth-github`.
3. Git object metadata includes historical paths `.auth-runtime/enrollment/transactions.sqlite` and `export/grid-consumer-v2/verify/results/live-smoke.sqlite`, but neither path exists in any current local or `origin/*` branch-tip tree. Their bytes were not printed or treated as safe. Before a public-history rewrite is considered, the owner must determine whether these are synthetic fixtures or sensitive data.
4. Several non-default release branches retain superseded architectures and generated `dist/` artifacts. They are not release authorities. The default branch and future owner-approved tags are the only release candidates under the versioning policy.
5. No high-confidence AWS, GitHub-token, OpenAI-token, or non-fixture private-key signature was found in the reachable history scan.

## Disposition

Current default-branch publication is technically clean under these checks. Deleting public branches or rewriting history is intentionally not automated. If the owner confirms either historical SQLite object contains live or private data, follow AUTH-H4 in the human-action ledger: revoke/rotate affected credentials if relevant, authorize a coordinated history rewrite, and invalidate old clones/releases.

CI now performs full-history secret scanning on every default-branch push and pull request. Dependency review runs for pull requests.
