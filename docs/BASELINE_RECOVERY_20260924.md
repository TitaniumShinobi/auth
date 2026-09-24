# AUTH baseline recovery — 2026-09-24

Scope: source/test recovery from deployed base `8ef31a3fe902bad241cbbe8c361b1eb46a9d25a7`. No deployment, credentials, production mutation, VVAULT changes, migration or GRID work.

## Eight reproduced failures

Original compiled auth/oauth run: 12 pass / 8 fail. Tests are identified by their original titles and base line numbers. All eight are stale expectations; no runtime correction or missing runtime prerequisite was established.

| Test (base file:line) | Expected → base actual | Historical authority | Smallest correction |
|---|---|---|---|
| Ask Hydro thread resolves to the canonical per-project Hydro singleton transcript (auth.test.ts:240) | 200 + canonical transcript → 404 | `bf60e5e` removed execution; pre-`3fe8da9` tests explicitly assert opt-in 501; `3fe8da9` restored older tests | Test default absence and opt-in moved response, forbid upstream calls |
| Ask Hydro status reports canonical readiness without leaking relay errors into the UI contract (auth.test.ts:316) | 200 configured → 404 | Same removal and recovered test history | Test default absence and explicit opt-in moved disposition |
| scratch project creation returns canonical project metadata and Ask readiness (auth.test.ts:369) | 201 + Ask bootstrap → 404 | Same history; optional scratch metadata route survived, Ask bootstrap did not | Test default absence, opt-in authentication, validation and metadata-only response |
| Ask Hydro message relay forwards attachments, grouping metadata, and canonical transcript path (auth.test.ts:446) | 200 + provider/storage relay → 404 | Same history | Test default absence, opt-in 501 and zero external execution |
| redirects OAuth callback to signup when product consent is missing (auth.test.ts:803) | 302 product root, no cookies → 403 explicit enrollment + identity cookies | `bf60e5e` has explicit ENROLLMENT_REQUIRED; pre-`3fe8da9` tests cover this contract; snapshot restored obsolete redirect expectation | Assert 403, no dead redirect, required consent and authenticated explicit continuation |
| live-lineage GRID routing and hosted native authorization preserve existing selectors (auth.test.ts:843) | /signin missing-consent redirect → registered loopback enrollment_required | `2860351` introduced test; `3301c10` honors explicit current consent snapshot; `8ef31a3` returns native enrollment failure before token issuance | Assert exact registered loopback, state, no code/cookie; prove explicit signup consent still completes code issuance |
| falls back to existing callback base env vars when explicit callback url is unset (oauth.test.ts:91) | 5173 callback → empty configured callback | `bf60e5e` origin enforcement; pre-`3fe8da9` fixture uses allowed 2048; snapshot substituted disallowed 5173 | Assert disallowed configuration is ignored; retain allowed-origin positive coverage |
| starts OAuth with the configured callback base when legacy callback env vars are present (oauth.test.ts:198) | redirect_uri 5173 → allowed request origin 2048 | Same origin policy and snapshot evidence | Assert allowed request origin fallback, never broaden allowlist |

No deployed-source staleness was established for these failures. No missing prerequisite commit is necessary to restore Hydro execution: it is deliberately outside AUTH. The historical pre-snapshot tests establish the intended boundary; recovering that entire snapshot would import unrelated changes. Current dirty `src/app.ts` also retains the Code-runtime moved disposition and explicit enrollment response; it is not imported or treated as release authority. Dirty source cannot justify adding product execution to this baseline.

Refresh replay coverage is recovered narrowly from `3fe8da9^:src/test/auth.test.ts`. New fetch spies infer the Node fetch signature, eliminating the obsolete RequestInfo references without suppression. The later frozen fetch-typing patch consequently requires reconciliation, not restoration of obsolete mocks.

## Verification boundary

Baseline TypeScript build: PASS. All tracked baseline test files (auth, oauth, githubBrowse): 30 passed, zero failed/skipped. Includes Chatty-shaped identity regression, missing consent, native explicit signup, invalid state and refresh rotation/replay.

The frozen package.json normal test wrapper references absent bin/node20, bin/npm20, wizard files, authorizationCode.test.ts, startup.test.ts, providerOwnerFlow.test.ts and ownerDatasourceKeychain.test.ts. The latter four have no file history in available refs. This recovery does not import untracked architecture to pretend those suites exist. Receipts name the actual complete tracked suites run via the existing Node runtime. This is a remaining packaging/test-entrypoint blocker, not a waiver or a claim that npm test passes.

Production rollback reference remains 8ef31a3fe902bad241cbbe8c361b1eb46a9d25a7. Source tests establish no live acceptance. Credential rotation/re-homing remains an independent hard production gate.
