# auth post-write verification lane

M4 adds a transient execution coordinator, not an authentication service or a shared MDBO engine. Governing principles live in [auto/MDBO.md](../../auto/MDBO.md). Seven lanes remain visible: build, regression, behavioral, security, recovery, integration, acceptance.

## Reviewed specification

`life.auth.verification-lane/1` is an execution specification. It supplements existing capability observations, source receipts, and release evidence; it does not replace their schemas.

Required fields:

- `productId`, `revision`, `requestedOutcome`, `evidenceScope` (`isolated` or `live`).
- `authorizedPaths`: relative regular-file paths; no symlinks, traversal, or Git metadata.
- `inputs`: `{path, sha256}` entries pinning test and integration inputs.
- `normalBuildGate`: pinned input path identifying the product-owned test gate.
- `normalBuild`: literal `{argv, timeoutMs, maxOutputBytes}` for the ordinary product command.
- `lanes`: exactly seven entries `{id, required, checks, command? , exclusionReason?}`. Check IDs are catalog `capabilityId/checkId` pairs. Optional lanes require reviewed exclusion reasons. At least one lane is required.

`$NODE` selects the running Node interpreter. Other executables are literal paths or PATH-resolved names. Commands are reviewed executable authority, not a sandbox. No shell is used by the coordinator; a deliberately supplied shell remains executable authority and requires review like any command. Never place secrets in argv/specifications. Test commands must use isolated data and avoid writes outside their declared fixture/output scope.

Bounded commands have timeouts up to ten minutes and captured-output limits up to 4 MiB. Output is represented by a digest, not exported raw. Commands, timings, results, scope/outcome/spec digests and a candidate-file digest appear in the result. Spawn failure is BLOCKED; execution failure/timeout is FAIL; a required missing executor is NOT_VERIFIED. Excluded lanes remain visible and never become PASS.

A declaration of coverage is not independently proven by a command exit code. Review the actual mapped tests and retain disposable mutation evidence. A digest does not prove semantic correctness or provide authentication against a writer controlling all trust inputs.

## Invocation

Existing-file repair includes `verificationSpec` in the existing reviewed repair JSON. Its original `--repair-sha256` binds the nested specification. Binding revision is the repair's reviewed input revision. Inputs are checked before mutation and during verification; the post-repair candidate digest covers authorized paths.

Native `apply`, `repair`, and `migrate` accept `--verification-spec FILE --verification-sha256 FILE_SHA256`. For apply, binding revision is the reviewed `planDigest`; for repair/migrate it is the input `receiptDigest`. These are operation bindings, not invented Git revisions. Apply, repair, and migration permit pending test inputs only when their expected hashes match the reviewed operation postimages; other inputs are checked before mutation. Native repair/migration scopes cover receipt-managed files.

The lane runs automatically on supported native operations and the built-in existing-file repair, including no-change repair. Missing specifications return NOT_VERIFIED and CLI exit 2. Legacy source plans/receipts remain readable; source integrity PASS is not durable completion. Registered custom ACT modules without actual in-process coordinator results cannot claim durable completion.

Native source transaction finalization remains separate from lane acceptance. If a lane cannot run, the source receipt is still source-only; do not claim rollback occurred. The existing-file handler retains its in-process rollback on failing lane execution where its preimage can safely be restored. Neither path promises rollback of arbitrary test side effects or power-loss safety. A crashed process cannot export a successful lane result; recovery restores/finalizes source state only, and requires subsequent fresh behavioral verification.

`VERIFIED` requires all mandatory lanes plus the ordinary build gate to pass. An isolated result is not live-product acceptance. The wizard's existing capability/profile and fresh-observer requirements can still prevent `durableCompletion` even when the selected lane passes. Release acceptance still uses the separately pinned runtime/authority/history contract.

## Ordinary product build and CI

Alignment can install a reviewed dependency runner with `--dependency-spec FILE --dependency-sha256 SHA256`, using the existing bounded product-test command format. Generated CI executes that product-owned runner before its tests. Dependencies and commands must be reviewed for the product; auth never guesses Python/Node environment setup.

For an existing npm build/test entrypoint:

1. Align product-owned behavioral tests using the existing reviewed alignment plan.
2. Supply a reviewed repair template for `package.json`, including product/revision/capability, its expected `beforeSha256`, test evidence hashes, checks, and behavioral command.
3. Run `auth native build-plan --repo PRODUCT --repair-spec TEMPLATE --repair-sha256 SHA256 --script build|test --plan OUTPUT`.
4. Review the resulting exact replacement and its SHA-256; apply using the existing authorized `wizard --operator ACT --repair-spec OUTPUT --repair-sha256 SHA256` path.

Planning never mutates the product. It preserves the original command in a collision-checked `auth:original:build` or `auth:original:test` script and runs that script before `node test/auth-behavior.mjs`. This contains shell exits/comments while preserving failure behavior and existing lifecycle hooks. A source mismatch, missing command, existing invocation, or alias/lifecycle collision is rejected. This is a reviewed single-file repair, not a multi-file atomic migration. Non-npm builds require an explicit reviewed integration using existing repair contracts; there is no automatic arbitrary-build parser.

During lane verification, the normal build must execute the product-owned runner. The coordinator supplies a one-use temporary witness path/nonce; the runner records it only after its test command succeeds. Missing witness prevents VERIFIED even if the build exits zero. Witness files are cleaned afterward; normal product operation has no dependency on auth. Pin the real runner and relevant build files in `inputs`. This is execution evidence within the reviewed-command trust boundary, not protection against malicious test code forging a witness.

## Acceptance boundary

Focused disposable fixtures exercise success, each lane failure, missing executor/specification, timeout, missing dependency, drift, unsafe inputs, ordinary-build regression rejection, and existing-repair rollback. Synthetic commands exercising the protocol do not prove OAuth, browser focus, delivery, or live credentials. Production acceptance remains explicitly unverified until separately executed on the target candidate.

In-process ACT proof is bound to the product, reviewed revision, and fresh execution challenge. Mutating a returned report invalidates its issuance digest; serialized reports cannot substitute for current execution. Timeout cleanup targets subprocess groups on POSIX and uses `taskkill /T` on Windows. The Windows cleanup path requires platform acceptance; source review is not a Windows execution receipt.
