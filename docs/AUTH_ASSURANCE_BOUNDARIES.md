# Transient AUTH verification and release acceptance

AUTH runs on demand, writes product-owned source/tests or an operator-selected receipt, then exits. No installed kit, daemon, observer, network service or application runtime dependency is added by this workflow.

Four independent results are exposed under `assurance`:

- `source_integrity`: receipt-managed bytes match. Native `verification=PASS` and repair `NO_CHANGES` mean only this. A database outage can coexist with source PASS.
- `capability_conformance`: declared checks satisfy the selected profile. Observation references alone do not establish runtime acceptance.
- `runtime_acceptance`: independently reviewed, current product test evidence covers each applicable product/shared/contract check in the selected profile. Authority-owned checks additionally require conformance evidence through the existing authority verifier.
- `historical_continuity`: an independently pinned prior report's obligations remain satisfied. Without a pin this is INDETERMINATE, even when current conformance passes.

## Alignment ownership

Before `native align-plan`, supply `--auth-role IDENTITY_AUTHORITY|RELYING_PARTY` and `--auth-entrypoint <product-relative-file>`. Mixed frontend/backend repositories also require `--auth-runtime node|python`. A package.json is not proof that Node owns authentication. Entrypoints must be real files inside the target and match the selected runtime. Static probes are bounded and filtered by runtime; they are leads, not execution proof.

Generated identity-authority tests are explicitly metadata smoke tests. Generated relying-party tests fail with `PRODUCT_RUNTIME_TEST_REQUIRED` until the product owner supplies actual callback/session acceptance. They do not require the relying party to expose authorization-server metadata. Alignment never invents a working product acceptance test.

## Product-owned release gate

Keep observations, prior reviewed reports, runtime test receipts and CI in the product's chosen locations. CI invokes an immutable, reviewed AUTH revision ephemerally. Do not install AUTH into the application. Use:

```sh
node /reviewed-auth/scripts/auth-cli.mjs wizard \
  --adapter product-observations.json --operator VERIFY --profile RELYING_PARTY_CLIENT \
  --authority-evidence authority.json --authority-sha256 "$AUTHORITY_FILE_SHA256" \
  --baseline reviewed-report.json --baseline-digest "$BASELINE_CANONICAL_SHA256" --require-history \
  --runtime-evidence runtime-receipt.json --runtime-digest "$RUNTIME_CANONICAL_SHA256" --release
```

The baseline/runtime pins are SHA-256 of canonical JSON (`digest` exported by `auth-conformance-binding.mjs`); the existing authority pin is SHA-256 of file bytes. Obtain pins through independent review/CI policy, not from the candidate being accepted. A digest proves integrity, not authenticity by itself. Protect required status checks and pin policy outside the candidate branch. A writer controlling both checks and their trust anchors can replace them; AUTH does not claim otherwise.

`--require-history` rejects omitted, truncated or replaced baselines against the reviewed pin. It does not require the current product revision to equal the baseline revision. Advancing the trusted pin is a separate explicit product-contract review; ordinary VERIFY never advances it. A pinned report protects its captured obligations, not an unaudited claim to all prior history. For first adoption, review the initial report explicitly before configuring the continuity gate.

Runtime receipt schema `life.auth.runtime-acceptance/1` requires `productId`, exact `revision`, nonempty `runId`, ISO `issuedAt`/`expiresAt` (maximum 24 hours), and `checks: [{capabilityId, checkId, result, references}]`. Every applicable non-authority check must have exactly one result and nonempty sanitized execution references. Product-owned tests produce it; operator review supplies the independent pin. Missing proof never becomes PASS. `--release` exits nonzero unless profile and runtime acceptance pass, plus continuity when required. Native source integrity is separately verified with the target-bound native receipt where that source-installation workflow applies. Native subcommands reject `--release` and wizard evidence/history flags with `UNSUPPORTED_NATIVE_RELEASE_FLAG` and direct the caller to `auth wizard --operator VERIFY --release`. Unknown, duplicate, missing-value, positional, and wrong-subcommand options fail before target access or ACT. For example, `repair --dry-run` is rejected rather than silently performing a repair; dry-run is supported only by `native apply`.

Authority conformance retains the existing deployment-bound format, product/revision/authority matching, freshness and external file pin. Unbound legacy records are diagnostic material only and cannot satisfy release checks. There is no automatic conversion or resealing of old evidence.

## Bounded repair proof

ACT passes `{productId, revision, capabilityId, runId}` to the supported handler. The handler may return `{revision}` identifying resulting source; otherwise revision is unchanged. After completion AUTH calls `observe` with that context plus `resultingRevision` and `completedAt`.

The observer must execute affected behavior after completion and return its adapter plus `postRepairProof: {runId, capabilityId, revision, observedAt, checks}`. `observedAt` is milliseconds since epoch and `checks` enumerates every affected catalog check exercised. Exact run/capability/resulting-revision binding and time bounds are enforced. Cached observations without fresh proof return `FRESH_POST_REPAIR_PROOF_REQUIRED`, never verified success. A trusted observer remains responsible for honest execution; echoing a challenge alone does not prove behavior. ACT does not establish release acceptance: run the separate pinned VERIFY gate afterward.

Target receipts are bound to the canonical target directory. Copying identical source and a receipt into another repository fails `RECEIPT_TARGET_MISMATCH`. Relocation needs explicit re-review, not silent rebinding.

## Post-write verification

See the [M4 execution contract](AUTH_VERIFICATION_LANE.md) for automatic scoped lane results, legacy NOT_VERIFIED behavior, reviewed normal-build/CI integration, and the distinction between transaction completion and durable acceptance. Source receipts and historical release evidence retain their existing meaning.
