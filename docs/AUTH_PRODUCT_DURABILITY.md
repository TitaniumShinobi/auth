# Durable product authentication contract — v1

AUTH's setup wizard installs a development-time contract. It never becomes a normal application request dependency. This layer wraps the existing capability evaluator; it does not change provider, session, enrollment, storage or VVAULT runtime behavior.

## Install, observe, establish

Use a current AUTH checkout and Node 20 or newer. Existing known app configs remain supported. For any other product, provide its existing AUTH-compatible app config explicitly:

```sh
node /path/to/auth/scripts/auth-cli.mjs setup --repo /path/to/product --app example \
  --config /reviewed/product-auth-config.json --adapter /reviewed/observe.mjs \
  --inputs /reviewed/inputs.json --authorize
```

`inputs.json` names non-secret, product-relative artifact and configuration files:

```json
{"artifact":["dist/product.js"],"configuration":["config/auth-public.json"]}
```

Use the actual packaged/build artifact and non-secret configuration or secret-reference/version manifest. Do not use secrets as observations or configuration evidence. The command never builds the product: the product pipeline must build first. No wildcards or executable commands are accepted in these paths. Symlinked bundle/files are rejected. Existing bundle/workflow files are not overwritten. Legacy `.auth-kit` config/report files may coexist, but a durable contract cannot be silently reinstalled/reset.

When an adapter or input list is omitted, setup still creates an UNESTABLISHED bundle with an explicitly failing observer placeholder. It cannot PASS or establish until a product-owned collector and actual artifact/configuration inputs have been supplied. Edit the unestablished contract's input list and observer deliberately before establishment. After establishment, these are pinned; incompatible integration/tool changes require a supported future upgrade or AUTH DEVELOPMENT handoff, not deletion/reinstallation.

Canonical installed files:

| Path | Executable purpose |
| --- | --- |
| `.auth-kit/contract.json` | Product identity, contract version, pinned profile/input policy, state, history sequence/head and provenance digest |
| `.auth-kit/observe.mjs` | Product-owned evidence collector, executed with Node, bounded to 120 seconds; hash pinned at establishment |
| `.auth-kit/verify.mjs` | Canonical entrypoint; automatically loads and validates history/baselines |
| `.auth-kit/ci.mjs` | Build/release gate calling that same entrypoint |
| `.auth-kit/runtime/*.mjs` | Vendored verifier and dependencies; no sibling AUTH/VVAULT checkout needed |
| `.auth-kit/provenance.json` | Catalog/source identity and SHA-256 hashes of verifier/runtime/workflow files |
| `.auth-kit/baseline/000001.json`, etc. | Immutable numbered verification snapshots |
| `.auth-kit/history/000001.json`, etc. | Append-only, hash-linked establishment/advancement/amendment events |
| `.auth-kit/reports/<run-uuid>.json` | Durable verification outcomes, including failures where bundle remains accessible |
| `.github/workflows/auth-product-contract.yml` | Generated gate; required contents are hashed |
| `.auth-kit/auth.config.json`, `ADAPTER.md`, `reports/latest.md` | Existing setup configuration/instructions/report; not substitutes for a baseline |

The collector reads a JSON context from stdin containing `productId`, `revision`, `commit`, `artifactDigest`, `configurationDigest`, `observedAt`, and `runId`. Return JSON `{binding, adapter, independence}`. `binding` must echo the exact context. `adapter` uses the existing schemaVersion 1 capability format, with matching productId/revision. It must actually gather evidence; echoing context is necessary, not proof that observations are truthful. The revision digest binds Git HEAD and current tracked/unignored product files, including dirty changes; `.auth-kit` is excluded because verification reports/history necessarily change. Artifact/configuration contents are hashed separately, including ignored build outputs. Changes during collection fail verification. Submodule/symlink source trees require a supported explicit integration; they do not silently pass.

`independence` requires `wizardStopped:true`, `authOrchestrationRequests:0`, `runtimePassed:true`, and nonempty evidence references. The product collector must test the relevant packaged runtime without the wizard/service orchestration process, including its applicable auth flow. This is an attestation boundary, not automatic network instrumentation. The included fixture proves only a synthetic standalone product. It is not GRID acceptance.

Trusted authority evidence uses the existing format. Supply `AUTH_PRODUCT_AUTHORITY_EVIDENCE` and separately trusted `AUTH_PRODUCT_AUTHORITY_SHA256` through operator/CI configuration. The adapter cannot provide its own trusted authority assertions. Missing applicable authority evidence remains unresolved.

## Canonical commands

```sh
cd /path/to/product
node .auth-kit/verify.mjs verify
node .auth-kit/verify.mjs establish /reviewed/establishment.json
node .auth-kit/verify.mjs maintain
node .auth-kit/verify.mjs advance /reviewed/advancement.json
node .auth-kit/verify.mjs amend /reviewed/amendment.json
```

The equivalent trusted external invocation is `node /trusted/auth/scripts/auth-cli.mjs product verify --repo /path/to/product` (or `bin/auth product ...` where AUTH's local Node launcher is available). The installed command itself only needs Node and the product's collector dependencies.

VERIFY never writes a baseline or creates missing history. UNESTABLISHED reports cannot claim preservation. Existing baseline/history absence, tampering, truncation, observer/gate drift, wrong revision, or historical check regression returns nonzero. Reports retain profile and full verification separately. A narrow profile does not hide historical passing checks, even outside that profile. Legacy `auth wizard --adapter` remains a low-level diagnostic API, explicitly marked `NOT_ASSESSED_USE_PRODUCT_VERIFY`; it is not the product release gate.

## Authorization and advancement

After inspecting the current VERIFY report, supply a reviewed authorization file **outside product source inputs**:

```json
{
  "authorized": true,
  "operation": "establish",
  "productId": "example",
  "revision": "exact-binding-revision-from-current-report",
  "expectedHead": null,
  "expectedContractDigest": "contractDigest-from-current-report",
  "observerDigest": "observerDigest-from-current-report",
  "operator": "reviewing-owner",
  "reason": "Reviewed first integration and runtime evidence",
  "runId": "approval-reference-123",
  "retireChecks": []
}
```

For subsequent operations, use the current history digest as `expectedHead`. Fresh evidence is collected again; stale authorization fails. `advance` preserves every historical passing check. Retirement requires `operation:"amend"` and exact `retireChecks` such as `providers.github/supported`; retiring a capability requires explicitly listing every historical check being removed. A general ACT authorization is not accepted. Remaining current applicable requirements still have to pass; amendment cannot turn a failing applicable implementation into success.

Every event records prior contract/baseline digest, new baseline digest, prior/new history digest, product/revision/catalog snapshot, exact changed checks, retirement list, authorization/operator/reason, timestamp/run identity, and artifact/configuration provenance. Previous files are never overwritten. An exclusive advancement lock and compare-before-write reject concurrent advancement. Interrupted partial writes fail closed; an operator must investigate them rather than reset history.

Authorization JSON is an explicit local approval record, not a digital signature or independent proof of the approver's identity. Protect its creation and review externally for release use.

## Catalog upgrades and long-lived products

`maintain` performs the same evidence collection, integrity checks, historical comparison and VERIFY. Each history entry retains its catalog ID/family/check snapshot. Compatible additive catalog changes use an in-memory identity migration: every old capability, family and check must remain represented. Nothing is discarded. A subsequent authorized advance records the current catalog without rewriting old entries.

Renamed/removed/ambiguous checks, unsupported catalog versions or contract schema versions return a migration-required non-PASS result. They must go to AUTH DEVELOPMENT. Reusing an existing check ID for different semantics is prohibited; this mechanism cannot prove that English meaning or arbitrary verifier code is unchanged. Pinned verifier hashes detect local code drift. A general tool/observer upgrade installer and arbitrary semantic migration system are deliberately not supplied in v1; unsupported upgrades remain blocked.

Provider/platform/callback/session drift is caught when product collectors exercise those applicable capabilities. This is not a universal provider-change detector. Scheduling maintenance in CI is optional and outside application runtime. Existing blocker-handoff generation is reused; no ad hoc repair is authorized by a blocker.

## Local and external enforcement

The generated workflow has job ID `auth-product-contract` under workflow `AUTH product contract`. It calls `node .auth-kit/ci.mjs verify`. It deliberately does not guess dependency-install, build, secret provisioning or product test commands. A product pipeline must supply those prerequisites before invoking the gate. The minimal standalone workflow fails when evidence/build prerequisites are absent. Provide a reviewed complete workflow with setup `--gate /reviewed/auth-product-contract.yml` to include the product's prerequisites and the literal `node .auth-kit/ci.mjs verify` command. Its bytes are then pinned automatically. Presence of that command is not proof of CI execution; external enforcement must verify the check actually ran. After establishment workflow changes require a supported upgrade; do not hand-edit hashes.

A repository writer can remove the entire local workflow, replace the verifier or rewrite a self-consistent history. No local file can prevent that authority. For mature releases, an independently managed required status check must:

1. Run a trusted, pinned AUTH verifier outside candidate product code.
2. Require the product bundle and verifier/gate hashes.
3. Supply `AUTH_CONTRACT_CHECKPOINT` with the externally approved current history head; advance this external checkpoint only after reviewing a contract amendment/advancement.
4. Bind its check result to the exact candidate commit/artifact and require PASS in branch/release protection.
5. Isolate the product collector as untrusted repository code; do not expose deployment secrets to it.

The CLI supports trusted external verification and checkpoint comparison. AUTH does **not** configure hosted branch protection or publish a remote required status automatically. Workflow installation alone is not external enforcement. Complete rollback to an older locally consistent bundle is detected only with an externally retained checkpoint.

## Distribution boundary

Source/development retains the full kit, provenance, history and build gate. Packages ship only their required authentication runtime/adapters/configuration and secure user-session storage. They need not ship this wizard, development secrets, reports or baselines. A stopped wizard is not permission to disable an independently required identity authority or session security check. Real product independence must be demonstrated by its collector and live acceptance, separately from AUTH's synthetic tests.

## Git executable discovery

Setup/verification invokes Git without a shell. It selects an executable from absolute PATH entries, then standard Windows Git installation locations derived from ProgramFiles/ProgramW6432/LOCALAPPDATA. Case-insensitive Windows environment names are supported. Override with an absolute `AUTH_GIT_EXECUTABLE` path; an invalid override fails rather than falling back. Each selection must pass `--version`. Discovery errors retain a diagnostic without echoing repository or credential output. On PowerShell, for example: `$env:AUTH_GIT_EXECUTABLE = (Get-Command git.exe -CommandType Application).Source`. Installations created before this fix remain pinned to their earlier runtime; do not hand-edit their provenance.

## Large repository enumeration

Git path inventories are consumed asynchronously with backpressure and NUL record parsing; raw stdout is never captured with spawnSync/maxBuffer. UTF-8 records may span chunks; invalid encoding or an unterminated record fails closed. Parsing holds at most one filename (1 MiB per-name ceiling, not an inventory-size limit). Existing per-path hash metadata is retained for canonical sorted hashing and before/after preservation comparison; memory still scales with file count, not a claim of constant-memory snapshots. Duplicate paths retain their existing deterministic meaning. Only the existing .auth-kit exclusion applies; .tmp is not excluded.

Windows inventory uses read-only `git -c core.longpaths=true ls-files -z --cached --others --exclude-standard` and extended filesystem paths. No Git config is changed. GIT_OPTIONAL_LOCKS=0 prevents optional index refresh writes. Any stderr diagnostic, nonzero exit, spawn failure or truncated record invalidates the entire run. No candidate or establishment accepts partial enumeration. Inspect the same command locally to diagnose access/long-path warnings without forwarding sensitive filenames/logs. Existing OS/filesystem limits still cause a closed failure, not implicit exclusions.
