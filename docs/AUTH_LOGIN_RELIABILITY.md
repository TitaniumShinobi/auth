# Login reliability: operator contract and rollout plan

## Incident and evidence boundary

The 2026-10-08 production handoff reports successful Google identity verification followed by a database trigger rejecting a returning `NORMAL` session: code expected migration `0039_returning_owner_session_without_device_gate.up.sql`, but the enrollment ledger had not received it. The owner reports transactional application fixed login. AUTH did not apply or independently query that migration.

Read-only host inspection in this task found `/opt/auth` resolving to revision `5f1176186b3bab33769745dfce5f1d1e127ffaeb`, `/opt/vvault-public` resolving to `540c248e19c541b8a6bf53154e5b527b7441d4a1`, both services active, root capacity 90%, and 3,470,352 KiB available (about 3.31 GiB). No deployment or database writes occurred.

The read-only recovered production deployment script (SHA-256 `c5410372b282d0e9c33a54f7071095b87e8a76de0f9ec4389e01ccb941d2d1fb`) has full-mode backups/migration handling, but backend-only skips migrations and checks shallow readiness after restart. The serving 540c248e tree contains no tracked 0039 artifact. Local `0039_paired_welcome_outbox.up.sql` is an untracked proposal on `hotfix/vvault-recovery-email`, with header referencing older deployment 6234b6bf; no committed history was found for it. Its SHA-256 is `6b6266344e90cf652c3bbbd1883598ade6b39b2f8e57cca4c8bc1434e7335a8c`. This is an uncommitted numbering collision, not proof of two committed migrations. Production's different 0039 was applied separately according to the owner. Exact ledger + semantic artifact + SHA-256 must agree; prefix alone is never authority.

## Signals

- `/health`: process liveness only. Safe for supervision, not deployment admission.
- `/ready`: process/routes only; `authenticationReady:null`. Existing consumers remain compatible, but this is not a login-health signal.
- `/ready/auth`: 200 only with fresh, complete, serving-bound authentication proof. Missing adapter, stale proof, dependency failure, missing schema, failed session or failed callback yields 503. Never substitutes local storage or synthetic authority for the configured database.
- Browser callback failures: explicit recovery page and server-generated `X-Request-ID`; JSON clients retain a structured `RECOVERABLE_ERROR`. Valid native transactions preserve registered loopback/state and carry a sanitized reference. Failure handling never replays OAuth exchange/session creation.

## Release manifest and host adapter

AUTH's generic policy is `scripts/auth-release-reliability.mjs`; its executable CLI is:

```
node scripts/auth-cli.mjs reliability check /absolute/manifest.json /absolute/adapter.mjs ADAPTER_SHA256
```

The manifest (`life.auth.release-reliability/1`) declares `service`, candidate `revision`, SHA-256 `runtimeDigest` and `configurationDigest`, `databaseAuthority` (non-secret identity/reference), and nonempty `requiredMigrations:[{ledger,id,semanticId,artifactName,sourcePath,sha256}]`. It must come from the reviewed release contract, not guessed numbering or a different checkout. `databaseBounds` specifies positive `connectTimeoutMs`, `statementTimeoutMs`, `acquireTimeoutMs` (each <=10000), and `maxConnections` (<=100). Proposed initial bounds: 3000/3000/3000 milliseconds and 10 connections, subject to DB operator capacity review. No DSN or credential belongs in the manifest.

Set `diskFloorBytes` >=5368709120 and `diskFloorFraction` >=0.15. The gate uses the larger floor. Warning starts below the larger of 8 GiB or 20%; at/below required headroom the deployment gate refuses. Current observed host headroom fails this policy. Budget peak staging/build space separately; stage must abort before crossing the floor. Never reclaim canonical files, databases, snapshots, or recovery material merely to pass.

A reviewed, SHA-pinned **AUTH-owned operator adapter** implements `observeReadOnly(manifest,{signal})` and `invalidatePool()`. It uses only existing authorized protected datasource references; never copies another product's credentials. Observation must include:

- fresh timestamp and exact candidate artifact/config binding; serving revision/artifact separately for post-deploy/runtime checks;
- provider configuration, canonical database identity, successful connectivity and pool validation, effective driver timeout/pool bounds;
- actual applied migration rows including exact ledger/ID/checksum;
- separate controlled session-issuance and callback-completion proof, each binding `manifestDigest`, timestamp, result, sanitized references, `controlledFixture:true`, `cleanupVerified:true`;
- measured filesystem space (use exported `diskObservation`), bounded logging, verified alert delivery, failed-staging cleanup, active/rollback release identities and classified release artifacts.

Provider configuration is not session/callback proof. A memory-only fixture cannot attest canonical DB behavior; use approved isolated fixtures exercising the relevant schema/trigger in the target contract without real-user credentials. Observation reads retained fresh proof; it must not create sessions or replay codes during a health poll. Proof max age is 60 seconds, so the operator must provide a safe regularly refreshed controlled-proof producer or the endpoint stays unready. That producer is an outstanding infrastructure dependency, not implemented by these adapters implicitly.

Read-only connection resets/refusals may retry once after invalidating the pool, within a bounded deadline. Timeouts and unknown outcomes never retry. Adapters MUST honor AbortSignal and configure driver-side connect/query/acquire timeouts; Promise timeouts alone do not cancel SQL. Mutating session issuance, token exchange, migrations and publication are never automatically replayed. No fallback authority is allowed.

`guardedRelease(manifest,adapter,authorization)` requires exact manifest-bound operator authorization and a unique run ID. The host implements `stage`, `publish`, `restart`, `rollback`, `cleanupStaging`, `retainReleases`. Gates run before staging, immediately before publication/restart, and against the serving artifact afterward. Cleanup is limited to the run-owned stage, including partial-stage errors. Rollback restores a compatible prior artifact, never database state. Retention receives only verified disposable artifact IDs, preserving active plus one rollback and all unclassified/canonical/recovery material. Host adapter path validation and transactional publication remain deployment-owner responsibilities. The existing VVAULT deploy script is NOT automatically wrapped by adding this module.

## Monitoring and diagnosis

`auth reliability monitor ...` uses serving-mode checks: exit 0 healthy, 2 unready, 3 capacity warning. It exports only sanitized check IDs/results/alerts. `templates/reliability/` contains review-only service/timer and journald-limit templates. They are NOT installed or enabled. Wire the one-minute timer to the existing approved alert channel; verify delivery, including failure of the monitor itself, before marking alert delivery established. Journal proposal: 512 MiB maximum, 5 GiB keep-free, 14 days, rate limiting; host-wide impact and forensic retention require operator approval. File logs need equivalent existing rotation, verified by the adapter.

For failures: use the correlation ID; compare serving artifact/config with the release manifest; test authenticated DB reachability with a bounded read; compare exact ledger checksums; inspect session/callback proof independently. Do not log SQL, provider tokens, DSNs, passwords or raw exceptions. Schema mismatch goes to the schema owner for a reviewed forward migration, never blind `apply_all` or inferred ledger backfill.

## Explicit deployment plan — approval required, nothing activated

1. VVAULT production owner supplies exact serving/candidate migration paths, ledger identifiers/checksums and current non-secret compatibility observations. Keep production's verified 0039 fix; do not substitute local paired-welcome 0039.
2. Review the concrete `scripts/auth-production-host.mjs` / `auth-host-database.py` adapter and `integrations/vvault/deployment-reliability.patch`. The exact schema identity is retained in `config/reliability/vvault-production-schema.json`; this is not a completed release manifest. Recover the missing SQL source, then prepare a manifest with the protected host configuration. Effective application timeout/pool proof, safe acceptance producer, alert destination, and rollback compatibility remain operator inputs.
3. Review this AUTH delta against the actual serving release before selecting a candidate; do not deploy the entire development branch blindly. Build and run focused regressions; bind hashes to that candidate.
4. Review disk cleanup candidates; retain canonical/recovery data and active+rollback artifacts. Obtain a fresh filesystem measurement above the safety floor and staging reserve. No cleanup is performed in this task.
5. Submit the exact candidate, manifest, adapter digest, non-secret `AUTH_RELIABILITY_MANIFEST`, `AUTH_RELIABILITY_ADAPTER`, `AUTH_RELIABILITY_ADAPTER_SHA256` references, approved monitor/alert config and rollback artifact for explicit deployment approval.
6. After approval, integrate the guarded lifecycle into the deployment owner's existing pipeline **before** publish/restart; install approved log/monitor configuration. No migrations are executed by AUTH. Validate `/ready/auth`, alert delivery, and controlled returning-user callback/session acceptance before declaring production fixed.

Source tests prove the generic guard and recovery behavior. They do not establish deployment integration, live canonical DB readiness, notification delivery, production retention, or production login acceptance. These remain explicit owner/operator gates.

## Source integration receipt

See [VVAULT integration](../integrations/vvault/README.md) for exact host fields, manifest preparation, failure gates, protected receipt trust, and deployment limits. Source code and deterministic deployment tests exist; nothing is installed or production-proven. The old local script is not the patch baseline. No GRID authority evidence is used.
