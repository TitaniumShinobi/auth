# VVAULT deployment integration — source only

This patch is against the **actual deployment script recovered read-only**, not the divergent local VVAULT checkout. `BASE-SHA256` pins its exact bytes. The full baseline is retained solely to reproduce patch application and deterministic deployment tests. It is not a complete VVAULT release.

No deployment, migrations, service/timer installation, credential changes, cleanup, or production tests are authorized by this artifact. Review and apply in the deployment owner's isolated source checkout. Reject baseline drift rather than applying fuzz:

```sh
sha256sum scripts/deployment/droplet-deploy-vvault.sh
# Must match BASE-SHA256
# Then, from that isolated checkout:
git apply --check /reviewed/auth/integrations/vvault/deployment-reliability.patch
git apply /reviewed/auth/integrations/vvault/deployment-reliability.patch
bash -n scripts/deployment/droplet-deploy-vvault.sh
```

## What changes

Both full and backend-only deployment require the protected datasource wiring and a passing AUTH candidate gate **before checking out candidate code**. The gate reads immutable Git blobs at the exact fetched candidate SHA. It repeats before publication/restart and checks serving process/artifacts afterward. Backend-only can no longer skip schema compatibility.

Automatic migration execution is deliberately removed from this deployment path. Apply missing schema only through the existing separately approved migration workflow, then rerun the gate. Backup-receipt creation in full mode remains. This avoids checking compatibility and then silently applying additional unreviewed migrations before publication. The 0039 artifact must be recovered into reviewed source; a ledger entry alone is insufficient.

Full mode copies the built frontend into a uniquely owned `/tmp/vvault-auth-stage.*` directory, checks capacity/readiness, and publishes only after the gate passes. EXIT cleanup touches only that stage. Candidate-gate failure before checkout does not reset/rewrite the serving checkout. Later failure uses the existing artifact rollback, never schema rollback. Active and previous code/frontend artifacts are retained; this patch introduces **no automatic pruning**. Retention classification/operational proof must be provided through the reviewed receipt; the generic policy never deletes canonical or recovery material.

The existing deployment remains an in-place checkout/build workflow. It is not magically an atomic immutable-release switch. There is a residual concurrent-reader boundary while the checkout changes; deployment owner must schedule the operation accordingly. The gate does not authorize running unreviewed candidate build hooks. Expensive full-mode build/backup can consume capacity; fresh gates prevent publication/restart below the floor but cannot recover capacity already consumed. Reserve and monitor peak build/backup space separately.

## Host configuration and trust

Install the reviewed AUTH toolkit in a root-owned, non-writable release directory, preserving this commit's file hashes (including JS dependencies and Python worker). The shell gate alone is not a trust root for replaceable sibling code. Keep all parent directories and configuration/receipt paths under operator control. No forwarded certificate, browser, product, or `/ready` claim supplies operational proof.

`auth-release-gate.sh` is invoked by the deployment script with `candidate|serving` and exact revision. Operator supplies non-secret references:

- `AUTH_RELEASE_GATE`: absolute path to this reviewed shell adapter.
- `AUTH_RELEASE_GATE_SHA256`: its approved SHA-256.
- `AUTH_RELIABILITY_TOOLKIT`: immutable AUTH toolkit root.
- `AUTH_RELIABILITY_HOST_CONFIG`: root-owned JSON host configuration (not group/world writable).
- `AUTH_RELIABILITY_HOST_CONFIG_SHA256`: its approved SHA-256.
- `AUTH_RELIABILITY_MANIFEST`: reviewed candidate manifest path, root-owned.

Host JSON fields (values below are descriptions, **not ready-to-run deployment configuration**):

| Field | Required value |
|---|---|
| `repository` | Absolute resolved VVAULT release repository with candidate Git object available |
| `python` | Existing VVAULT venv Python with psycopg; no dependency installation by probe |
| `schemaContract`, `schemaContractSha256` | Reviewed schema JSON and its SHA-256 |
| `databaseWorkerSha256` | SHA-256 of `scripts/auth-host-database.py` |
| `datasourceReference` | Actual protected, root-owned regular environment file containing exactly one `VVAULT_BODY_DATABASE_URL`; no symlink or copied credential |
| `configurationReferences` | Explicit protected regular files determining runtime config, including datasource reference; metadata is bound, contents never exported |
| `receiptPath` | Protected, fresh controlled acceptance/operations receipt described below |
| `diskMount` | Filesystem containing releases/build/publication; owner must ensure common mount or add separate checks before activation |
| `systemdService`, `serviceUser` | Exact serving service and expected Unix identity |
| `execStartSha256` | Canonical `digest(serviceInvocation(ExecStart))` from the AUTH adapter; binds executable/argv only, excluding changing PID/start timestamps |

Direct env-file parsing is intentionally narrow: no shell evaluation, interpolation or multi-file guessing. Unsupported encoding fails closed. Existing file access must be granted via existing approved service/deployment identity; do not copy the DSN into AUTH/GRID. Group-read 0640 is supported, group/world writes are rejected. Worker opens one fresh read-only connection, enforces driver connect/statement/lock bounds, closes/rolls back, and parent kills it at acquire deadline. It reads only database identity and exact ledger rows. This does **not** claim VVAULT's application connections already use these limits.

Build manifest with the reviewed host context (never run against production in this source-only task):

```sh
node /reviewed/auth/scripts/auth-production-gate.mjs prepare \
  /protected/host.json HOST_JSON_SHA256 CANDIDATE_COMMIT /protected/candidate-manifest.json
```

The builder refuses missing/mismatched migration source and duplicate semantic artifacts in the contracted migration directory. It hashes explicit authentication-critical sources plus migration artifacts; this digest does not claim to hash the whole Python dependency environment. Review the critical-path list and bind the deployment's dependency/runtime provenance in the receipt. The output is a candidate for review, not deployment authorization.

## Required fresh acceptance receipt

Receipt has `manifestDigest`, `observedAt` (maximum age 60 seconds), `providerConfiguration`, `runtimeDatabase:{poolValidated,bounds}`, `probes`, and `operations`. Each probe (`session_issuance`, `callback_completion`) carries `manifestDigest`, `observedAt`, `result`, `controlledFixture:true`, `cleanupVerified:true`, and sanitized `references`. `operations` contains verified bounded logging, alert delivery, failed-stage cleanup, and `active`, `rollback`, `releases` matching the generic retention policy. All required evidence must refer to the reviewed manifest and current operating configuration. A root-owned receipt is an operator trust boundary, not independent cryptographic attestation.

The producer must actually exercise canonical session insertion through the deployed schema with approved disposable fixtures: ACTIVE returning owner + NORMAL + NULL device succeeds; non-ACTIVE or wrong/untrusted supplied device is rejected; provider callback completion preserves the existing enrollment and linking gates. Cleanup must be verified. The observer never creates these fixtures or copies real session credentials. It will remain unready if the producer/receipt is absent or stale. Deterministic source tests use labeled synthetic receipts and do not establish these production outcomes.

`prepare` and `candidate` do not assume the old serving process is already the candidate. `serving` additionally verifies systemd identity/ExecStart, process cwd, Git HEAD, file hashes/mtime, and configuration file timestamps relative to service start. A fresh protected receipt is required after a long build/restart. No automatic success from a prior user login or `/api/ready`.

## Remaining operator inputs before approval

1. Recover exact migration artifact with SHA `a2fa93bae20a083e346fa68b49b82166d2b6ce7019099d9e6c3fd4948efc349a` into authoritative source. Do not reconstruct SQL from this description. Resolve the untracked paired-welcome numbering conflict separately.
2. Review candidate and compatible rollback revisions, actual service command identity, critical dependency list, protected datasource reference and existing read access.
3. Supply current application driver/pool bounds and controlled acceptance/operations proof producer. Current source observation did not establish bounded application connections, alert delivery, or retention automation.
4. Restore approved disk headroom and budget build/backup peak; the reported ~3.3 GiB free fails the 5 GiB/15% floor. No deletion is part of this patch.
5. Review the forward-only schema compatibility for the rollback artifact. No automatic database rollback or migration occurs.
6. Approve deployment separately after staging proof, pinned toolkit/config/manifest, and non-secret release/provenance receipt are reviewed.
