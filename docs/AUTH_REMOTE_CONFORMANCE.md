# Public/deployed authority conformance

Run the existing `bin/auth conformance` on the AUTH deployment host (or an operator environment with direct, verified access to its serving artifacts). It exports the SAME `auth-authority-conformance/1` records consumed by `AUTH_PRODUCT_AUTHORITY_EVIDENCE`. No endpoint, production fixture backdoor, alternate identity authority or consumer SSH integration is added. The localhost LaunchAgent path remains unchanged when no deployment adapter is supplied.

```sh
node scripts/auth-cli.mjs conformance \
  --adapter /reviewed/consumer-binding.json \
  --app REGISTERED_APP --client-id REGISTERED_PUBLIC_CLIENT \
  --authority https://PUBLIC_AUTHORITY_ORIGIN \
  --deployment-adapter /reviewed/deployment-adapter.mjs \
  --deployment-sha256 INDEPENDENTLY_REVIEWED_ADAPTER_SHA256 \
  --out /reviewed/new-authority-evidence.json
```

The consumer binding is the current product adapter with exact productId/revision and identityAuthority.id/revision, plus configurationDigest/runtimeDigest where pinned. It must come from the current product observation, not a guessed repository HEAD. The authority origin must be exact HTTPS origin, no path/credentials. The output filename must not already exist. The result prints its SHA-256 and 11 check results, never tokens or fixture logs.

## Reviewed deployment adapter

The adapter is privileged OPERATOR code. It is not supplied by a consumer and not loaded from a URL. Review its entire dependency closure and protect it on the deployment host. Its exact entry file SHA-256 is required before import; imports are part of the operator trust boundary, not automatically attested by that single-file digest. Prefer a self-contained adapter using Node built-ins. A hash is integrity against an independently reviewed reference, not a signature or proof of honesty.

Export `async function snapshot({authority, app, client})` returning:

- authority: verified public HTTPS origin
- revision: actual serving full Git commit/build revision (40–64 lowercase hex)
- root: authority release directory with the serving dist artifacts and dependencies
- nodeExecutable: actual runtime executable usable by the isolated fixture
- runtimeDigest: SHA-256 of the serving runtime artifact manifest
- configurationDigest: SHA-256 of reviewed effective configuration/contract manifest (no secrets exported)
- fixtureArtifactDigest: `digest(fixtureArtifacts(root))` using AUTH's existing compiled artifact closure
- processIdentityDigest: SHA-256 binding actual service process identity/start/release
- ingressBindingDigest: SHA-256 binding reviewed public origin/proxy/upstream to that process
- registeredApp / registeredClient: values verified from the serving registration
- servingDeploymentVerified: true ONLY after those observations succeed

This is an operator interface, not a prefilled deployment attestation. The adapter MUST inspect the actual serving service/process, release hashes, effective config provenance, public ingress mapping and registration. Repository HEAD or health alone is insufficient. It MUST reject unknown/mixed deployments, load-balanced heterogeneous revisions, post-start artifact changes and unverified proxy/backend association. It MUST be read-only, never restart services or collect/export credentials, and return stable snapshot data (no new timestamp per call). Deployment-specific systemd/container/proxy integration belongs here; this task does not guess an unprovided host's service state. Absent such a reviewed adapter, production generation remains unavailable rather than substituted with localhost evidence.

## Checks and scope

The runner compares snapshots and compiled artifact closure before/after. It makes only safe public negative authorization probes, without cookies or Authorization headers, following no redirects. Registered client/redirect rejection comes from public probes. PKCE/code replay/session invalid/expiry/revocation/refresh checks use the existing isolated fixture against the matched compiled artifacts, synthetic identities and memory stores, with automatic cleanup. They prove artifact behavior, not production database durability, store configuration or deployment-wide revocation propagation. Missing fixture completion/cleanup/binding leaves those checks INDETERMINATE. Unexpected negative-probe behavior is FAIL; transport unavailability is INDETERMINATE. Deployment mismatch aborts the entire export.

Only explicitly selected fields are exported; no raw adapter snapshots, responses, logs, credentials or fixture objects. Records expire after one hour. They bind consumer product/revision, authority/revision, configuration/runtime, adapter/process/ingress digests, run identity, capability/check/result and sanitized references. The existing verifier rejects mismatches, tampering, expired records and health-only claims. Consumers must independently review the file SHA-256 and provenance before trusting it; do not let a product adapter self-supply trusted evidence.

```powershell
$env:AUTH_PRODUCT_AUTHORITY_EVIDENCE = 'C:\reviewed\authority-evidence.json'
$env:AUTH_PRODUCT_AUTHORITY_SHA256 = '<independently reviewed file SHA-256>'
node .auth-kit\verify.mjs verify
```

No product applicability decision is inferred. Password NOT_APPLICABLE does not retire OAuth/session requirements. A successful fixture or export is not GRID baseline establishment or live product acceptance.

## Minimal consumer binding handoff

Export only this existing-schema subset; no capabilities, credentials or source inventory:

```json
{
  "productId": "actual-product-id",
  "revision": "current-product-binding-revision-digest",
  "identityAuthority": {
    "id": "https://actual-public-authority-origin",
    "revision": "declared-full-serving-authority-commit",
    "configurationDigest": "optional-existing-pinned-sha256",
    "runtimeDigest": "optional-existing-pinned-sha256"
  }
}
```

Omit optional digests if not already established; do not insert placeholder strings. The authority operator must independently verify the declared authority revision against the real serving deployment. Unknown authority revision cannot be invented; exporter fails explicitly if absent.

The supplied standalone `auth-export-authority-binding.mjs` uses only Node built-ins and the product's installed kit. Place it OUTSIDE the product. It runs fresh product VERIFY, invokes the existing collector, compares product/observer/contract bindings again, and exports only the allowlisted fields above. It writes normal kit verification reports but does not alter source/index, establish or advance a baseline. It requires no SSH and does not require VERIFY PASS merely to export a valid current binding. Execute in PowerShell:

```powershell
$Grid = 'C:\Users\woods\Documents\GitHub\grid'
$Out = Join-Path $env:TEMP ('grid-authority-binding-' + [guid]::NewGuid() + '.json')
node .\auth-export-authority-binding.mjs $Grid $Out
if ($LASTEXITCODE -ne 0) { throw 'Binding not exported; do not substitute guessed values' }
Get-FileHash -Algorithm SHA256 $Out
```

Return that sanitized JSON and its hash for authority-side generation. If a Git override is needed, preserve the pilot's existing AUTH_GIT_EXECUTABLE environment setting. Export is a binding handoff only, never authority evidence or baseline establishment.
