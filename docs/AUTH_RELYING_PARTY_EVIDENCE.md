# Safe relying-party verification

A relying-party client consumes an identity authority. It must not retain or
replay real bearer credentials to prove the authority's security behavior.
Declare `authenticationRole: "RELYING_PARTY"` in its observation adapter, plus
`identityAuthority: { "id": "<authority identifier>", "revision": "<deployment revision>" }`.
Existing adapters without this declaration retain the legacy evaluation contract;
they must adopt this declaration to use authority evidence aggregation.

AUTH's fixed per-check ownership is executable in
`scripts/auth-evidence-ownership.mjs`; products cannot override a check's owner.
Applicability remains unchanged. No security check is removed or globally made
NOT_APPLICABLE.

- PRODUCT: runtime observations, isolated fixtures and safe negative tests. Includes
  client state binding, S256 generation, session persistence/restoration, logout
  cleanup, callback success/failure, and terminal continuation/error presentation.
- EXTERNAL_AUTHORITY: token/code proof validation, rotation, replay enforcement,
  revocation persistence/rejection, issuer-side session expiry and redirect registration.
  Use controlled authority conformance tests with synthetic identities/tokens.
- CONTRACT: static evidence of the declared identity-authority boundary.
- SHARED: random token generation, storage secrecy and logging secrecy require both
  client evidence (including PKCE/state and local storage) and authority conformance.

Issuer/audience validation by a consumer remains a client obligation. Client-side
failure presentation is not satisfied by an authority rejecting a request.
An authority check is NOT_REQUIRED **for product-side collection**, not waived:
its authority result must still PASS. Health alone never proves conformance.
Missing evidence yields INDETERMINATE; explicit failure yields FAIL. Implementation
and applicability must also be established. Existing baseline regression checks apply.

## Trusted evidence input

Product `checks` and `evidence` continue to describe client observations. Supply
reviewed authority evidence separately using `evaluateAdapter(adapter,
{ trustedAuthorityEvidence: records })`. This API option is a trust boundary: the
invoking operator must obtain and authenticate the records from the authority's
controlled test/CI process. An adapter's own `trustedAuthorityEvidence` field is
ignored. AUTH does not authenticate arbitrary external URLs or fetch references.

Each authority record has this shape (no tokens or credentials):

```json
{
  "productId": "example-cli",
  "revision": "client-revision",
  "authority": "authority-id",
  "authorityRevision": "deployment-revision",
  "capabilityId": "session.refresh",
  "checkId": "replay_rejected",
  "verification_owner": "EXTERNAL_AUTHORITY",
  "kind": "CONFORMANCE",
  "result": "PASS",
  "references": ["ci:controlled-authority-test/run/check"]
}
```

The authority deployment and client revision must match exactly. The operator must
refresh evidence when either changes. Conflicting PASS/FAIL evidence resolves to
FAIL. Wrong scopes, health records, missing references and absent evidence cannot
PASS. References identify sanitized test results, never plaintext secrets.

CLI invocation from AUTH:

```sh
bin/auth wizard --adapter /absolute/path/observations.json --operator VERIFY \
  --authority-evidence /absolute/path/authority-conformance.json \
  --authority-sha256 <independently-trusted-sha256>
```

The evidence file is a JSON array. The digest pins operator-approved content; it
is not a signature or proof of origin. Do not trust a digest supplied by an
untrusted product alongside its own evidence. Without trusted conformance, run
without these flags and forward the resulting EXTERNAL AUTHORITY handoff.

Handoffs expose per-check owners, local/authority results and sanitized authority
references. Missing authority proof routes to EXTERNAL AUTHORITY; outstanding
client checks remain visible and must also be resolved. No automatic ACT or
secret collection is introduced. After any authorized repair, VERIFY is mandatory.

## Generate evidence for the existing local AUTH deployment

Use the same CLI; no internal imports are required:

```sh
bin/auth conformance --adapter /absolute/path/product-context.json \
  --app <registered-app-id> --client-id <registered-client-id> \
  --out /absolute/path/new-authority-evidence.json
shasum -a 256 /absolute/path/new-authority-evidence.json
```

The product context declares the exact authority URL and full Git revision in
`identityAuthority`. The generator currently supports the established macOS
`local.vvault.auth` LaunchAgent at http://localhost:1111. It checks the actual
listener's command, working directory, start time, configured app files and main
compiled artifacts before and after probing. Files newer than process startup
block generation. It does not start, restart, reconfigure or mutate the authority.
Output uses the existing array of check records and refuses to overwrite a file.

Records add `binding`, `digest`, `reasonCode`, and sanitized `observations` to the
existing evidence format. Binding contains contract version, configuration and
runtime digests, generation/expiry timestamps and run/process identity. The
record digest uses SHA-256 of recursively key-sorted JSON, excluding `digest`.
Evidence expires after one hour. The verifier rejects invalid record digests,
stale timestamps, incompatible generator contracts, and mismatched declared
configuration/runtime digests. Pin the independently reviewed whole-file digest
through the existing `--authority-sha256` verifier option. Legacy trusted records
remain supported; a digest is integrity evidence, not a cryptographic signature.

Current supported probes establish rejection of an unregistered client and an
unregistered redirect, and observe unauthenticated userinfo rejection. The latter
is narrower than the catalog's general invalid-session check and does not upgrade
it to PASS. Health is only a prerequisite. The generator emits INDETERMINATE for
replay, rotation, revocation, expiry, PKCE verifier, identity/session and shared
crypto checks until a controlled fixture interface for the deployed authority is
established. An unknown token or an empty revocation response cannot prove these.
No live tokens, secrets, passwords, codes or accounts are collected or created.

Deployment provenance limit: Git HEAD plus process and main compiled artifact
hashes is observable local provenance, not proof that a clean commit built every
loaded dependency or that the process environment matches a signed deployment.
Do not claim signed build attestation. Review this limitation and the specific
probe coverage before trusting records. A deployment/configuration change requires
fresh evidence and matching adapter binding; expiry also requires regeneration.

## Controlled fixture extension

`bin/auth conformance` now also runs a disposable fixture child against the exact
compiled AUTH application import graph observed alongside the running service.
The generator compares artifact digests before/after and runs the child with the
same Node executable as the LaunchAgent. It copies only compiled relative imports
into a private temporary directory, supplies no inherited credentials or workspace
environment files, and injects the existing memory identity, refresh and ephemeral
stores plus local-only identity resolvers. Dependencies are shared read-only by
reference; their complete dependency graph is not a signed build attestation.

The fixture has no TCP listener and adds no endpoint to the running application.
Its Unix socket is inside a mode-0700 temporary directory; normal clients cannot
request fixtures over AUTH's public protocol. Synthetic secrets exist only inside
the child and are never returned. Only named boolean results and digests leave the
child. The parent enforces a 45-second timeout and removes the private directory
in `finally`, including child-failure paths. The child closes its socket and exits;
all fixture identity/session stores then cease to exist. No production credentials,
configuration files or data stores are copied into the fixture environment.

Evidence with reason `ISOLATED_ARTIFACT_FIXTURE` proves application behavior under
these explicitly substituted stores, not a live production-store transaction.
It now covers code replay, PKCE verifier failure, refresh rotation/replay,
revoked access/refresh rejection, malformed/expired proof rejection and authorized
userinfo control cases. Correctly signed expired synthetic proofs avoid changing
the live clock or waiting on real sessions. The record retains the fixture scope,
artifact/runner digests and boolean observations for review.

Production persistence, restart durability, distributed atomicity, deployment
policy/enrollment, complete session TTL enforcement and shared crypto guarantees
remain INDETERMINATE. Do not use artifact-fixture evidence to claim those guarantees.
The fixture does not establish real identity resolution. Health-only evidence
still cannot PASS any conformance obligation. Tests: `bin/npm20 run test:conformance`
(private socket permission required), then `bin/npm20 run test:wizard`.

## Verification profiles

Select scope explicitly with `bin/auth wizard --profile RELYING_PARTY_CLIENT`
(or API `verificationProfile`). Defaults to FULL_AUTHORITY_CONFORMANCE.

- RELYING_PARTY_CLIENT: product authorization entry, PKCE/state/callbacks, session
  binding, userinfo identity validation, local persistence/restoration, refresh
  handling, revoke request/local cleanup, authority boundary, and explicit error
  and continuation outcomes. Required authority proof still comes from trusted
  conformance. Requires adapter `authenticationRole: "RELYING_PARTY"`.
- AUTHORITY_RUNTIME: applicable session, enrollment, trust, consent, security,
  linking/email-identity and authority authorization requirements, including
  production persistence, restart, stores and policy enforcement.
- FULL_AUTHORITY_CONFORMANCE: the complete applicable catalog and all existing
  full-report checks; nothing unresolved is excluded.

The executable per-check requirements are in
`scripts/auth-verification-profiles.mjs`. Ownership and check results do not change.
Reports expose `verification_profile`, `profile_verification`, `full_verification`,
`profile_required_checks`, and `outside_profile_unresolved_checks`. The legacy
`verification` field remains the full result. CLI VERIFY/DECIDE exit status follows
`profile_verification`. Operators must name the profile when reporting PASS.

Outside-scope unresolved checks retain FAIL/INDETERMINATE and carry
`OUTSIDE_CURRENT_PROFILE`; they are neither waived nor marked NOT_APPLICABLE.
Blocker handoffs remain present with `profile_scope` so deeper work stays tracked.
Missing applicability/implementation for a required check remains INDETERMINATE;
explicit failure remains FAIL. Unknown declarations still block every profile.
Prior passing requirements cannot be excluded to evade a supplied baseline.

The added `relying_party.client_operations` capability requires four client facts:
`authorization_launched`, `userinfo_identity_validated`, `refresh_response_handled`,
and `revoke_request_sent`. These are separate from authority enforcement. Existing
adapters must provide their evidence; the wizard never invents it or translates a
successful authority test into a client runtime observation. No secrets are needed.

Example:

```sh
bin/auth wizard --adapter /absolute/path/observations.json \
  --profile RELYING_PARTY_CLIENT --operator VERIFY \
  --authority-evidence /absolute/path/reviewed-conformance.json \
  --authority-sha256 <independently-trusted-digest>
```

Expired conformance stays unresolved even under the narrower client profile.
