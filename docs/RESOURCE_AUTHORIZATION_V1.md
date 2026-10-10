# Registered-client resource authorization v1

Status: AUTH source implementation with finalized VVAULT wire compatibility and opt-in direct mTLS runtime, disabled by default. This is a partial milestone 1 implementation, not a deployed GRID/VVAULT handshake. Milestones 2 and 3 are not implemented here. See [runtime integration and owner-admission adapter](RESOURCE_RUNTIME_INTEGRATION.md).

## Authority boundaries

AUTH authenticates the account and native client and issues a resource authorization. VVAULT verifies it, checks current authorization online, validates its authoritative identity-to-owner association and current enrollment/device/policy requirements, and resolves its own opaque workspace. GRID consumes the resulting capability without owning VVAULT credentials, paths, shards, or owner derivation rules.

Keep AUTH issuer/subject, local GRID StableAccountId, OAuth client ID, application/RP ID, VVAULT owner UUID, workspace ID and application-instance ID distinct. An owner UUID, email, local registry record, native VVAULT cookie or redirect is not admission. No instance allocation or storage mutation is part of workspace resolution.

## Implemented AUTH contract

Contract identifier: `life.auth.resource-authorization/v1`. This additive contract does not replace existing VVAULT assertion v2. The old Chatty endpoints, audience and enrollment host remain isolated. The new path has no Chatty fallback.

Native code exchange derives `native_client: {clientId, applicationId}` from the selected server registration. Access and refresh tokens carry this signed binding. Both refresh paths revalidate it against current registration; profile rebuilding preserves it. Older tokens lacking the binding keep their legacy behavior but cannot obtain a new resource authorization. They need fresh native authorization; headers cannot restore missing provenance.

The new AUTH-owned endpoints are:

| Operation | AUTH endpoint | Authentication / input |
|---|---|---|
| Issue | `POST /api/auth/resource-authorization` | AUTH Bearer access token; `{audience, capabilities}` only |
| Online status | `POST /api/auth/resource-status` | Authenticated, pinned VVAULT workload certificate over direct mTLS; `{assertion}` only |
| Revoke own grant | `POST /api/auth/resource-revoke` | AUTH Bearer access token; `{grant_id}` only |

Cookies cannot authenticate issuance/revocation. No request can select its subject, owner, session, client or application. Responses use `Cache-Control: no-store`. Failure responses contain only `active:false` and a reason code. No raw exception, token or private credential is logged by these modules.

Issuance returns `{contract, token, token_type:"Bearer", grant_id, expires_at, capabilities}`. Clients must keep the short-lived artifact in memory, separate from their AUTH token, and send it only to the approved HTTPS resource origin with redirects disabled. They request a new artifact after normal AUTH refresh; resource assertions have no refresh token of their own.

### Signed artifact

Ed25519 JWT; protected header `alg=EdDSA`, `typ=life-resource+jwt`, configured pinned `kid`.

| Claim | Binding |
|---|---|
| `contract`, `wire_contract` | AUTH contract version and separately approved resource wire-contract version |
| `iss`, `sub` | Pinned AUTH issuer and authenticated AUTH subject |
| `aud` | Exact configured HTTPS resource origin; production VVAULT must be `https://vvault.thewreck.org` |
| `client_id`, `application_id` | Signed current native client and registered application/RP |
| `owner_id` | Canonical VVAULT UUID established by the authoritative admission adapter |
| `sid`, `jti`, `grant_id` | AUTH session, unique artifact and durable grant identifiers |
| `capabilities` | Explicit requested capabilities, permitted by both registration and authoritative admission |
| `admission_version` | Current resource admission/policy version |
| `iat`, `exp` | At most 60 seconds; no later than source AUTH access expiry or admission expiry |

Requests containing an unauthorized capability are rejected rather than silently broadened or replaced with omnibus scopes. No workspace or instance claim is issued in milestone 1.

### Online status and revocation

VVAULT must locally validate the signature, exact issuer/key/version/audience, claim types, lifetime, client/application admission and capability before contacting AUTH. AUTH then requires the exact issued JWT digest, stored grant and immutable session/subject/client/application binding. Every call rechecks AUTH session/access revocation, current client registration, resource policy and authoritative admission. Owner changes, policy/wire-version changes, disabled registration and scope removal invalidate old grants. There is no positive status cache.

The successful status response is `{active:true, contract, wire_contract, admission_version, issuer, subject, sid, jti, grant_id, audience, client_id, application_id, owner_id, capabilities, expires_at}`. VVAULT must compare it to the locally verified artifact in full; a bare `active:true` is insufficient. VVAULT still owns database-level owner/RP enforcement and workspace resolution.

Read assertions may be reused while valid and authorized. `jti` identifies an artifact; it is not a single-use read nonce. Authorization codes and enrollment proofs remain separately single-use. After acknowledged session/grant revocation, subsequent checks fail. Requests already authorized in flight cannot be undone. Later mutations must check status immediately before transactional commit and use operation-level idempotency.

Invalid/expired/revoked artifacts return 401; unauthorized capabilities/current registration return 403; unresolved enrollment/linking/reauthentication admission returns 409; unconfigured, malformed authority evidence or failed dependencies return 503. Resource policy/admission/session callbacks have bounded deadlines (2 seconds each by default, configurable up to 5 seconds); late results cannot resume authorization. Adapters must also bound/cancel their underlying I/O. VVAULT maps these to its explicit public failure contract and never retries through native cookies or the legacy v2 route.

The status endpoint accepts only an actual authorized `TLSSocket` and exactly one approved SHA-256 client-certificate fingerprint/audience registration. Spoofed proxy certificate headers are ignored. A reverse proxy that terminates client mTLS cannot be used with this implementation by forwarding headers. Use direct mTLS/TLS passthrough or develop a separately reviewed authenticated host adapter.

## Host activation contract — still required

`createAuthApp({resourceAuthorization: ...})` is the supported programmatic integration point. It requires:

1. AUTH issuer, Ed25519 signing key and key ID supplied through an authorized protected service configuration.
2. An explicitly selected durable `ResourceGrantStore`. `SqliteResourceGrantStore` implements the existing local SQLite architecture using its own protected absolute path, dedicated 0700 parent and 0600 file. It rejects symlinks, foreign databases and attempts to rebind a session. It stores artifact digests, not bearer artifacts. It never selects or switches account/refresh databases. Production multi-instance routing must use a shared coherent store or a reviewed shared-store adapter; independent local databases are not interchangeable.
3. `resolvePolicy(session,audience)`: live operator-owned mapping of enabled native client, application, resource, approved wire-contract version and permitted capabilities. Public OAuth registration alone is not resource admission.
4. `resolveAdmission(session,audience)`: a trusted VVAULT adapter that verifies identity-to-owner binding and current enrollment/device/policy admission and returns exact subject/session/client/application/audience, owner UUID, permitted capabilities, policy version and expiry. It may instead return explicit `ENROLLMENT_REQUIRED`, `ACCOUNT_LINK_REQUIRED` or `REAUTH_REQUIRED`. Owner lookup alone is prohibited. Never implement this callback from request fields, browser claims or a cached owner UUID.
5. Pinned resource workload certificate fingerprints and direct authenticated TLS hosting for online status.

The AUTH host supplies its own strict `sessionActive` checks; products cannot inject a bypass. `src/index.ts` now optionally loads `resourceRuntime.ts` and starts a separately configured direct-mTLS status-only listener while retaining the primary HTTP service. The finalized VVAULT mapping is represented in `config/resource-policies.json`, disabled by default. No certificate, key, port, policy enablement or production activation is supplied automatically. Missing runtime configuration returns `RESOURCE_AUTHORIZATION_NOT_CONFIGURED` (503); owner-admission configuration is mandatory for an enabled stock runtime, and unconfigured or failed admission cannot issue a grant.

The dedicated store initializes its additive tables only when explicitly selected by the host. No live schema migration was run. Account and refresh-session stores were not changed. Grant/session-binding retention maintenance is an operational follow-up; expired grants already fail closed. A lost/revoked underlying AUTH session never becomes active merely because a grant survived restart.

## VVAULT owner handoff

VVAULT has published `life.vvault.resource-workspace/v1`: `workspace:resolve` authorizes `POST /api/v1/resource/workspace/resolve` with an empty body, for client `grid-windows`, application `grid`, audience `https://vvault.thewreck.org`. Its supplied source validator and AUTH artifacts/status responses pass controlled cross-language compatibility testing. VVAULT also publishes the independent `life.vvault.resource-owner-admission/v1` protocol at `POST /api/v1/resource/owner-admission/resolve`. AUTH now uses its direct-mTLS adapter before grant issuance and during status revalidation. No placeholder route or `fixture.*` capability is valid production configuration.

Implement in approved release source:

1. Assertion-specific trust readiness: pinned keys/issuer/audience, contract, workload connectivity, current client/application admission across runtime/database, required migrations.
2. Generic registered-client validation and authoritative subject-to-owner/current-admission adapter. Do not confuse native OAuth client `grid-windows` with application `grid`.
3. Per-request mTLS online AUTH status validation, fail-closed without positive caching.
4. Read-only own-workspace resolution. Resolve an existing VVAULT-owned opaque binding; no filesystem IDs, constructs/callsigns, instance creation or lazy workspace allocation. Reject owner/RP selectors rather than allowing overrides. Missing provisioning returns a recoverable disposition.

The existing Chatty-specific enrollment host has not been generalized into a GRID enrollment flow. Pending identities are denied resource grants; registered-client enrollment handoff, provider support and saved-checkpoint integration remain coordinated follow-up work. Do not coerce unsupported provider proof into Google/GitHub identity.

Before deployment supply backend commit/build/time, dirty status, authorization-critical artifact/config hashes, applied migration state, `trustReadiness.ready=true`, consistent admitted client/RP state and tested mTLS status connectivity. Frontend hashes and public `/api/ready` cannot establish these. Source tests here do not establish deployed VVAULT behavior.

## GRID owner handoff

Modify only `C:\Users\woods\Documents\GitHub\grid`; the approved handoff directories are evidence, not an editable replacement checkout.

Keep current PKCE, login, DPAPI token storage and StableAccountId local partitioning. Add an AUTH resource client and opaque workspace result interface, then a VVAULT adapter using the approved wire mapping. Keep AUTH and VVAULT artifacts in separate transports; require HTTPS, reject credential-bearing redirects and serialize refresh/reissue. Bind async responses/caches to issuer/subject/application/account-generation. Logout/account-switch cancels work and clears bindings before composing the next account. Missing native client binding requires fresh authorization.

Do not add instance allocation or persistence until workspace canary acceptance. Milestone 2 adds read-only resolve and separately authorized idempotent allocate/bind; VVAULT owns IDs and transactional uniqueness. Milestone 3 adds instance-bound reads/appends/assets, version checks, receipts and account-partitioned outbox. Pending offline data is not persisted until receipt/readback verifies the write.

## Verification and ACT

Run `bin/npm20 run test:resource-authorization`. The runner compiles to a temporary directory, runs synthetic unit/HTTP/mTLS, durable-store, native OAuth and legacy v2 tests, then deletes its build. It never overwrites serving `dist`. Tests create only ephemeral loopback servers and disposable local fixtures; no Chatty/GRID process or real credentials are needed.

Wizard catalog 1.5 adds optional `assertion.resource_grant` and `assertion.resource_status`. For relying-party adapters, grant evidence belongs to `identityAuthority`; status enforcement evidence belongs to `resourceAuthority`. Source booleans or AUTH issuer tests cannot satisfy VVAULT validator proof. Existing assertion, enrollment, session and failure obligations remain independently visible. No bounded deployment ACT handler has been registered for this handshake: the existing owner-lookup repair cannot install it.

Use `bin/auth wizard --adapter <observed-adapter.json> --profile ASSERTION_INTEGRATION --operator VERIFY`. Supply operator-approved deployment-bound issuer/validator evidence through the existing `--authority-evidence` and `--authority-sha256` inputs only after those exact deployments have been verified. Do not relabel synthetic evidence as production conformance. The checked-in milestone adapter intentionally lacks production proof and evaluates INDETERMINATE.

Production milestone 1 requires disposable approved Owner A/B fixtures with existing workspaces, valid200, missing/invalid/expired/wrongaudience401, wrongclient/RP401, insufficientauthority403, owner-selector403, cross-owner denial, reusable authorized reads, post-revocation401 and status/trust-unavailable503. Prove zero instance allocations/data writes. No real-user credential replay. Disable registration/revoke grants and restore compatible artifacts on failure; no account rollback or table dropping.

Milestone 1 is complete only after the approved GRID build obtains the correct production-proven isolated workspace result. The current result is source implementation plus synthetic proof, with production acceptance INDETERMINATE.
