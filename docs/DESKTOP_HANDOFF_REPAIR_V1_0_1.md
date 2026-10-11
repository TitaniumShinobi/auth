# Desktop handoff repair 1.0.1 — source candidate

Status: source verified; deployed persistence and Windows integration remain unverified. This is a reusable AUTH repair, not a GRID redesign. No deployment or product mutation is included.

## Diagnosis and source changes

The previous provider callback copied exception.message into postLoginPath?error=..., including sqlite3 command errors. GRID's AUTH registration selects /return. That chain explains the reported error-bearing URL; the actual serving proxy/build and specific SQLite failure are not established from this checkout. The public /return observation could not be independently retrieved in this environment.

Valid provider-state failures now consume the associated native authorization request and return only a fixed error plus its native state to the registered callback. They issue no authorization code. Invalid/replayed states get an explicit error with no redirect. Browser-only errors return sanitized JSON. The AUTH /return compatibility route returns RECOVERABLE_ERROR (400/409), never admission or success, and never echoes query errors. An external frontend/proxy must actually route that URL to this handler or its own equivalent; editing AUTH does not change deployed routing.

SQLite continues to use the configured existing database and sqlite3 executable. SQL is passed over stdin rather than process arguments; execution has a ten-second bound and five-second busy timeout. Errors are reduced to AUTH_PERSISTENCE_UNAVAILABLE. There is no new database, storage fallback, migration, retry that creates another identity, or credential change. A missing executable, permissions failure, or schema issue must be repaired by the serving host operator after examining sanitized local diagnostics. This source change does not establish that the deployed persistence problem is repaired.

DesktopHandoff now distinguishes provider denial from recoverable authority failure and requests activation of the existing instance after a validated error callback. Callback hosts may render desktopRecoveryPage using trusted app registration, with Open App fallback and no secret-bearing activation URL. The renderer does not itself install an OS handler or wire a product route.

## Install/source handoff

1. Inspect the authoritative AUTH revision and its release manifest. Do not apply or port source patches into a consuming product; the selected immutable revision is the installation input.
2. Select the authoritative AUTH revision containing the provider-callback, terminal-return, and SQLite repair, then use explicit AUTH UPGRADE. Do not apply a patch or copy/adapt those runtime/provider modules inside a consuming product. Preserve product-owned UI, routing, secrets, sessions, identities, and data.
3. The Windows host implements DesktopHost using its existing session/token client, DPAPI and single-instance dispatcher; call begin with the registered appId/clientId, exact callback, pinned issuer and local resume reference. The real native flow must carry authorization_request/authorization_return through browser provider login. Starting provider login directly cannot identify an initiating native transaction.
4. Deliver loopback/deep-link callbacks only to the primary instance. Invoke callback; show completion only after authenticated result, recovery for a validated failure. Register the secret-free activation URI to raise that instance, never create an account/window/session. Restore the original authorized account/workspace. No manual code entry or refresh.
5. On the actual serving backend, verify sqlite3 is installed/executable by the service identity, existing AUTH_DB_PATH provenance and writable parent/database permissions, and applicable schema through approved operator diagnostics. Do not switch the database to make login pass. Confirm proxy routing for /return and actual artifact hashes. No deployment is authorized by this ZIP.

## Test and acceptance

Run the desktop test with the receiving AUTH TypeScript dependency and run build plus compiled desktopCallbackFailure/oauth/authorizationCode tests. Run the ordinary npm test suite; report unrelated failures separately. Test only isolated accounts/databases.

Live acceptance still requires GitHub sign-in → persisted authorized session → same Windows process/window foreground → restored workspace. Exercise deny, SQLite unavailable, state mismatch/replay, expiry, restart, cancellation and sign-out. Check no raw errors/secrets in URLs/logs and no false success. The app must remain unauthenticated on persistence failure.

## Required current Windows/deployment ZIP evidence

Include commit/worktree status, packaged build ID/manifest, sanitized grid.auth.config.json and loader/AuthOptions; GridAuthHttpClient, GridAuthHost, SessionManager, callback/deep-link listener, single-instance handler, DPAPI adapter, production composition, and any /return implementation. Include serving proxy/route configuration, backend build provenance, OS/runtime dependency versions and sanitized exact SQLite error/stack. Exclude env secrets, tokens/cookies/codes, SQL values, databases, user profiles, account files and history. This evidence is required to identify the deployed persistence cause and produce a build-specific final installation—not to invent another auth system.
