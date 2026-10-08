# Auth Setup Kit

AUTH's operating contract is **configure once, verify once, operate independently, detect drift, repair only when necessary**. The setup/repair wizard exits after verified handoff; normal product use must not require wizard interaction or recurring orchestration calls. See the [canonical runtime-independence and completion contract](docs/AUTH_WIZARD.md#setup-runtime-independence-and-maintenance), including the distinction between the wizard and explicitly declared identity services.

Desktop integrators: [Reusable desktop OAuth handoff v1](docs/DESKTOP_OAUTH_HANDOFF_V1.md).

Start here: [Human operator guide](docs/AUTH_OPERATOR_HUMAN.md) · [Agent operator guide](docs/AUTH_OPERATOR_AGENT.md) · [Canonical wizard contract](docs/AUTH_WIZARD.md).

`auth/` is the reusable authentication and authorization authority. It owns identity/session lifecycle and standards-shaped CLI/native authorization; consuming products keep their branded login, signup, consent, and account UI.

See [Enrollment handoff and admission v1](docs/ENROLLMENT_HANDOFF_V1.md) for the server contract and required VVAULT/product integration.

See [Registered-client resource authorization v1](docs/RESOURCE_AUTHORIZATION_V1.md) for the additive AUTH grant/status contract, controlled verification command, and VVAULT/GRID activation prerequisites. This source implementation is disabled until the authoritative resource adapter and workload trust are configured.

## Canon

`auth/` provides both reusable setup tooling and the shared runtime protocol authority for registered public clients.

The rule is concrete: copy the reusable prompt into a chat with the agentic coder working on the consuming app. Do not ask that agent to figure out auth from scratch.

`auth/` owns the setup source, templates, configuration contract, validation checks, and setup reports.

Products own visible authentication UI and product routing. `auth/` owns provider integration, auth cookies, authorization codes, access/refresh sessions, client validation, `/api/me`, refresh, revocation, and logout.

`auth/` does not own app startup, app UI, product routing, dashboards, downstream runtime topology, or downstream success claims. Starting the auth API service proves only the auth API service started.

The setup operation is one-time; the authorization authority is a runtime dependency for registered CLI/native clients. Products retain their configuration, visible UI, ports, and runtime proof without copying the authorization protocol.

## Commands

```sh
bin/auth setup --repo ../chatty --app chatty --authorize
bin/auth validate --repo ../chatty --app chatty
```

See [Auth Setup CLI](docs/AUTH_SETUP_CLI.md).

## Copy This Prompt

Copy [the canonical agentic coder prompt](docs/AGENTIC_CODER_PROMPT.md) into a chat with your other AI provider.

That prompt is the onboarding contract for any consuming repository. The target result is one setup pass that configures app identity, origins, callbacks, provider credentials, session cookies, storage posture, and the consuming repo's own auth integration.

## Hard Boundary: No Frontend Lives Here

`auth/` does not own, ship, or serve a product frontend. Do not put target login, signup, consent, account, dashboard, profile, or product UI in this repo.

If a browser opens the `auth/` service root (`/`), that is a routing mistake. The root returns `410 auth_frontend_removed` on purpose so the mistake is obvious.

Consuming apps own every visible auth screen. Browser adapters may expose these product-facing API surfaces while delegating identity/session authority to `auth/`:

- `GET /api/auth/config`
- `POST /api/auth/login`
- `POST /api/auth/register`
- `GET /api/auth/:provider`
- `GET /api/auth/:provider/callback`
- `GET /api/me`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`

## Containerism Start Here

- [Auth Containerism Adapter](docs/CONTAINERISM_ADAPTER.md)
- [Auth session/config contract](#auth-service-and-session-contract)
- [Session behavior](#session-behavior)

Broader local workspace doctrine may exist beside this repo, but a third-party clone of `auth/` must not need any sibling checkout to build, start, or integrate a consuming app.

Setup ownership:

- `auth/` owns setup source, templates, validation, reports, identity/session lifecycle, and reusable authorization protocol.
- Apps own continuity topology, runtime topology, and continuity storage.
- Consuming apps own persistence/readback facts where they declare that dependency; auth reachability is not downstream persistence proof.

Fail-closed gate:

- Downstream features are not promoted unless auth proof (`/api/me`, provider status, callbacks, provider/env config) is explicit for the active app config.
- Missing `/api/me`, callback, or provider config must keep auth in hard-block mode and cannot be remapped into downstream success claims.

### New feature/container pre-promotion checklist

1. Declare auth feature ownership and the consuming app surfaces it affects.
2. Prove app-config alignment (origins, redirects, providers, callback URLs).
3. Prove local-vs-production session behavior (`/api/me`, provider availability, cookie posture).
4. Require explicit failure behavior for session or callback gaps before claiming integration success.

It is not owned by any consuming repo. Consuming repos use this repository as the reusable setup authority, then keep their own implementation, app config, origins, OAuth callback URLs, provider settings, consent documents, and session expectations in their own repo/runtime.

## What Auth Is

`auth/` provides a setup model and reusable auth source that can be copied, forked, or adapted into a consuming repo. The target repo should keep the resulting implementation and config locally.

The app config defines the product-facing identity that `auth/` reports through API responses. It does not create or imply an `auth/`-hosted product interface:

- app id, name, and optional brand tagline
- allowed browser origins
- login/logout redirect paths
- whether credential login is enabled
- required legal/consent docs
- enabled provider buttons
- OAuth environment variable prefix

The service port is where that repo's auth API listens. A port does not imply downstream ownership, and it is not a shared central dependency. For example, a consuming repo may run its own auth integration on its own chosen auth port while its frontend/backend use separate app ports.

`auth/` must distinguish:

- `AUTH_PORT`: the port where a repo's auth process listens.
- App ports: the consuming repo's frontend/backend ports.
- `allowedOrigins`: the browser origins allowed to call that repo's auth API.
- Provider callback URLs: the OAuth return URLs registered for that repo/provider pair.
- App config selection: the app identity and provider posture selected by request app id, origin, referer, or config path during setup and validation.

`auth/` setup source covers:

- provider login patterns
- callback handling patterns
- session issuance patterns
- `/api/me` session truth patterns
- auth cookies such as `auth_sid` and `auth_rid`
- logout/session destruction patterns
- app-specific auth config selection
- API responses that target repo frontends call after setup

## What Auth Is Not

`auth/` is not a frontend application.

`auth/` is not a login page.

`auth/` is not a signup page.

`auth/` is not a consent screen.

`auth/` is not an account/profile UI.

`auth/` is not a single-app service.

`auth/` is not tied to any personal repository.

`auth/` is not proof of downstream application readiness.

Consuming apps provide all visible auth UI and may proxy product-facing endpoints, but they do not duplicate authority-owned protocol or session logic.

`auth/` is not currently a full OIDC identity provider. It exposes project-facing HTTP endpoints, session cookies, provider callbacks, and an optional PostgREST-compatible JWT bridge.

For VVAULT account context, `POST /api/auth/vvault-account-assertion` issues a short-lived,
audience-bound Ed25519 assertion only after Auth has canonical owner evidence. Configure
`AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM` in Auth and distribute only its public key to VVAULT;
local-only LIFE identifiers cannot satisfy this endpoint. The assertion contains only the
display name, optional `adult`/`minor` assurance, owner binding, session identifier, and JWT
verification metadata—never email, provider profile, picture, credentials, or tokens.

For user-scoped canonical VVAULT access, `POST /api/auth/vvault-access-assertion` issues the
60-second `life-auth-vvault-access-assertion/v2` Ed25519 JWT after the same canonical-owner
proof. It contains only subject, owner, server-derived relying-party identity, session, nonce, timing, key ID, and explicit VVAULT
read/append scopes. `scripts/open-auth-standalone.sh` loads its private PEM from macOS
Keychain service `life-auth-vvault-access-assertion-v1`, account `auth-local`, unless the
dedicated private-key environment variable is already set. Live VVAULT receives only the
current/next public-key ring.

`auth/` does not own:

- sibling-service discovery
- local/public runtime door selection
- continuity bridge topology such as `/api/vault/session-bridge`
- application-specific runtime authority rules

If a downstream app needs a runtime-topology contract between sibling services, that contract belongs in the downstream app docs and runtime config, not here.

## Consuming App Model

A consuming app uses `auth/` by:

1. Running `bin/auth setup --repo <target> --app <app> --authorize`.
2. Reviewing `.auth-kit/auth.config.json`, `.auth-kit/ADAPTER.md`, and `.auth-kit/reports/latest.md` in the target repo.
3. Copying, adapting, or implementing the auth runtime inside the target repo.
4. Setting provider credentials and callback URLs using the config's OAuth env prefix.
5. Proving `/api/auth/*`, `/api/me`, refresh, and logout work inside that repo's runtime without this checkout running.

Example setup:

```sh
bin/auth setup --repo ../chatty --app chatty --authorize
```

The default app config is `config/example-app.json` for examples. Target setup uses `config/<app>.json`.

For a single repo, `AUTH_APP_CONFIG_PATH` is enough. For setup validation where one temporary auth process needs to inspect multiple app configs, use `AUTH_APP_CONFIG_PATHS` with multiple config files. The service can then select the active app config from an explicit app id, request origin, or referer.

Multi-config operation is supported for a shared authority. Each consuming product still records its own app config, origins, callbacks, UI routes, and ports.

## App Config Model

Each config follows the `AuthAppConfig` shape used by `src/types.ts`:

```json
{
  "app": {
    "id": "example-app",
    "name": "Example App",
    "brandTagline": "Sign in securely."
  },
  "oauth": {
    "envPrefix": "MYAPP"
  },
  "allowedOrigins": [
    "http://localhost:3000"
  ],
  "redirects": {
    "postLoginPath": "/",
    "postLogoutPath": "/"
  },
  "credentials": {
    "enabled": true
  },
  "docs": [],
  "turnstile": {
    "required": false,
    "enabled": false
  },
  "providers": [
    {
      "provider": "google",
      "label": "Continue with Google",
      "enabled": true
    }
  ]
}
```

`config/example-app.json` is the primary onboarding example.

One provider is a complete valid setup. The `providers` array should list only implemented providers the consuming app actually intends to offer and has credentials for. Do not add GitHub, Microsoft, Apple, or any future provider as a placeholder.

Checked-in consumer examples demonstrate how the model can be used by existing apps; they are not ownership declarations for the `auth/` product. A third-party clone can ignore them and use `config/example-app.json` or its own config file.

## Env Prefix Model

Provider environment variables are resolved from the active config's `oauth.envPrefix`.

For an app with:

```json
{
  "oauth": {
    "envPrefix": "MYAPP"
  }
}
```

the Google settings are:

```sh
MYAPP_GOOGLE_CLIENT_ID=
MYAPP_GOOGLE_CLIENT_SECRET=
MYAPP_GOOGLE_CALLBACK_URL=http://localhost:3000/api/auth/google/callback
```

Alternatively, the app can provide a shared callback base:

```sh
MYAPP_PUBLIC_CALLBACK_BASE=http://localhost:3000
```

OAuth start must use the same callback URL that setup reports. Callback selection is intentionally frontend-owned:

1. App-specific callback env whose origin is in `allowedOrigins`, such as `MYAPP_GOOGLE_CALLBACK_URL`.
2. App-specific public callback base whose origin is in `allowedOrigins`, such as `MYAPP_PUBLIC_CALLBACK_BASE`.
3. The request `Origin` or `Referer`, when it matches `allowedOrigins`.
4. Generic legacy callback env, such as `GOOGLE_CALLBACK_URL` or `PUBLIC_CALLBACK_BASE`, only when its callback origin is explicitly listed in `allowedOrigins`.
5. Backend/internal callback env only when its callback origin is explicitly listed in `allowedOrigins`.

Values such as `GOOGLE_CALLBACK_URL=http://localhost:8000/...`, `PUBLIC_CALLBACK_BASE=http://localhost:8000`, or `MYAPP_BACKEND_CALLBACK_URL=http://localhost:8000/...` must not override a target repo whose registered browser callback is `http://localhost:3000/api/auth/google/callback` unless `http://localhost:8000` is explicitly present in that app config's `allowedOrigins`. Setup and validation report these names as callback conflicts rather than printing secret values.

Target repos should record explicit auth settings:

```sh
AUTH_APP_CONFIG_PATH=config/example-app.json
AUTH_PORT=1111
AUTH_COOKIE_NAME=auth_sid
AUTH_SESSION_SECRET=change-me
```

The setup CLI does not read `.env*` files and never prints secret values. If a target repo adapts the runtime service code, that target repo owns its own env loading policy.

```sh
bin/auth validate --repo ../chatty --app chatty
```

`auth/` does not search sibling repos by name except for the explicit `--repo` path passed to setup or validation.

## Port and Origin Model

`AUTH_PORT` is the auth listener for one repo's auth integration. It answers that repo's auth API.

Consuming app ports are origins and callback targets for that repo. They are not proof that this shared auth checkout must stay running.

Temporary setup validation may load many configs at once, but final integration should leave each repo with independent port ownership. Keep a port reference so agents do not keep rediscovering or inventing these values:

- [Local port reference](docs/LOCAL_PORTS.md)

Use additional auth listening ports only when a repo intentionally owns its own auth process, side-by-side version testing is needed, or a separate deployment needs isolation. Do not turn this checkout into an unspoken central dependency.

## Auth Service and Session Contract

The auth service contract is the API boundary each consuming repo must own after setup. Auth service startup is not consuming app startup, and `/health` is not proof of product login success.

The core contract is:

- `GET /api/auth/config`: app identity, consent docs, Turnstile posture, and provider availability
- `POST /api/auth/login`: credential login
- `POST /api/auth/register`: credential registration
- `GET /api/auth/:provider`: OAuth start
- `GET /api/auth/:provider/callback`: OAuth callback
- `GET /api/me`: canonical session truth
- `POST /api/auth/refresh`: refresh-token rotation
- `POST /api/auth/logout` and `GET /api/auth/logout?origin=<allowed-origin>`: logout/session destruction

Success requires app config alignment, provider credentials, registered callback URLs, matching allowed origins, valid cookie posture, and `/api/me` proof. A reachable `/health` endpoint is partial service proof only.

## Session Behavior

The primary login flow issues two HTTP-only JWT cookies:

- `auth_sid` or `AUTH_COOKIE_NAME`: a 15 minute access token
- `auth_rid` or `AUTH_REFRESH_COOKIE_NAME`: a 30 day refresh token

Consuming apps can check the session with:

```text
GET /api/me
```

Credential login and OAuth callback paths both end in this session-cookie model. Clients can rotate the refresh token family with:

```text
POST /api/auth/refresh
```

Refresh tokens are stored only as `HMAC-SHA256(AUTH_REFRESH_TOKEN_HASH_SECRET, rawRefreshJwt)`. PostgreSQL is the source of truth for refresh-token family state when `AUTH_STORAGE_ADAPTER=postgres` or `DATABASE_URL` is set; Redis is used for OAuth state, cross-origin exchange codes, refresh single-flight locking, and revocation caches.

Logout follows the same ownership boundary as login: consuming apps should initiate logout through their own auth integration, and the target repo's auth implementation clears both canonical auth cookies. Browser consumers can use `GET /api/auth/logout?origin=<allowed-origin>` to clear the session and return to the configured `postLogoutPath`; API clients can use `POST /api/logout` or `POST /api/auth/logout` for JSON logout.

## Optional PostgREST JWT

The reusable auth source can also issue a short-lived JWT for PostgREST-style API access when a target repo carries that endpoint:

```text
POST /api/auth/postgrest-token
```

This endpoint reads the existing auth session cookie and returns a standard HS256 JWT only when:

- `AUTH_POSTGREST_JWT_SECRET` is configured
- the JWT secret is distinct from `AUTH_SESSION_SECRET`
- the active session has a Supabase UUID in `uid`

The JWT uses:

- `sub`: Supabase UUID from the session
- `role`: `authenticated`
- `exp`: short expiry
- optional `email`

This JWT is for direct API/PostgREST access. It does not replace the auth session cookie.

## Provider Boundaries

Provider buttons are configured per app, but provider implementation still depends on the target repo carrying or adapting a provider adapter.

Currently supported provider adapters include:

- Google
- GitHub

If a config lists a provider without an implemented adapter, the target repo must report it unavailable. Microsoft, Apple, and any other provider IDs are not ready merely because they appear in a config; they need implemented provider adapters before they can be treated as available.

## Third-Party Project Setup

For an unrelated project:

1. Run `bin/auth setup --repo <path-to-project> --app <app-id> --authorize`.
2. Review the generated `.auth-kit/` files in the target repo.
3. Copy, adapt, or implement auth runtime code inside the target repo.
4. Add provider credentials using the generated env var names.
5. Wire the consuming app's `/api/auth/*`, `/api/me`, and logout flow inside that repo's own runtime.
6. Run `bin/auth validate --repo <path-to-project> --app <app-id>` and the target repo's own proof commands.
7. Keep session secrets and provider secrets outside source control.

Minimal example:

```sh
bin/auth setup --repo ../my-app --app chatty --dry-run
```

Do not commit real `.env`, `.env.local`, provider secrets, session secrets, or JWT secrets.

For third-party integration, prefer the single reusable prompt in [docs/AGENTIC_CODER_PROMPT.md](docs/AGENTIC_CODER_PROMPT.md) over a custom checklist.

Reusable lifecycle verification: see [AUTH canonical wizard contract](docs/AUTH_WIZARD.md). Run `bin/npm20 run test:wizard` for its focused checks.

Generate non-secret local authority conformance through `bin/auth conformance`:
[operator instructions and proof limits](docs/AUTH_RELYING_PARTY_EVIDENCE.md#generate-evidence-for-the-existing-local-auth-deployment).

Canonical-owner repair operators: [bounded assertion repair and protected datasource contract](docs/AUTH_ASSERTION_REPAIR.md).

Desktop repair packaging: [1.1.0 integration instructions](docs/DESKTOP_HANDOFF_1_1_0.md).

## Durable product integration

Use the [durable product contract](docs/AUTH_PRODUCT_DURABILITY.md) for installed lifecycle protection: `auth setup` now installs the `.auth-kit` verifier, observation entrypoint, provenance and CI gate. Explicit establishment creates the reviewed baseline; `node .auth-kit/verify.mjs verify` automatically validates it and its check-level history. `maintain` reverifies; `advance` and `amend` require separate reviewed authorization. Raw `auth wizard --adapter` remains a diagnostic primitive, not a durable release gate. External required-status protection and live product evidence remain separate obligations.

Public/deployed authority evidence: [operator adapter and conformance export](docs/AUTH_REMOTE_CONFORMANCE.md).
