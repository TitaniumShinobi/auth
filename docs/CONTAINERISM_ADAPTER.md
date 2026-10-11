# Auth Containerism Adapter (Front-Door)

This is the canonical front-door adapter for `auth/`.

Canon: `auth/` is a one-time plug-and-play login, OAuth, and session setup package for any consuming repository. It owns setup source, templates, validation, and reports. The target repo owns login APIs, OAuth callbacks, provider availability, auth cookies, sessions, `/api/me`, refresh, and logout after setup.

Port canon: `AUTH_PORT` is the auth API listener for one repo's auth integration. Consuming app frontend/backend ports are `allowedOrigins` and provider callback targets. This checkout is not a central auth hub that every repo must keep calling after setup.

Master doctrine:
- Auth must build, validate, and package its setup source from this repo alone.
- Broader local workspace docs can exist beside this repo, but they are not required inputs for a third-party clone.

## Ownership and Authority Boundaries

`auth/` owns setup authority and reusable provider/session contracts for the consuming app.

- Owns source-kit templates, setup reports, and validation checks.
- Provides provider login, callback handling, session issuance, `/api/me`, and logout/session destruction patterns.
- Provides auth cookie, refresh-token rotation, and app-config-driven provider/env selection patterns.
- The target repo owns the complete runtime installed by AUTH SETUP; it does not manually recreate or adapt runtime/provider implementation.
- Does **not** own downstream continuity topology, continuity storage, or sibling-service runtime doctrine.
- Does **not** own cross-app product routing or app-owned auth policy surfaces.

## Shared Infrastructure Contract

`auth/` is shared setup infrastructure for provider login and session authority.

- `auth/` setup proves who/session/provider/callback/logout posture only.
- `auth/` does not prove downstream persistence, continuity, app runtime, or app UI behavior.
- OAuth setup templates treat OIDC as identity proof only. The consuming
  application owns admission, pending enrollment, consent/MFA/device gates,
  and must never auto-create an active application account from an email claim.
- For VVAULT, state, nonce, PKCE verifier, callback URI, and invitation digest
  are durable VVAULT runtime records. This setup package is not a concurrent
  VVAULT auth/session service.
- Consuming repos must name their app config, callback origins, cookie/session behavior, and provider posture before claiming auth integration success.
- `auth/` reachability must never be treated as downstream app success or persistence/readback proof.

## Local-vs-Production Truth

- Auth source-kit readiness and local env wiring are setup proof.
- Consumer runtime topology (`AUTH_APP_CONFIG_PATH`, callback base/origins, cookie naming, and recorded ports) is the production contract boundary for product integration. `AUTH_APP_CONFIG_PATHS` is for temporary setup validation unless a repo intentionally owns a multi-config auth process.
- Local auth readiness does not imply downstream runtime truth for consuming apps.
- Consuming apps initiate logout, and the installed AUTH runtime clears the canonical auth session cookie.

## Fail-Closed Expectations

- If `/api/me` is unavailable, callbacks fail, or provider/environment config is missing, treat auth posture as hard-blocked.
- Missing callback registration or provider config must never be treated as a success signal for downstream runtime.
- `auth/` reachability does not imply downstream continuity or continuity-route health.

## New feature/container promotion gate

Before promoting new auth work:

1. State ownership boundary changes and the apps the change can affect.
2. Prove app-config, callback, and provider posture for the active deployment context.
3. Include hard-block behavior for `/api/me`, callback route, and provider-env failures.
4. Link the change to canonical consumer integration contract surfaces:
   - [Auth service and session contract](../README.md#auth-service-and-session-contract)
   - [Session behavior](../README.md#session-behavior)
   - [App Config Model](../README.md#app-config-model)

## Compliant Example

- Auth marks `/api/me` or callback errors as blocked and refuses downstream success claims until app config and provider posture are valid.

## Non-Compliant Example

- A feature ships with provider/env assumptions and claims integration success while callback URLs, `AUTH_APP_CONFIG_PATH`, or `AUTH_PORT` integration evidence are missing.
