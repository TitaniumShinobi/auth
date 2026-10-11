# Agentic Coder Prompt

This is the canonical reusable prompt for one-time auth setup in a consuming repository.

Copy only this prompt into the agentic coder working in that repository:

```text
Run the authorized AUTH SETUP for this repo once. SETUP installs the complete authentication runtime under .auth-runtime/auth-system and the lifecycle verifier under .auth-kit. This repo supplies configuration, secrets, UI, routing, deployment, and observation around that installed runtime. Do not make it call a separate shared auth checkout at runtime.

Use the reusable auth contract:
- visible login/signup/logout UI stays in this repo
- the installed runtime owns login, OAuth callbacks, cookies, /api/me, refresh, logout, and supported provider behavior after setup
- one real provider is enough; remove placeholder providers
- never print secret values
- OAuth start must emit the same redirect_uri as the setup callback report. Callback precedence is: app-specific callback env, app-specific public callback base, request Origin/Referer, generic callback env, backend/internal callback env. Any selected callback must match an allowed frontend origin; stale generic/backend callback values must fail validation instead of silently overriding the target repo callback.

Do the setup:
1. Record this repo's ports and origins.
2. Configure app id/name, env prefix, allowed origins, redirects, docs/consent, Turnstile, cookies, storage, and providers.
3. Build and launch the installed product-local runtime, then configure product-owned UI and routing to its /api/auth/config, /api/auth/login, /api/auth/register, /api/auth/:provider, /api/auth/:provider/callback, /api/me, /api/auth/refresh, and /api/auth/logout surfaces. Never recreate, copy, adapt, or carry runtime/provider implementation manually.
4. List exact OAuth callback URLs to register.
5. Add a check that compares the setup-reported OAuth callback URL to the redirect_uri emitted by /api/auth/:provider.

Do not call it done until proof passes:
- build/start succeeds
- /api/auth/config returns this app
- unauthenticated /api/me fails cleanly
- login or OAuth issues cookies
- authenticated /api/me returns the user
- refresh rotates
- logout clears cookies
- unknown origins/app ids fail closed

Return only: changed files, recorded ports, env var names without values, callback URLs, commands run, proof results, and blockers.
```
