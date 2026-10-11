# Desktop OAuth handoff v1

Contract: `life.auth.desktop-handoff/v1`. Reusable reference source: `src/auth/desktopHandoff.ts`.

The contract is capability source for the TypeScript native profile and a standards reference for existing-auth alignment. AUTH does not install an adapter or operate a desktop callback service. A product that selects this capability owns its generated or existing native implementation, OS integration, routing, secure storage, tests, and deployment.

The retained requirements are system-browser authorization, PKCE, state and callback binding, registered client and issuer validation, single-use exchange, bounded timeouts, generation checks, protected session storage, replay rejection, explicit account switching, revocation/logout, and crash-safe recovery. Product-specific window activation and callback routing are `AGENT_INTEGRATION_REQUIRED`; credentials and provider registration are `EXTERNAL_ACTION_REQUIRED`; a missing reusable security capability is `AUTH_DEVELOPMENT_REQUIRED`.

`bin/node20 --test src/test/desktop-handoff.test.mjs` proves the framework-neutral coordinator's ordering, cancellation, binding, replay, expiry, recovery, page secrecy, and fallback behavior. It does not prove an OS adapter or live provider deployment. Product acceptance must exercise its own system browser, registered callback, existing process/window activation, denial, timeout, restart, sign-out, and account switch, followed by fresh AUTH observation and VERIFY.
