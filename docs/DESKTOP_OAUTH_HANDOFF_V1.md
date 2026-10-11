# Desktop OAuth handoff v1

Contract: `life.auth.desktop-handoff/v1`.

The contract is capability source for the TypeScript native profile and a standards reference for existing-auth alignment. AUTH does not install an adapter or operate a desktop callback service. A product that selects this capability owns its generated or existing native implementation, OS integration, routing, secure storage, tests, and deployment.

The retained requirements are system-browser authorization, PKCE, state and callback binding, registered client and issuer validation, single-use exchange, bounded timeouts, generation checks, protected session storage, replay rejection, explicit account switching, revocation/logout, and crash-safe recovery. Product-specific window activation and callback routing are `AGENT_INTEGRATION_REQUIRED`; credentials and provider registration are `EXTERNAL_ACTION_REQUIRED`; a missing reusable security capability is `AUTH_DEVELOPMENT_REQUIRED`.

The prior product-contaminated coordinator was removed rather than presented as reusable wizard code. The TypeScript native profile proves authorization-code PKCE, state, callback binding, refresh replay rejection, and revocation. Product-specific OS process/window activation and secure-storage behavior remains an explicit observation requirement; AUTH must classify a missing target implementation as `AGENT_INTEGRATION_REQUIRED`, not silently install an adapter. Live product acceptance must exercise its own system browser, registered callback, existing process/window activation, denial, timeout, restart, sign-out, and account switch, followed by fresh AUTH observation and VERIFY.
