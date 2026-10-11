# Product-local Authentication System

This lifecycle directory accompanies the complete authentication runtime installed at `.auth-runtime/auth-system/` from the shared `auth/` source kit.

Rules:

- This repository owns and runs the complete installed authentication system after setup.
- Do not depend on the shared `auth/` checkout as a forever runtime hub.
- Keep visible login, signup, consent, account, and logout UI in this repository.
- Keep secret values out of source control and out of reports.
- Fill `.auth-kit/observer-input.json` only with fresh, secret-free evidence. It begins fail-closed and INDETERMINATE.
- Follow `executionClassification`: registered bounded ACT first; agent work only for product configuration, UI, routing, deployment, or observation; external actions stay with the owner; missing reusable capabilities return to AUTH development.
- One real provider is enough. Remove placeholder providers.

Expected local API surfaces:

- `GET /api/auth/config`
- `POST /api/auth/login`
- `POST /api/auth/register`
- `GET /api/auth/:provider`
- `GET /api/auth/:provider/callback`
- `GET /api/me`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`

Proof is not complete until this repository can start independently and prove config, login or OAuth, `/api/me`, refresh, logout, and fail-closed unknown-origin behavior without requiring the source `auth/` checkout to stay running.
