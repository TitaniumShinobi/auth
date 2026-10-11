# Contributing

Read [the canonical durability architecture](docs/AUTH_DURABILITY_ARCHITECTURE.md), [security policy](SECURITY.md), and repository `RULES.md` before changing AUTH.

Contributions must preserve the product-local architecture: AUTH SETUP installs the complete runtime; consuming products must not recreate runtime/provider/session implementation. Product integration is limited to configuration, secrets, UI, routing, deployment, and observation.

Required checks:

```sh
npm ci
npm test
npm run test:durability
npm run build
```

Use temporary products for setup/lifecycle tests. Never commit credentials, databases, runtime state, identity/session data, generated dependency directories, or private evidence. Changes to compatibility, manifests, lifecycle state, rollback behavior, or installed artifacts must update canonical documentation in the same change.

Agent-origin changes must also satisfy the repository governance policy and audit requirements. Pull requests should explain compatibility impact, migration behavior, security impact, tests, and rollback.
