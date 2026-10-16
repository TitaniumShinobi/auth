![auth](docs/assets/auth-banner.png)

auth is a transient authentication-engineering wizard. It discovers and assesses a consuming product, creates or aligns target-native authentication through an exact reviewed plan, verifies the result, emits an operator-selected secret-free receipt, and exits.

Canonical architecture: [auth transient wizard architecture](docs/AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md). Public acceptance gates: [auth public-production rubric](docs/AUTH_PUBLIC_PRODUCTION_RUBRIC.md).

auth leaves no `.auth-runtime`, `.auth-kit`, adapter, daemon, shadow service, copied auth package, lifecycle control plane, installed auth workflow, or continuing dependency on this repository. The consuming product owns its resulting authentication source, configuration and persistence schemas, migrations, tests, standards contracts, CI, secrets, identities, sessions, and data.

## Native workflow

```sh
bin/auth native discover --repo /absolute/product
bin/auth native assess --repo /absolute/product
bin/auth native plan --repo /absolute/empty-product --product my-product \
  --receipt /operator/receipts/my-product.json --plan /operator/review/my-product.plan.json
bin/auth native apply --repo /absolute/empty-product \
  --plan /operator/review/my-product.plan.json --authorize
bin/auth native verify --repo /absolute/product --receipt /operator/receipts/my-product.json
```

For existing authentication, use `native align-plan` after `assess`. Alignment creates only product-owned standards and observation tests and never overwrites authentication source heuristically. See [existing-auth alignment](docs/AUTH_EXISTING_ALIGNMENT.md).

`native repair` is same-version and receipt/provenance bound. `native migrate` requires an explicit immutable target revision, verifies before receipt advancement, records lineage, and recovers to a complete old or new runtime/receipt pair. See [native CLI](docs/AUTH_NATIVE_CLI.md).

## First profile

The first public profile is TypeScript, Node.js, Express, and Prisma. auth installs the reviewed product-neutral profile under ordinary product paths. The product then supplies configuration, secret values, visible UI, external routing/TLS, deployment, monitoring, provider registration, delivery infrastructure, and product-owned MCP tools. See [profile contract](docs/AUTH_TYPESCRIPT_NATIVE_PROFILE.md).

The profile covers credentials, generic OAuth/OIDC providers, authorization code with S256 PKCE, state/nonce/callback validation, magic email, hardened cookies and sessions, access and rotating refresh tokens, replay-family revocation, logout, Prisma persistence, native/CLI clients, and an OAuth-protected MCP resource boundary.

## Agent boundary

Agents run auth and follow its machine classification. They may implement only the exact product-native UI, routing, configuration, deployment, observation, or reviewed integration seam named by `AGENT_INTEGRATION_REQUIRED`. They must not recreate authentication architecture. Registered bounded ACT handlers remain preferred. Credentials, provider registration, legal choices, irreversible migrations, and release approval remain owner-controlled.

## Security and limitations

Plans and receipts contain digests and non-secret configuration shape, never secret values. VERIFY is read-only. Mutations use target-filesystem staging, atomic publication, authenticated rollback, and controlled-process crash recovery. Ambiguous replacements are preserved and fail closed.

Power-loss/fsync durability and irreversible datasource/schema migration are not claimed. Current release status and remaining executable gates are recorded in [public-release readiness](docs/PUBLIC_RELEASE_READINESS.md).

## Requests and support

Submit bug reports, compatibility requests, suggestions, support questions, and security concerns through the private [auth Request Intake](https://docs.google.com/forms/d/e/1FAIpQLSedgkIPwkanca6XJjb1iL2dI3rOm-4bTNF3dEXaoiT9UHXwAw/viewform). Security vulnerabilities may also be reported through GitHub's private vulnerability-reporting interface. Do not include credentials, tokens, cookies, private keys, identity databases, or user data.

Security handling is defined in [SECURITY.md](SECURITY.md). Contribution and support boundaries are documented in [CONTRIBUTING.md](CONTRIBUTING.md) and [SUPPORT.md](SUPPORT.md).

Verification scopes and release gates: [AUTH assurance boundaries](docs/AUTH_ASSURANCE_BOUNDARIES.md).
