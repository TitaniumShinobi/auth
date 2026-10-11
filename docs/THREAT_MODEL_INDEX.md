# Threat-model index

| Surface | Primary controls | Evidence |
| --- | --- | --- |
| Setup publication | preflight, staging, atomic rename, identity/digest rollback, journal recovery | `scripts/auth-setup-transaction.mjs`, `scripts/auth-cli.test.mjs` |
| Runtime provenance | immutable Git commit, file inventory, lockfile/config digests | `scripts/auth-runtime-installer.mjs` |
| Runtime replacement | candidate acceptance, identity-bound swap journal, baseline pairing, rollback | `scripts/auth-runtime-lifecycle.mjs` |
| Crash recovery | real child termination at every swap state; old/new pair invariant | `scripts/auth-runtime-lifecycle-crash.test.mjs` |
| Evidence integrity | binding to product revision/config/artifacts; read-only VERIFY; regression retention | `scripts/auth-product-contract.mjs` |
| Agent execution | four execution classifications, registered bounded handlers, exact authorization, post-ACT VERIFY | `scripts/auth-blocker-handoff.mjs`, `scripts/auth-wizard.mjs` |
| Observer onboarding | generated fail-closed checklist; no commands or secrets; product-bound output | `scripts/auth-observer-scaffold.mjs` |
| Secret handling | no `.env` reads by setup; no secret values in reports; CI secret scan | `SECURITY.md`, `.github/workflows/auth-ci.yml` |
| Product boundary | product supplies only config/secrets/UI/routing/deployment/observation | `docs/AUTH_DURABILITY_ARCHITECTURE.md` |

Out of scope: filesystem power-loss guarantees without `fsync`, provider compromise, compromised product hosts, legal determinations, and unapproved incompatible data migrations.
