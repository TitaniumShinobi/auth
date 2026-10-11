# Public-release readiness

Status: **not ready** under the [transient wizard architecture](AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md).

The native workflow is executable; APPLY, same-version REPAIR, and explicit immutable-revision MIGRATE have controlled-process crash recovery with adversarial-replacement protection and old/new receipt lineage. Profile v2 now sources a product-neutral TypeScript/Node/Express/Prisma implementation rather than copying historical product-specific application code. Existing-auth alignment, complete profile capability acceptance, superseded-machinery removal, and public-artifact disposition remain open executable gates. Owner-controlled release actions cannot convert an unresolved executable gate into readiness.

The earlier conditionally-ready assessment below applies only to the superseded installed-runtime campaign and is retained temporarily as audit evidence.

Implemented technical gates:

- complete product-local installation from immutable Git source;
- transactional SETUP and controlled crash recovery;
- locked dependencies, Prisma generation, build/start/readiness acceptance;
- authenticated baseline, read-only VERIFY, bounded REPAIR, explicit UPGRADE and rollback;
- deterministic four-way execution handoffs and observer scaffolding;
- default lifecycle tests and committed CI;
- dependency-review and secret-scanning CI declarations;
- a lockfile audit with zero known npm advisories after pinning the compatible Prisma 6.12.0 client/tooling pair and refreshing fixed transitive dependencies;
- repository wrappers that prefer the optional VVAULT runtime helper but fall back to a verified system Node.js 20+ and npm, so a public clone has no sibling-checkout dependency;
- clean-clone acceptance procedure;
- compatibility, versioning, migration, threat-model, support, contribution, and security documentation.

The path/commit-only [public history audit](PUBLIC_HISTORY_AUDIT.md) covers every current local and origin branch ref and all reachable commits without printing candidate secret values.

Release remains blocked on the applicable entries in [the human-action ledger](HUMAN_ACTION_LEDGER.md), especially license choice, security contact, any confirmed history remediation, and owner approval of the first tag. Power-loss durability and incompatible migrations remain explicitly unsupported.
