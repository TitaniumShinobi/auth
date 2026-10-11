# Public-release readiness

Status: **conditionally ready; owner actions remain**.

Implemented technical gates:

- complete product-local installation from immutable Git source;
- transactional SETUP and controlled crash recovery;
- locked dependencies, Prisma generation, build/start/readiness acceptance;
- authenticated baseline, read-only VERIFY, bounded REPAIR, explicit UPGRADE and rollback;
- deterministic four-way execution handoffs and observer scaffolding;
- default lifecycle tests and committed CI;
- dependency-review and secret-scanning CI declarations;
- clean-clone acceptance procedure;
- compatibility, versioning, migration, threat-model, support, contribution, and security documentation.

The path/commit-only [public history audit](PUBLIC_HISTORY_AUDIT.md) covers every current local and origin branch ref and all reachable commits without printing candidate secret values.

Release remains blocked on the applicable entries in [the human-action ledger](HUMAN_ACTION_LEDGER.md), especially license choice, security contact, any confirmed history remediation, and owner approval of the first tag. Power-loss durability and incompatible migrations remain explicitly unsupported.
