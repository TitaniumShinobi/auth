# AUTH transient wizard architecture

This document is the canonical architecture for AUTH.

AUTH is a transient authentication-engineering wizard. It discovers a consuming product, classifies its current authentication state, prepares an exact target-native change plan, applies only an authorized plan, verifies the result, writes an operator-selected secret-free receipt, and exits.

AUTH does not install or require `.auth-runtime`, `.auth-kit`, an AUTH-owned adapter, daemon, shadow service, copied AUTH package, lifecycle control plane, installed AUTH workflow, or continuing dependency on this repository. The product owns all generated or aligned authentication source, configuration schema, persistence schema and migrations, standards contracts, tests, ordinary CI, secrets, identities, sessions, and data.

## First native profile

The first profile is TypeScript, Node.js, Express, and Prisma, derived from this repository's existing working implementation after capability and product-assumption review. Framework-neutral discovery, plan, receipt, security-profile, and plugin schemas remain separate from that profile. AUTH does not add another framework merely to demonstrate portability.

## Lifecycle

`DISCOVER -> CLASSIFY -> PLAN -> APPLY -> VERIFY -> RECEIPT -> EXIT`

Later operation is `DISCOVER -> VERIFY`. A same-version, provenance-authenticated defect may proceed through `PLAN_REPAIR -> REPAIR -> VERIFY -> RECEIPT -> EXIT`. A profile or standards change requires explicit `PLAN_MIGRATION -> MIGRATE -> VERIFY -> RECEIPT -> EXIT`; VERIFY and REPAIR never advance versions.

Classifications are `GREENFIELD`, `COMPATIBLE`, `DEGRADED`, `NONCONFORMANT`, `EXTERNAL_ACTION_REQUIRED`, `MIGRATION_REQUIRED`, and `AUTH_DEVELOPMENT_REQUIRED`. Machine execution handoffs remain `AUTO_REPAIR_AVAILABLE`, `AGENT_INTEGRATION_REQUIRED`, `EXTERNAL_ACTION_REQUIRED`, and `AUTH_DEVELOPMENT_REQUIRED`.

## Change safety

Every mutation requires an exact reviewed plan naming each path, ownership, preimage digest, intended postimage digest, provenance, rollback action, and post-change checks. Existing authentication is never overwritten heuristically. Publication uses target-filesystem staging, atomic rename where possible, an atomic revisioned journal, identity-and-digest verification, quarantine before deletion, and fail-closed recovery. Ambiguous or adversarial replacements are preserved.

Native APPLY journals use `life.auth.native-transaction/2`. Before publication they durably record staged file device/inode identity and digest plus identities of product directories created by the transaction. Recovery accepts exactly one well-formed transaction, atomically quarantines each publication, and deletes it only when the recorded staging identity and digest still agree. Foreign replacements are restored to their destination and recovery fails closed. A COMPLETE transaction is finalized only when its receipt and every permanent file retain their recorded identity and digest. Journal revisions use adjacent temporary files and atomic rename; a valid interrupted temporary revision is reconciled against the prior valid journal. The controlled-process-termination guarantee does not claim power-loss durability.

An interruption before the first journal can authenticate newly created staging state remains fail-closed evidence rather than deletion authority. Native REPAIR uses the same version-2 journal: it authenticates the preimage before quarantine, authenticates the staged replacement before publication, and after interruption restores either the complete pre-repair pair or finalizes the complete repaired pair. It never advances the profile or receipt version.

MIGRATE selects a different immutable Git revision explicitly and requires a passing current receipt. It refuses dirty preimages, target file-set changes, implicit profile changes, no-op targets, and Prisma schema changes that could cross an irreversible data boundary. Changed runtime files are quarantined and replaced transactionally; the successor receipt is staged and published only after target verification passes. Its `priorReceiptDigest` records lineage. Recovery before COMPLETE restores the old runtime and old receipt and removes an authenticated successor receipt; recovery after COMPLETE validates and finalizes the new runtime and new receipt. A mixed runtime/baseline pair is never accepted.

Dry-run, DISCOVER, CLASSIFY, PLAN, and VERIFY are read-only. REPAIR is version-preserving and limited to authenticated AUTH-created bytes or separately authorized product files. MIGRATE is explicit and reports irreversible boundaries before mutation.

## Capability continuity

Every existing capability is classified `RETAIN`, `GENERALIZE`, `SUPERSEDE`, or `REMOVE` before its implementation is changed. OAuth/OIDC, authorization code and PKCE, state/nonce/callback validation, credentials, magic email, cookies, sessions, refresh rotation, replay protection, revocation, logout, persistence, native/CLI authorization, and standards-based MCP behavior are preserved unless a reviewed replacement has equal or stronger executable evidence.

MCP is a resource-server and agent-authorization integration, never a second identity authority. Product-native MCP code validates issuer, audience, resource, scope, expiry, and revocation before tool dispatch and binds the authenticated subject to each request.

## Receipts and limitations

Receipts use canonical JSON and contain no secret values. They bind tool/profile versions, target identity, plan digest, input and output file digests, capability dispositions, verification, rollback/recovery outcome, and optional prior-receipt lineage. Their location is selected by the operator; a receipt is evidence, not a control plane.

Power-loss durability is not claimed without file and directory `fsync` evidence. Irreversible identity or schema migration, provider registration, credentials, legal decisions, publication, and release remain owner-controlled.

Implementation and command-specific documentation change in the same coherent phase and commit. A phase whose behavior and documentation disagree has failed.
