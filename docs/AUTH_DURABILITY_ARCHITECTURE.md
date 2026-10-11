# AUTH durability architecture (superseded)

This installed-runtime architecture is superseded by [AUTH transient wizard architecture](AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md). Its transaction, provenance, rollback, verification, and crash-recovery techniques are being ported to exact target-native changes; its `.auth-runtime`, `.auth-kit`, baseline, observer, and lifecycle-control-plane ownership model is not the product destination.

This document is the canonical architecture for AUTH durability. Implementation and documentation must change together: a lifecycle, ownership, artifact, or invariant change is incomplete until this document and the affected implementation agree.

## Purpose and ownership

AUTH exists so authentication survives ordinary product development. AUTH owns the canonical authentication-system source, initial installer, lifecycle contract, deterministic verification rules, bounded repair contracts, and provenance rules for intentional change.

The consuming product owns the installed system, its secrets and runtime data, provider registrations, product-facing authentication UI, deployment, startup, monitoring, and runtime operation. AUTH is not a shared central runtime service, a thin adapter, or a permanent runtime dependency on the source `auth/` checkout.

Wizard handoffs have exactly four execution classifications: `AUTO_REPAIR_AVAILABLE`, `AGENT_INTEGRATION_REQUIRED`, `EXTERNAL_ACTION_REQUIRED`, and `AUTH_DEVELOPMENT_REQUIRED`. Registered bounded ACT handlers are preferred. Agents may implement only product-specific configuration, UI, routing, deployment, and observation seams; credentials, provider registration, legal choices, irreversible migrations, and final release approval remain owner actions.

## Lifecycle

`SETUP → ESTABLISH → normal development with VERIFY → bounded REPAIR when verification fails → authorized UPGRADE / ADVANCE for intentional change`

- **SETUP** transactionally installs the complete product-local runtime and its durability controls. Initial setup never overwrites an existing runtime or lifecycle bundle.
- **ESTABLISH** records the explicitly reviewed known-good baseline. An unestablished installation must not claim durability.
- **VERIFY** read-only and deterministically checks the installed system, pinned inputs, verifier provenance, and established history. It emits its report to the caller and does not write it into the installation. Normal product development runs VERIFY without the AUTH source checkout or setup process.
- **REPAIR** is an authorized, version-preserving reconstruction from the authenticated baseline's immutable commit. Only runtime inventory/integrity drift is repairable; provenance, baseline, ownership, or ambiguous failures refuse repair. Candidate acceptance precedes an atomic runtime swap and fresh VERIFY.
- **UPGRADE** is an explicitly authorized change to a selected immutable commit. The candidate is built and accepted before activation; the old runtime remains quarantined until the matching baseline and lineage are advanced.
- **ADVANCE** appends a reviewed known-good baseline after an intentional compatible change. It never silently rewrites history.

## SETUP installation

SETUP installs:

- `.auth-runtime/auth-system/`: the complete product-local provider, session, refresh, authorization, persistence, configuration, build, and launch source;
- `.auth-kit/`: configuration, system instructions, verifier runtime, observer, contract, provenance, reports, and empty append-only baseline/history stores;
- `.github/workflows/auth-product-contract.yml`: the deterministic verification gate.

The installation is independent after publication. Runtime requests are served by the product-owned installed system; they do not call the setup wizard or source AUTH checkout.

New installations include `.auth-kit/observe.mjs` and `.auth-kit/observer-input.json`: a deterministic, fail-closed read-only observer scaffold covering every catalog capability. It begins INDETERMINATE and cannot establish a baseline until product-owned evidence and runtime-independence observations are supplied. `auth observer scaffold` migrates only the exact legacy placeholder in an unestablished contract and refuses custom or established observers.

Runtime source bytes come from one resolved Git commit, not from the source checkout's working tree. The installed manifest records the commit, tree, content digest, runtime inventory digest, lockfile digest, configuration digest, installer version, installation identifier, compatibility declaration, lifecycle state, and lineage fields. Dirty or untracked checkout bytes are therefore excluded rather than silently treated as a release. The installed runtime includes the committed `package-lock.json` and declares `npm ci` as its dependency installation path.

The manifest timestamp is UTC ISO 8601 metadata and is intentionally outside the deterministic installation identifier. The identifier is the canonical SHA-256 digest of product identity, immutable source identity, runtime inventory, dependency lockfile, and non-secret product configuration. Secret values are neither installation input nor provenance content.

## Runtime baseline and replacement

`auth runtime establish` runs locked dependency installation, product-local Prisma generation, build, isolated startup, readiness, and route acceptance before atomically publishing authenticated `.auth-kit/runtime-baseline/` material, including its `state.json`. The baseline contains only AUTH-owned immutable runtime files, manifest, and lifecycle state; secrets, dependency directories, build output, sessions, identities, storage, and product files are excluded.

`auth runtime verify` is read-only. It binds current runtime integrity to the authenticated baseline and stable installation identifier. Operational acceptance is recorded during establishment and candidate validation; normal VERIFY does not rebuild or start the product.

`auth runtime repair` accepts only runtime inventory/file drift, reconstructs the exact baseline revision, refuses any installation identifier change, accepts the candidate, transactionally swaps it, verifies it, and records repair lineage. `auth runtime upgrade --target-revision <commit>` follows the same swap protocol but requires a different immutable installation identifier and records previous/target lineage.

The runtime swap journal keeps the old runtime until candidate verification and matching baseline advancement succeed. Its durable states are `PREPARED`, `OLD_QUARANTINED`, `NEW_PUBLISHED`, `BASELINE_ADVANCING`, and `BASELINE_ADVANCED`; the two baseline renames also have a tested termination boundary. Recovery rolls back states before authenticated baseline publication and finalizes only when the runtime installation identity and the target baseline digest agree. A failure may not leave a mixed runtime/baseline pair.

Real child-process termination tests call `process.exit(87)` only behind `AUTH_RUNTIME_TEST_MODE=1`, restart the CLI, and cover REPAIR and UPGRADE at all six boundaries. REPAIR restart completes the same immutable version; UPGRADE recovery yields the complete old pair before baseline publication or the complete new pair afterward. Each result is re-verified, product/session/data sentinels remain byte-identical, and journal, candidate, previous-runtime, next-baseline, and previous-baseline residue must be absent. This is controlled process-termination recovery, not a power-loss durability claim.

## Durability invariants

1. Initial SETUP is explicitly authorized and preflights every destination before writing.
2. SETUP stages all artifacts before publication and publishes with atomic rename where practical.
3. A journal records every planned publication and any parent directory created by the invocation.
4. Failed SETUP removes only artifacts whose journal path, recorded post-publication device/inode identity, and digest all prove they were created by that invocation.
5. Rollback first atomically renames each published artifact to a same-filesystem quarantine, then verifies its identity and digest. Ambiguous objects are restored when safely possible and preserved; rollback fails closed.
6. Recursive staging cleanup requires the expected resolved path, a non-symlink directory, recorded device and inode, matching transaction marker, and the journal for that same transaction. Every condition is required; a copied marker is never deletion authority.
7. Existing runtime, lifecycle, and workflow destinations are never silently overwritten.
8. Journal revisions are written to an adjacent temporary file and atomically renamed into place; revisions increase monotonically.
9. Before a new initial SETUP, abandoned-transaction recovery accepts only one exact-prefix, schema-valid journal whose paths, marker, identities, and digests agree. Malformed, symlinked, path-escaping, duplicate, unsupported, or ambiguous evidence fails closed.
10. Incomplete transactions are safely rolled back. A valid COMPLETE journal with every permanent artifact intact is finalized without removing the completed installation.
11. Temporary staging, quarantine, journal-temporary, and active-journal artifacts are absent after successful setup and after successfully verified recovery.
12. ESTABLISH is a separate reviewed act; SETUP alone is not a durability claim.
13. VERIFY is deterministic, product-local, and independent of normal AUTH orchestration.
14. Baselines and history are append-only. Intentional change requires the appropriate authorized lifecycle operation.
15. Authentication secrets, provider credentials, session state, and user data are never setup artifacts.
16. Product authentication UI and runtime operations remain product-owned.
17. SETUP never copies `node_modules`, build output, untracked files, or arbitrary working-tree bytes. Dependencies are installed product-locally from the committed lockfile.
18. Controlled process-termination recovery is tested. Power-loss durability is not claimed: journal files and containing directories are not yet explicitly `fsync`ed.
19. Runtime and baseline agreement is proven by both installation identity and the target baseline digest; equal runtime versions during REPAIR cannot make an unadvanced baseline appear advanced.

## Normal product development

Ordinary product changes run the installed VERIFY gate. A passing result preserves the established authentication contract. A failure blocks the durability claim and produces a bounded handoff; it does not authorize ad hoc mutation. Product runtime continues to use its installed authentication system without contacting the source AUTH repository.

## Current implementation status

Initial SETUP installs the product-local runtime, lifecycle bundle, setup metadata, and workflow through one staged, revisioned transaction. Publication records post-rename filesystem identity and content digest. Rollback uses verified quarantine; staging cleanup requires independent identity, marker, path, and journal agreement. Parent creation intent is journaled before mutation; a termination before its device/inode can be recorded preserves the parent and fails closed. Before a new initial setup, deterministic recovery either rolls back one validated incomplete transaction or finalizes one validated COMPLETE transaction. Adversarial replacement, abrupt process exit at each publication boundary, interrupted journal persistence, dry-run behavior, explicit authorization, successful validation, and residue cleanup have focused tests.

SETUP now selects immutable Git-commit source and installs a committed dependency lockfile with machine-readable provenance. Product-local `npm ci`, product-local Prisma client generation, and the isolated TypeScript build succeed without resolving the AUTH checkout. The earlier TS2347 result was caused by compiling before `prisma generate`; it was not a defect in the typed raw-query calls. A temporary immutable source checkout is physically renamed before the built runtime starts, reaches `/ready`, serves `/health`, and exposes the configured auth and provider-callback routes. Existing product-contract ESTABLISH/VERIFY/ADVANCE behavior remains distinct from runtime replacement lifecycle operations.

This phase proves canonical continuity and transactional initial SETUP only. It does not establish production readiness.

## Intentionally deferred gaps

- a reviewed release/tag policy above the implemented immutable Git-commit source mode;
- consuming-product startup, routing, callback, and readiness integration;
- power-loss durability for runtime swaps (`fsync` is not implemented);
- explicit data/schema migration plugins for future incompatible upgrades; current upgrades are source-compatible and declare no data migration;
- expanded ADVANCE/migration policy for incompatible runtime releases;
- external required-check enforcement and independently retained checkpoints.

GRID and VVAULT remain prior durability proving grounds; this architecture does not restart or replace their product work.

## CleanHouse integration status

CleanHouse's existing Python authentication remains its sole active authority. The Node runtime is an inactive candidate only: it is not started, routed, assigned live port 1111, or allowed to read or mutate CleanHouse identity, session, storage, or application data. No CleanHouse files are changed by this campaign. Any future migration requires separate product authorization and continuity evidence.
