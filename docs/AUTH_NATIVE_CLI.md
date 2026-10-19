# AUTH native CLI

Canonical architecture: [AUTH transient wizard architecture](AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md).

The successor command group is `auth native <discover|assess|plan|align-plan|apply|verify|repair|migrate|recover>`. DISCOVER, ASSESS, PLAN, ALIGN-PLAN, dry-run APPLY, and VERIFY are read-only. APPLY requires an exact generated plan, `--authorize`, an immutable AUTH source revision, and an operator-selected `--receipt` outside any hidden AUTH control plane.

Legacy `setup`, `validate`, `runtime`, `product`, `observer`, and `acceptance` commands fail with `LEGACY_PERSISTENT_AUTH_COMMAND_REMOVED_USE_NATIVE_WORKFLOW`. Their installed-runtime implementation modules have been removed after successor recovery coverage passed.

The first public profile is `typescript-node-express-prisma/2`. It maps the reviewed product-neutral profile source—not the repository's historical product-specific `src/`—into ordinary product-owned source, Prisma schema, lockfile, `package.json`, `tsconfig.json`, and `auth-standards.json`. It never writes `.auth-runtime`, `.auth-kit`, an adapter, daemon, copied package, installed AUTH workflow, or lifecycle control plane. See [the profile contract](AUTH_TYPESCRIPT_NATIVE_PROFILE.md).

Existing conflicting authentication or product files stop planning with a review-required error. REPAIR is same-version only, restores only receipt-authenticated files from the exact immutable source revision, and verifies afterward.

For an existing implementation, `assess` emits bounded static observations and never equates them with runtime proof. `align-plan` creates only product-owned standards and observation-test artifacts; APPLY byte-preserves the existing authentication implementation. See [existing-auth alignment](AUTH_EXISTING_ALIGNMENT.md).

APPLY uses an atomic revisioned journal and records staged file identity/digest before publication. `auth native recover --repo <path>` rolls an interrupted APPLY back or finalizes an already COMPLETE APPLY. Recovery accepts one unambiguous transaction only, quarantines before deletion, requires recorded inode/device identity plus digest agreement, preserves adversarial replacements, validates temporary journal revisions, and removes verified transaction residue. This is controlled-process-termination recovery, not a power-loss/fsync guarantee. An unauthenticated pre-journal residue fails closed.

REPAIR uses the same journal for controlled-process crash recovery. It records each damaged preimage before quarantine and each authenticated replacement before publication. Recovery either restores the complete pre-repair runtime/receipt pair or finalizes the complete repaired pair; it refuses ambiguous replacements and never changes the profile, source revision, or receipt.

`auth native migrate --repo <path> --receipt <current> --target-revision <commit> --new-receipt <path> --authorize` performs an explicit same-profile migration between immutable revisions. It requires an intact current baseline, unchanged file set, reversible Prisma schema boundary, and an actual runtime change. It verifies the target before publishing the lineage-linked receipt. Interruption recovery yields the complete old pair or complete new pair, never a mixed runtime/receipt state. Profile changes and data/schema migrations remain unsupported and owner-governed. These remaining profile and data boundaries keep the successor short of public-production readiness.

## Post-write verification

See the [M4 execution contract](AUTH_VERIFICATION_LANE.md) for automatic scoped lane results, legacy NOT_VERIFIED behavior, reviewed normal-build/CI integration, and the distinction between transaction completion and durable acceptance. Source receipts and historical release evidence retain their existing meaning.
