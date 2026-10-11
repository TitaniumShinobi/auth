# AUTH native CLI

Canonical architecture: [AUTH transient wizard architecture](AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md).

The successor command group is `auth native <discover|plan|apply|verify|repair|migrate|recover>`. DISCOVER, PLAN, dry-run APPLY, and VERIFY are read-only. APPLY requires an exact generated plan, `--authorize`, an immutable AUTH source revision, and an operator-selected `--receipt` outside any hidden AUTH control plane.

Legacy `setup`, `validate`, `runtime`, `product`, and `observer` commands now fail with `LEGACY_PERSISTENT_AUTH_COMMAND_REMOVED_USE_NATIVE_WORKFLOW`. Their implementation modules remain temporarily as reviewed source material until the successor reaches equivalent recovery coverage; they are not reachable production commands.

The first profile is `typescript-node-express-prisma/1`. It writes ordinary product-owned source, Prisma schema, lockfile, `package.json`, `tsconfig.json`, and `auth-standards.json`. It never writes `.auth-runtime`, `.auth-kit`, an adapter, daemon, copied package, installed AUTH workflow, or lifecycle control plane.

Existing conflicting authentication or product files stop planning with a review-required error. REPAIR is same-version only, restores only receipt-authenticated files from the exact immutable source revision, and verifies afterward.

APPLY uses an atomic revisioned journal and records staged file identity/digest before publication. `auth native recover --repo <path>` rolls an interrupted APPLY back or finalizes an already COMPLETE APPLY. Recovery accepts one unambiguous transaction only, quarantines before deletion, requires recorded inode/device identity plus digest agreement, preserves adversarial replacements, validates temporary journal revisions, and removes verified transaction residue. This is controlled-process-termination recovery, not a power-loss/fsync guarantee. An unauthenticated pre-journal residue fails closed.

REPAIR uses the same journal for controlled-process crash recovery. It records each damaged preimage before quarantine and each authenticated replacement before publication. Recovery either restores the complete pre-repair runtime/receipt pair or finalizes the complete repaired pair; it refuses ambiguous replacements and never changes the profile, source revision, or receipt. MIGRATE is not implicit and remains unavailable until a second reviewed profile exists. These limitations make the successor not yet production-ready.
