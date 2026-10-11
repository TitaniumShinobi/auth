# AUTH native CLI

Canonical architecture: [AUTH transient wizard architecture](AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md).

The successor command group is `auth native <discover|plan|apply|verify|repair|migrate|recover>`. DISCOVER, PLAN, dry-run APPLY, and VERIFY are read-only. APPLY requires an exact generated plan, `--authorize`, an immutable AUTH source revision, and an operator-selected `--receipt` outside any hidden AUTH control plane.

Legacy `setup`, `validate`, `runtime`, `product`, and `observer` commands now fail with `LEGACY_PERSISTENT_AUTH_COMMAND_REMOVED_USE_NATIVE_WORKFLOW`. Their implementation modules remain temporarily as reviewed source material until the successor reaches equivalent recovery coverage; they are not reachable production commands.

The first profile is `typescript-node-express-prisma/1`. It writes ordinary product-owned source, Prisma schema, lockfile, `package.json`, `tsconfig.json`, and `auth-standards.json`. It never writes `.auth-runtime`, `.auth-kit`, an adapter, daemon, copied package, installed AUTH workflow, or lifecycle control plane.

Existing conflicting authentication or product files stop planning with a review-required error. REPAIR is same-version only, restores only receipt-authenticated files from the exact immutable source revision, and verifies afterward. Initial creation and repair have exception rollback, but their successor crash journal and adversarial-replacement proof are not yet complete. MIGRATE is not implicit and remains unavailable until a second reviewed profile exists. These limitations make the successor not yet production-ready.
