# Public-release readiness

Status: **not ready** under the [transient wizard architecture](AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md).

The native workflow is executable; APPLY, same-version REPAIR, and explicit immutable-revision MIGRATE have controlled-process crash recovery with adversarial-replacement protection and old/new receipt lineage. Profile v2 sources a product-neutral TypeScript/Node/Express/Prisma implementation rather than copying historical product-specific application code. Existing-auth assessment and non-overwriting standards/test alignment are implemented. The superseded installed-runtime command surface and implementation have been removed. Clean-checkout acceptance, public-artifact disposition, and the final history/sensitivity audit remain open gates. Owner-controlled release actions cannot convert an unresolved executable gate into readiness.

Implemented gates are tracked by the [public-production rubric](AUTH_PUBLIC_PRODUCTION_RUBRIC.md), not by superseded SETUP claims. CI, dependency review, secret scanning, compatibility, migration, threat-model, support, contribution, and security documents remain subject to the final clean-checkout and public-source audit.

The path/commit-only [public history audit](PUBLIC_HISTORY_AUDIT.md) covers every current local and origin branch ref and all reachable commits without printing candidate secret values.

License selection is owner-controlled and is not established by ambiguous working-tree files. Release also remains blocked on the applicable entries in [the human-action ledger](HUMAN_ACTION_LEDGER.md), especially the security contact, any confirmed history remediation, and owner approval of the first tag. Power-loss durability and incompatible migrations remain explicitly unsupported.
