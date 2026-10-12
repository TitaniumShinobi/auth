# Public-release readiness

Status: **conditionally ready** under the [transient wizard architecture](AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md).

The native workflow is executable; APPLY, same-version REPAIR, and explicit immutable-revision MIGRATE have controlled-process crash recovery with adversarial-replacement protection and old/new receipt lineage. Profile v2 sources a product-neutral TypeScript/Node/Express/Prisma implementation. Existing-auth assessment and non-overwriting standards/test alignment are implemented. The superseded installed-runtime command surface and historical product-specific service implementation have been removed. Clean-checkout install, wizard build, lifecycle, generated-product operation, and source-checkout independence pass. Product-specific configurations and GRID legal material have been removed from the default branch with a digest/provenance manifest. Apache-2.0 licensing is committed while package publication remains disabled with `private: true`.

Implemented gates are tracked by the [public-production rubric](AUTH_PUBLIC_PRODUCTION_RUBRIC.md), not by superseded SETUP claims. CI, dependency review, secret scanning, compatibility, migration, threat-model, support, contribution, and security documents remain subject to the final clean-checkout and public-source audit.

The path/commit-only [public history audit](PUBLIC_HISTORY_AUDIT.md) covers every current local and origin branch ref and all reachable commits without printing candidate secret values.

All current executable gates in the public-production rubric pass in the clean checkout. AUTH is therefore **conditionally ready**: remaining release prerequisites are the public security contact, resolution of the conditional historical-data finding, the repository-visibility decision, and explicit release/tag approval. OAuth registration, credentials, live-provider acceptance, and product authority cutovers are deployment/operator actions rather than defects in the public AUTH release. Power-loss/fsync durability and irreversible or incompatible migrations are explicitly unsupported and are not included in the readiness claim.
