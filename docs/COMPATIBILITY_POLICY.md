# Compatibility policy

AUTH compatibility is defined by explicit machine-readable contracts, not by undocumented behavior.

- Runtime manifest contract version and product-contract schema changes follow the versioning policy.
- VERIFY accepts only the catalog versions listed by the installed verifier.
- A compatible UPGRADE must preserve identity, sessions, product data, configuration ownership, and supported external interfaces.
- REPAIR never changes the installed source revision.
- Unknown contract versions and semantic ambiguity fail closed with `AUTH_DEVELOPMENT_REQUIRED`.
- Node compatibility is recorded in the installed manifest. Dependency installation uses the committed lockfile and `npm ci`.

An incompatible storage or identity migration is unsupported until a reviewed migration implementation, rollback boundary, continuity proof, and explicit owner authorization exist.
