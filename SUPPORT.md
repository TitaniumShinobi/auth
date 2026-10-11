# Support boundary

AUTH supports installation and lifecycle integrity for the complete product-local authentication runtime it owns.

Supported AUTH work includes SETUP, observer scaffolding, ESTABLISH, read-only VERIFY, registered bounded ACT, version-preserving REPAIR, compatible UPGRADE, rollback, and controlled process-termination recovery.

Consuming-product teams remain responsible for configuration, secret custody, visible UI, routing/proxy configuration, deployment, readiness observation, provider-console registration, and product runtime operations. Agents may implement those seams only when an AUTH handoff returns `AGENT_INTEGRATION_REQUIRED` and must then collect fresh evidence and run VERIFY.

AUTH does not provide legal advice, provider-account administration, credential custody, user-data migration approval, power-loss durability, or automatic incompatible-schema migration. Unknown reusable authentication capabilities return `AUTH_DEVELOPMENT_REQUIRED`; credentials, consent, provider registration, and operator approval return `EXTERNAL_ACTION_REQUIRED`.
