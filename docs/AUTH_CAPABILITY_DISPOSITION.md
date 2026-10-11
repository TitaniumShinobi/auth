# Capability disposition

| Capability | Disposition | Successor rule |
| --- | --- | --- |
| OAuth/OIDC authorization code, redirects, callbacks | GENERALIZE | Product-neutral issuer/client/redirect schemas; preserve negative tests. |
| PKCE, state, nonce, replay protection | RETAIN | Required by applicable web/native profiles. |
| Credentials and password hashing | RETAIN | Native profile; no plaintext fallback. |
| Magic email | RETAIN | Expiring, single-use, intent-bound challenge and delivery failure handling. |
| Cookies and sessions | GENERALIZE | Product-native configuration with secure defaults and explicit deployment policy. |
| Access/refresh rotation | RETAIN | Rotation, replay rejection, expiry, and session binding remain mandatory. |
| Revocation and logout | RETAIN | Server invalidation and client credential clearing remain independently tested. |
| Memory/SQLite/PostgreSQL/Prisma persistence | GENERALIZE | Profile/plugin schema without product identities or private datasource defaults. |
| Native and CLI authorization | GENERALIZE | The native profile retains registered-client authorization code, PKCE, callback, token, and binding standards. OS activation remains product-owned integration evidence; the product-contaminated coordinator was removed. |
| MCP authorization | GENERALIZE | OAuth protected-resource metadata and per-request token/resource/scope/subject enforcement. |
| LIFE/VVAULT owner, assertion, federation, admission, fixed clients | SUPERSEDE | Remove from generic core or express as reviewed neutral extension; owner decides historical destination. |
| Installed runtime, `.auth-kit`, baselines, observer, swap lifecycle | REMOVE | Replace with target-native plans, receipts, read-only verification, and exact-file recovery. |

No `RETAIN`, `GENERALIZE`, or `SUPERSEDE` implementation is removed before successor tests pass.
