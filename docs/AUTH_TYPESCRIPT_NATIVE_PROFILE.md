# TypeScript/Node/Express/Prisma native profile

Profile `typescript-node-express-prisma/2` is the first public target-native profile. Its authoritative source is `profiles/typescript-node-express-prisma/`; the wizard maps that directory into ordinary product-owned `src/` and `prisma/` paths. It no longer copies the repository's historical LIFE/VVAULT/Chatty application.

The profile provides product-neutral credentials, magic-email delivery, secure cookie sessions, OAuth authorization-code with S256 PKCE, access tokens, refresh rotation and replay-family revocation, logout/revocation, Prisma persistence, OAuth metadata, and an OAuth-protected MCP resource boundary. Clients and upstream providers are configuration data. The MCP transport and tool implementation remain product-owned; the profile authenticates the request and exposes the bound subject/scope rather than creating another identity authority.

Required configuration is `AUTH_ISSUER`, a high-entropy `AUTH_SIGNING_SECRET`, `DATABASE_URL`, and `AUTH_CLIENTS_JSON`. Magic email additionally requires `AUTH_MAGIC_DELIVERY_URL` and `AUTH_MAGIC_DELIVERY_TOKEN`. `AUTH_PROVIDERS_JSON` is optional. Secrets are runtime inputs and never appear in a plan, receipt, generated source, or standards contract.

The generated server listens on loopback by default and exposes `/health`, `/ready`, `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/magic/request`, `/api/auth/magic/verify`, `/api/me`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, authorization-server metadata, protected-resource metadata, and a fail-closed `/mcp` boundary. Products own external routing, TLS termination, visible UI, delivery infrastructure, provider registration, deployment, monitoring, and MCP tools.

The bundled Prisma schema uses SQLite for deterministic local installation and acceptance. A product needing PostgreSQL or another provider requires an explicit reviewed profile migration; AUTH does not rewrite a live datasource or schema implicitly.
