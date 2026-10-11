# Public onboarding

1. Use Node.js 20 or newer and run `npm ci` in a clean AUTH checkout.
2. Run `bin/auth native discover --repo /absolute/product` and `native assess` when authentication already exists.
3. For greenfield TypeScript/Node/Express/Prisma, create an exact `native plan`, review every destination and digest, then run `native apply --authorize`.
4. For existing authentication, use `native align-plan`; AUTH adds only product-owned standards and observation tests and preserves authentication source.
5. In the product, run `npm ci`, `npm run prisma:generate`, `npm run prisma:migrate`, `npm run build`, and `npm test` before deployment.
6. Supply secrets through the product's approved runtime secret channel. Register exact callback URLs with providers and configure product UI, routing/TLS, delivery, deployment, monitoring, and MCP tools.
7. Keep the operator-selected receipt outside any hidden control plane. Run read-only `native verify` after ordinary development. Use same-version `native repair` only for authenticated owned bytes and explicit `native migrate` for an immutable revision change.

AUTH leaves no daemon, adapter, `.auth-runtime`, `.auth-kit`, copied AUTH package, installed workflow, or source-checkout dependency. Do not manually recreate authentication architecture.
