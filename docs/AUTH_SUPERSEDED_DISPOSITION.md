# Superseded architecture disposition

The transient successor reached greenfield creation, existing-auth alignment, read-only verification, same-version repair, explicit migration, authenticated rollback, controlled-process recovery, and product-owned runtime acceptance before the installed-runtime machinery was removed.

Removed tracked source and tests: `scripts/auth-setup-transaction.mjs`, `auth-runtime-installer.mjs`, `auth-runtime-acceptance*`, `auth-runtime-lifecycle*`, `auth-runtime-durability.test.mjs`, `auth-product-contract*`, the CleanHouse readiness integration, and `templates/auth-adapter/ADAPTER.md`. Removed canonical instructions: `AUTH_SETUP_CLI.md`, `AUTH_PRODUCT_DURABILITY.md`, `AUTH_OPERATOR_HUMAN.md`, `AUTH_DURABILITY_ARCHITECTURE.md`, `AUTH_OPERATOR_AGENT.md`, and `AUTH_WIZARD.md`. The public onboarding, agent prompt, and README were rewritten for the transient workflow.

Several removed files contained pre-existing working-tree edits related to the superseded observer/MCP campaign. Their pre-removal working-byte SHA-256 values were:

- `README.md`: `050870909e6ae63208260171f2ab4ffdbfd9d8f34e2e15be937c9aaec05e6691`
- `docs/AUTH_DURABILITY_ARCHITECTURE.md`: `7bbccab95e3dd4d3f921b3119d27838467b026f7a5b542107277246126ff4446`
- `docs/AUTH_OPERATOR_AGENT.md`: `2a2cf70a8ec00e62af0cea14a03d326f608282af0496a055475dedc0e05c29b8`
- `docs/AUTH_WIZARD.md`: `b64c066f743397abea807e7a03f82830124551631a25652e090180fcbe8c15ab`
- `scripts/auth-observer-scaffold.mjs`: `a5ac4d4896769c000a452c53f1c34253a841bf6d292aaa2f5d97fca30652da8b`
- `scripts/auth-observer-scaffold.test.mjs`: `e00a3a75cd5ce90d6ea23a71d119c90f5adcf337ba9bbdf8807a0f17bf4d3801`

The combined pre-removal binary diff digest was `1090b62a15529877a680a65e959aa264274291b5bc6dec1574dc5f855e733bf7`. Product-neutral MCP authorization was ported into profile v2 and its acceptance test before removal. No material was written to another repository.

Untracked `.auth-runtime/`, exports, evidence, duplicate recovered files, databases, binaries, and other ambiguous artifacts remain untouched pending their existing provenance/sensitivity review. Their presence in this hazardous working tree is not part of the committed public source and is not deletion authority.
