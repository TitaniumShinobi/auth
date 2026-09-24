# Canonical AUTH test-source recovery

Starting candidate: `07fd583c10d0547b1da9f19d046923aa4381709c`.

All 18 missing package-referenced suites were restored exactly before testing. The shell launchers come from `bf60e5e`; source suites and their coherent operator dependency closure come from tree `85021aaf55e9992e5adaa1fe777f4712d4e389b4`. Four recovered TypeScript suites emit byte-identically to committed `c963a19` artifacts. The machine-readable provenance ledger records every recovered source blob, original SHA-256, final SHA-256, necessity, impact, and dependency edges.

## Review boundary

The operator closure consists of catalog, lifecycle, evidence ownership/profiles, conformance binding/generator/runner/child, wizard, blocker handoff, bounded repair, CLI/runtime-acceptance, and setup template. These are operator functions, not HTTP-runtime imports; they are not described as harmless test fixtures. CLI setup writes require explicit authorization; generic CLI ACT cannot invent repair handlers; bounded repair requires scoped authorization and a supplied host adapter. No operator mutation was invoked against a product. The historical older setup CLI is not substituted for the coherent recovered wizard CLI.

Two runtime prerequisites are recorded separately: the existing enrollment host's dynamic module, byte-identical to committed `bf60e5e`, and the snapshot's example configuration named by the existing default config loader. Restoring the latter permits the already-declared default example profile to load when no explicit config is supplied. Production registration files and all existing src runtime files remain byte-identical to `07fd583` and the frozen Milestone implementation. No production process was reloaded.

## Evidence-backed corrections

The first exact-source run exposed two obsolete Chatty localhost assertions and three startup failures caused by the missing default config. `3fe8da9` explicitly changed the registration to production HTTPS; only those two assertions were aligned, keeping injection rejection and adding rejection of the old localhost callback. The default config was recovered without rewriting startup benchmarks.

The documented resource command was absent from package.json. Its exact older snapshot runner and three test dependencies were recovered. Its list then gained the already-committed `resourceRuntime` and `vvaultOwnerAdmission` suites introduced by frozen `9187d73`. No security tests were removed or fabricated; no runtime behavior was changed to accommodate a test.

## Verification

- `npm test`: exit 0; wizard 108 plus compiled runtime 51 = 159 PASS.
- `npm run test:conformance`: 3 PASS.
- `npm run test:assertion-repair`: 20 PASS (overlaps npm test).
- `npm run test:enrollment`: 22 PASS (overlaps npm test).
- `npm run test:startup`: 3 PASS (overlaps npm test).
- `npm run test:resource-authorization`: 80 compiled plus 13 source = 93 PASS.
- `npm run build`: exit 0.
- Single run of all 30 tracked suite files: 237 PASS, zero failures/skips. This is the unduplicated total; supplemental counts must not be summed into it.

All 18 recovered suites ran, as did both cross-language checks against frozen VVAULT `ed1959990901da092a83638b61d9a5943b13b86c`. Python ran with -B. Test identities, keys, stores and listeners were disposable; no live credentials or product accounts were used. Source verification is not production acceptance.

The restored Node/npm launchers require the existing shared runtime helper through `VVAULT_NODE_RUNTIME_HELPER`; the isolated checkout sets that explicitly. Cross-language checks require `AUTH_VVAULT_SOURCE_TEST_ROOT` and `AUTH_VVAULT_TEST_PYTHON`. These were set to the existing frozen source and its Python interpreter. Dependencies were temporarily linked to the existing AUTH installation; this is not a claim of a clean npm-ci installation.

## Release boundary

This source recovery supersedes earlier blocked AUTH test/package candidate evidence only through the accompanying final manifest. Rollback source reference is `8ef31a3fe902bad241cbbe8c361b1eb46a9d25a7`; no database rollback is implied. Credential rotation/re-homing remains a hard production gate, followed by deployment provenance, explicit activation approval and controlled canary work. No deployment, production mutation, VVAULT/GRID edits, migration, canary or Milestone 2 was performed.
