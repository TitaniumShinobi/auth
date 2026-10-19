# Existing-auth assessment and alignment

`auth native assess --repo <product>` is read-only. It inspects at most 200 authentication-relevant TypeScript, JavaScript, Prisma, JSON, and Python files and at most 2 MiB of source. It reports product stack, bounded evidence paths, prohibited legacy artifacts, and each profile capability as `OBSERVED_NOT_VERIFIED` or `NOT_OBSERVED`. Static observation is never reported as conformance or runtime success.

The deterministic classifications are `COMPATIBLE` when all profile signals are observed in a supported TypeScript/Node or Python/Flask target, `DEGRADED` when signals are missing, `MIGRATION_REQUIRED` for a non-profile stack, and `NONCONFORMANT` for prohibited persistent auth artifacts. Compatible and degraded existing implementations return `AGENT_INTEGRATION_REQUIRED`: the product agent may supply the named evidence or make reviewed product-native changes, but must not recreate authentication architecture or overwrite source heuristically.

`auth native align-plan --repo <product> --product <id> --receipt <path> --plan <path>` creates an exact plan containing product-owned `auth-standards.json`, `test/auth-contract.test.mjs`, and `test/auth-entrypoint.test.mjs`. Applying it uses the same crash-recoverable transaction as greenfield creation. Existing authentication source, configuration, secrets, persistence, identities, sessions, and data are byte-preserved. Existing files at any alignment destination stop planning for review.

The generated test requires an operator-supplied `AUTH_BASE_URL` and observes health, OAuth metadata, issuer origin, and S256 PKCE declaration. Passing that test is one evidence input, not complete conformance. Missing reusable AUTH capability remains `AUTH_DEVELOPMENT_REQUIRED`; credentials, provider registration, consent, and irreversible migration remain external or owner actions.

Release evidence and product-owned CI: [AUTH assurance boundaries](AUTH_ASSURANCE_BOUNDARIES.md).

Alignment also creates `test/auth-entrypoint.test.mjs`, an ordinary product-owned Node test. It pins the reviewed product identity, authentication role/runtime and entrypoint declaration; it rejects a missing, directory, or redirected entrypoint. It tolerates implementation edits and unrelated product changes. It locates the product relative to its own file, so invocation does not depend on the working directory. Run it with `node --test test/auth-entrypoint.test.mjs`, or include it in the product's existing Node test discovery. No AUTH checkout, daemon or network access is needed.

This is structural regression protection, not proof of authentication behavior. Existing-product alignment does not infer arbitrary build commands; the M4 build-plan and reviewed dependency runner provide explicit integration described below. Product runtime tests and external release enforcement remain required. A deliberate change to the established entrypoint/role needs a reviewed change to the product contract and its test together; an actor replacing both is outside this local test's protection.

New alignment plans also create a product-owned GitHub Actions workflow at `.github/workflows/authentication-regression.yml`. It runs both generated product tests on pushes and pull requests, without downloading or invoking AUTH. Existing workflows at that path stop planning for review; existing package scripts are not overwritten. Missing runtime acceptance remains a failing test, not a green smoke-only release claim. A product must provide its real behavioral tests and isolated runtime configuration before this alignment check can pass. Other CI providers and automatic existing-package-script modification are not supported by this change. Required-status protection remains an external operator responsibility.

New native TypeScript setups run Prisma generation and compilation automatically before `npm test`, preventing stale `dist` from masking source regressions. Their generated CI installs locked dependencies and runs this same command. The existing isolated runtime suite covers real credential/session, OAuth, refresh/replay and provider/magic flows; it now also asserts returning-user identity reuse, code replay rejection, and protected-access rejection after logout. These fixtures do not prove live provider configuration.

## Connect an existing behavioral command

Pass `--behavior-spec <reviewed.json> --behavior-sha256 <sha256>` to `native align-plan`. The JSON contains `argv` (literal executable and arguments), `timeoutMs` (100–600000), and optionally `executableEnvironment` (the name of an explicit local interpreter override). No shell interpolation or credentials belong in this file. Example: `{"argv":["python3","-m","unittest","tests.test_auth_api_validation"],"timeoutMs":60000}`.

Alignment creates product-owned `test/auth-behavior.mjs`; both the local `node test/auth-behavior.mjs` command and generated GitHub workflow run it. The workflow does not provision arbitrary product dependencies: the reviewed product command/environment must supply them. Existing destination collisions still require review. Unlike metadata smoke, its result is the actual supplied suite's exit code. Helper tests do not become live OAuth evidence. No AUTH checkout, service, network call, or kit is needed to run the generated test. An existing local build command is not silently overwritten.

## Reviewed existing-file repair

Use existing wizard ACT with `--repo`, `--adapter`, `--capability`, `--authorize`, `--repair-spec`, and `--repair-sha256`. The approved digest binds the entire external specification. It selects AUTH's built-in bounded handler through the same `executeRepair` registry; no product-local executable AUTH module is installed.

The specification is `schemaVersion:1`, `productId`, `revision`, `capabilityId`, `file` (relative regular file), `beforeSha256`, `afterSha256`, `replacement` (reviewed UTF-8 bytes), `checks` (only catalog checks actually proven), `evidenceFiles` (path/hash objects for every relevant test input), and `command` (`executable` absolute path, literal `args`, `timeoutMs` up to 120000, `maxOutputBytes` up to 4194304). This is explicit reviewed executable authority, not an untrusted/sandboxed command format. Never include secrets.

The handler checks scope and source/test preimages, atomically replaces one file, runs the reviewed test and a fresh observer, and restores the original bytes on an in-process failure unless concurrent source drift makes rollback unsafe. Already-correct files are re-tested without rewriting. Unrelated files and the Git index are never edited by the handler. Trusted test commands must themselves use isolated data and avoid mutating unrelated state. No automatic multi-file repair or kill/power-loss recovery is claimed.

`boundedRepair` reports the specific repair and behavioral outcome; the existing wizard retains INDETERMINATE for unmapped sibling checks and requires full fresh proof before whole-capability PASS. Its resulting revision fingerprints the scoped source/evidence, not an exhaustive product inventory. Native receipt VERIFY remains source-integrity only. Alignment artifact reconstruction beyond existing native support remains separate; do not use greenfield repair to restore customized existing-product tests.

## Post-write verification

See the [M4 execution contract](AUTH_VERIFICATION_LANE.md) for automatic scoped lane results, legacy NOT_VERIFIED behavior, reviewed normal-build/CI integration, and the distinction between transaction completion and durable acceptance. Source receipts and historical release evidence retain their existing meaning.
