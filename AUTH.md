# auth

## Core and authority

auth is LIFE Technology's reusable, transient authentication-engineering wizard. It establishes, diagnoses, repairs, and verifies product-owned authentication. It is one of Start, auth, AUTO, drbt, and chronos.

**The objective is reliable authentication that survives unrelated product development.** A repair is not durably complete until the affected behavior is protected by executable product-owned tests in the product's normal development path. The wizard exits; the product continues operating independently.

This is auth's authoritative living **development rubric**: requirements, module status, acceptance, and next work. Detailed architecture remains in [the transient architecture contract](docs/AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md). This rubric does not silently change executable formats or declare planned behavior shipped. A contradiction between a requirement and implementation is a recorded gap, not permission to fabricate verification.

Evidence reference: canonical commit `b220df0` and its inspected prerequisites `4dd1015`, `5c66656`, `cb00aca`, and `d15c18e`. Review date: 2026-10-19. This documentation pass inspected source and test definitions; it did not rerun runtime tests or establish new product acceptance.

### Operating ownership

| Owner | Responsibility |
|---|---|
| Human handler | authorizes scope, product policy, secrets/provider actions, irreversible changes, and release |
| Agent | Holds the original request; retrieves evidence; prepares exact bounded proposals; interprets results |
| auth | Validates supported plans, executes authorized changes through its handlers, verifies, and emits evidence |
| Consuming product | Owns authentication implementation, UI, persistence, configuration, tests, ordinary build/CI, and deployment |
| External authority | Owns provider, delivery, platform, or resource behavior beyond auth's execution boundary |

An agent's direct edit is not an auth-executed repair. Unsupported seams must be identified explicitly. No UI, identity registry, datasource, provider configuration, or session architecture is invented to evade a missing contract.

auth must not leave an installed `.auth-kit`, `.auth-runtime`, auth daemon, copied auth package, or required wizard network service. Product-owned source, tests, standards, and ordinary CI are legitimate output. Operator receipts are evidence, not a resident control plane. An existing product/provider authentication service is distinct from the wizard; transient operation does not imply removing a product's legitimate identity provider.

## Evidence and progress rules

Statuses used here:

| Status | Meaning |
|---|---|
| IMPLEMENTED | Executable source exists; not a claim of current acceptance |
| PARTIAL | Some required behavior exists; named obligations remain |
| ACTIVE | Selected unfinished development module |
| BLOCKED | A named prerequisite prevents a particular operation |
| NOT_VERIFIED | Required execution/evidence has not been established |
| COMPLETE | All module acceptance requirements have retained, revision-bound proof and review |

Observation is not authorization. Source presence is not execution. Unit tests are not live-provider acceptance. Health is not login success. A passing selected scope is not whole-product acceptance. Historical receipts retain their original scope and revision; never relabel them current.

No module is newly certified COMPLETE by this document. Existing accepted contracts must be preserved, not reopened without regression evidence. Rechecking a changed boundary is not license to redesign it.

### Current checkout discrepancy

At inspection, the mixed checkout differs materially from canonical `b220df0`: existing-repair, product-test, and assurance modules/tests are staged for deletion, and CLI/package/native-wizard wiring differs. Canonical code references below describe the committed tree, not those unreviewed local bytes. Preserve that work and index. Execute future canonical verification from a separate pinned source; do not reset this checkout or treat a shortened local test command as equivalent coverage.

## Executable architecture

Native lifecycle:

```text
DISCOVER → CLASSIFY → PLAN → authorized APPLY → VERIFY → RECEIPT → EXIT
```

Capability lifecycle:

```text
OBSERVE → ASSESS → DECIDE → authorized ACT → fresh VERIFY
```

| Component | Canonical implementation | Actual boundary |
|---|---|---|
| CLI | `bin/auth`, `scripts/auth-cli.mjs` | Subcommand-specific flags; explicit mutation authorization; separate release VERIFY |
| Native discovery/plans/transactions | `scripts/auth-native-wizard.mjs` | Bounded discovery; exact-file plans; target-bound receipts; controlled-process recovery |
| Existing-file repair | `scripts/auth-existing-repair.mjs` | Reviewed single-file replacement plus evidence hashes, bounded command, fresh observer, in-process rollback |
| Product behavioral runner | `scripts/auth-product-test.mjs` | Product-owned command runner; propagates exit status, timeout and interruption |
| Capability evaluation | `scripts/auth-capability-catalog.mjs`, `scripts/auth-wizard.mjs` | Declared applicability/implementation/checks, regression comparison, authorized handler registry |
| Scope and authority evidence | `scripts/auth-verification-profiles.mjs`, `scripts/auth-evidence-ownership.mjs`, `scripts/auth-conformance-binding.mjs` | Scope-specific aggregation and evidence binding, not automatic live collection |
| Runtime acceptance | `scripts/auth-assurance.mjs` | Separately pinned, fresh product/revision-bound test evidence |
| Product-native profile | `profiles/typescript-node-express-prisma/` | Generated product implementation; do not copy historical mixed `src/` as a generic runtime |

See [native CLI](docs/AUTH_NATIVE_CLI.md), [profile contract](docs/AUTH_TYPESCRIPT_NATIVE_PROFILE.md), [existing alignment](docs/AUTH_EXISTING_ALIGNMENT.md), and canonical `docs/AUTH_ASSURANCE_BOUNDARIES.md` at `b220df0` (absent in the current mixed checkout).

## Capability inventory and applicability

The executable catalog is authoritative for exact CapabilityIDs/check names. Do not infer applicability from a product name or make every authentication method mandatory.

Covered requirement families include sign-in, sign-up, providers/callbacks, email identity, enrollment, linking, optional cross-product enrollment, sessions, relying-party authorization, device/trust, recovery, consent/policy, UX, authentication emails, welcome confirmation, and security/failure behavior. Catalog coverage does not imply a working repair handler or product implementation for every check.

The native profile retains/generalizes credentials; Oauth/OIDC; authorization code/S256 PKCE; state/nonce/callback checks; magic email; cookies/sessions; access/refresh rotation; replay/revocation/logout; persistence; native-client authorization; and protected-resource MCP authorization. See [capability dispositions](docs/AUTH_CAPABILITY_DISPOSITION.md). OS focus, actual provider registrations, email delivery, and user-visible enrollment remain integration/acceptance obligations.

Preserve executable semantics:

- Applicability: `TRUE`, `FALSE`, `INDETERMINATE`; false requires an explicit reason.
- Implementation: `ESTABLISHED`, `NOT_ESTABLISHED`, `INDETERMINATE`.
- Verification: `PASS`, `FAIL`, `INDETERMINATE`, `NOT_APPLICABLE`.
- Profile selection does not erase full results or change ownership.
- Required missing proof cannot become PASS. An established obligation cannot be retired casually through an adapter change.

Welcome email is optional onboarding/account-lifecycle communication; verification and magic login email are different contracts. Marketing newsletters are outside auth authority.

## MDBO governance

Required governing reference: [auto/MDBO.md](../auto/MDBO.md). Universal definitions belong there; this rubric describes auth specialization.

auth uses deterministic OBSERVE/ASSESS/DECIDE/ACT/VERIFY operators. This establishes executable operator behavior, **not verified complete MDBO mapping**.

The supplied GRID rubric names seven universal L1 Skill Classes: Entities & Artifacts; Structure & Relationships; Specification & Rules; Interfaces & Exchange; Execution & Behavior; Condition & Integrity; Lifecycle & Transitions. auth-specific specialization belongs below that foundation. Exact auth capability-to-MDBO lineage and shared realization registration are NOT_VERIFIED in this review; do not invent lineage from filenames or claim a shared engine already exists.

Future shared verification governance must define execution/evidence/result/completion contracts once; each wizard supplies domain-specific tests and existing test tools. This document does not implement that framework or govern another repository by fiat.

## Development module ledger

Each row gives source evidence, dependencies, and the proof required for completion. Status applies to the whole module, not every individual function.

| Module | Status / evidence | Dependencies and Definition of Done |
|---|---|---|
| M1 — Transient setup and native recovery | IMPLEMENTED; native wizard, `scripts/auth-native-wizard.test.mjs` | Exact reviewed plan; scope/path/provenance checks; generated product builds and runs without auth; interruption/drift tests preserve unrelated bytes; receipt proves actual scope. No power-loss guarantee. Fresh acceptance NOT_VERIFIED here. |
| M2 — Existing-product assessment/alignment | PARTIAL; `assessNativeTarget`, `planNativeAlignment` | M1; correct role/runtime/entrypoint; static findings never become runtime PASS; generated tests/workflow run with real product dependencies; collision and preservation tests pass. Existing arbitrary build integration remains missing. |
| M3 — Bounded existing repair | IMPLEMENTED with limits; `createExistingRepair`, `executeRepair`, `scripts/auth-existing-repair.test.mjs` | Reviewed source/test preimages; authorized exact scope; failing behavior before, passing behavior after; fresh check-bound observer; no sibling proof fabricated; rollback and repeat invocation tested. Single-file/in-process recovery only; fresh acceptance NOT_VERIFIED here. |
| M4 — Durable repair completion / RPTVL | **ACTIVE — scoped lane implemented; product acceptance NOT_VERIFIED** | M2/M3/M5; mandatory post-write lane, test-to-check coverage, product normal-build connection, disposable regression rejection, truthful visible receipt. All required lanes must pass before VERIFIED. |
| M5 — Evidence/history/release verification | PARTIAL; evaluator, profiles, assurance and their tests | Trusted product/revision-bound runtime evidence; pinned applicable authority evidence; pinned historical obligations; altered/missing/stale evidence rejected. Caller must currently supply/invoke the gate; initial policy review and external enforcement are not automatic. |
| M6 — Native profile security/lifecycle | IMPLEMENTED; profile source/tests and profile contract | M1/M4; generated-product build plus real isolated session/provider/refresh/replay/logout/MCP tests; negative security and persistence checks; deployment-specific acceptance separately proven. No new runtime certification in this pass. |
| M7 — Compatibility/migration | IMPLEMENTED with bounded support; native migrate/recover, migration tests | M1; explicit immutable target, preimage verification, preserved old/new receipt pair, controlled interruption recovery, incompatible schema changes refused. Arbitrary product migrations/power-loss durability unsupported. |
| M8 — Shared MDBO verification integration | PLANNED / NOT_VERIFIED | Reviewed shared semantic contract and actual realization registry; cross-wizard conformance fixtures; no duplicate engines or fabricated lineage. Not permission to edit other wizards. |

## RPTVL — mandatory completion requirement

**Regression–Penetration Testing Verification Lane** is the required post-write completion contract. The M4 candidate implements automatic scoped orchestration for supported writes; it still requires reviewed product tests and integration. This is not universal test generation or live-product certification. Native receipt verification alone proves source integrity, not this lane.

Trigger: every authorized wizard write pass, including supported apply, repair, alignment, or migration. In the M4 candidate, the coordinator runs before durable completion is reported; missing execution specifications remain NOT_VERIFIED. A no-change repair still rechecks relevant behavior. Pure diagnosis is read-only and does not imply a successful write lane.

| Lane | Required proof in its declared scope |
|---|---|
| Build & Structural | Correct toolchain; syntax/compilation/static checks; rebuilt artifacts rather than stale outputs |
| Functional Regression | Previously accepted applicable behaviors still work; existing suites preserved |
| Behavioral Penetration | Adversarial valid inputs, edge cases, incomplete outcomes, and negative operations challenged |
| Security Penetration | Relevant bypass, identity/account isolation, privilege, token/state/replay boundaries reject misuse |
| State & Recovery | Valid transitions; cancellation, expiry, interruption, persistence, restart and recovery as applicable |
| Integration | Real declared component interfaces/dependencies work together, with fixture/live scope explicit |
| End-to-End Acceptance | Intended user-visible workflow demonstrated on the identified candidate/runtime/platform |

“Security Penetration” names a scoped lane, not certification of a comprehensive external penetration test. Use disposable identities, isolated data and controlled fault injection. No real-user credential replay, secret export, production mutation, or expansion beyond authorization.

### Deterministic selection and results

Before writes, bind required lanes/checks to the request, applicable capabilities, changed boundary, accepted obligations, and environment. Mandatory requirements cannot be removed after a failure. Exclusions require a recorded, reviewed reason; non-applicability never means a test passed.

Lane reporting uses `PASS`, `FAIL`, `PARTIAL`, `BLOCKED`, or `NOT_VERIFIED`. These are orchestration dispositions, not replacements for existing capability enums. Unrun or unsupported checks are NOT_VERIFIED; unavailable prerequisites are BLOCKED with owner/resume condition; incomplete coverage is PARTIAL. A mandatory non-PASS prevents VERIFIED.

`VERIFIED` means every mandatory check for the declared scope passed with valid evidence. Source-only verification cannot claim live acceptance. Successful unit tests cannot satisfy browser/OS behavior. A failure permits repair only within the original authorized scope; bounded retries must terminate with an honest unresolved result rather than broaden permissions.

### Required receipt content (specification, not a new implemented schema)

Reuse existing evidence formats where sufficient. Any necessary extension requires review and compatibility tests. The resulting report must identify:

- Product, original requested outcome, scope, wizard revision/profile and candidate revision.
- authorization reference, changed paths and pre/post digests, preserved state and rollback outcome.
- Required lanes/check IDs, applicability, prior obligations, and coverage mapping.
- Exact commands, environment/toolchain identity, fixture/live classification, timestamps and exit results.
- Sanitized evidence references/digests, failures with reproduction steps, unresolved owner/resume condition.
- Product-native normal-build command and proof that it runs the relevant regression suite after auth exits.
- Aggregate result and explicit unverified product-level acceptance.

Never include tokens, passwords, private keys, cookies, identity data, or plaintext magic links. Visible per-lane results must be produced by execution, not assembled into a cosmetic all-green report.

## Implementation gaps and next module

**Next: M4, durable repair completion using existing repair and test machinery.** This closes the missing connection directly; another authentication architecture or PR approval campaign does not.

Smallest reviewed implementation sequence:

1. Define the execution/report extension binding a repair to required lanes and concrete test-to-check coverage. Preserve existing evaluator/evidence formats.
2. Connect the existing behavioral runner to reviewed ordinary build/test entrypoints and CI dependency setup. Do not overwrite arbitrary scripts/workflows; inspect and plan exact changes.
3. Make supported write completion execute the required lane and refuse durable VERIFIED when coverage or product-native integration is absent.
4. Demonstrate disposable regression rejection: working behavior broken again must fail the normal product command; unrelated edits must remain acceptable. Prove history/applicability degradation cannot manufacture green.
5. Review evidence independently; retain exact commands/diffs/results; request live acceptance only for the remaining live boundary.

Required focused tests: success; each mandatory lane failing; unsupported/unrun lane; timeout; stale/mismatched evidence; wrong coverage mapping; build/CI collision; missing dependency; unchanged/failed repair; existing-test preservation; regression mutation rejected; unrelated changes tolerated; wizard unavailable during product tests/runtime. Test interruption recovery within the supported transaction guarantee. Broader transaction reuse is a separately bounded change if a repair requires multiple files; do not silently claim it for the current single-file handler.

Historical gate enforcement remains optional unless the caller supplies the required pinned baseline and invokes release verification. Generated behavioral CI alone is not that release gate. A writer controlling tests and trust anchors can replace both: external required checks/pin custody are an explicit distribution boundary, not a fabricated prerequisite for local login repair.

## Acceptance and module advancement

Before implementation: state the original goal, evidence, exact target files, exclusions, required tests and approval scope. Use the smallest coherent change. Preserve unrelated work/index and existing product behavior. Do not repair by deleting tests or changing applicability to hide failures.

Advance a module only with a retained receipt tied to the tested committed/candidate bytes, passing required scoped checks, reviewed diff, and explicit remaining live obligations. Ordinary VERIFY must not advance a baseline or silently approve new policy. Record dated status updates with evidence references; keep historical receipts historical.

Product repair acceptance:

```text
Defect reproduced → auth applies authorized repair → behavior passes
→ normal product build runs regression tests → disposable regression fails
→ unrelated development still passes → auth exits → product operates
```

Release acceptance adds applicable live-provider/platform tests and independently governed evidence pins. It is not implied by package build, source receipt, documentation, or this rubric.

## Verification and maintenance entrypoints

Run from a clean pinned auth source, not the mixed checkout described above:

```sh
bin/npm20 run test:native
bin/npm20 run test:standards
bin/npm20 run test:wizard
bin/npm20 run build
git diff --check
```

These are canonical package scripts at the reviewed revision. auth's own `build` checks wizard syntax; it is not a generated product compilation or live E2E test. Select focused tests first and additional relevant profile/integration acceptance explicitly. Do not quote prior counts as fresh results.

Further contracts: [acceptance evidence](docs/AUTH_ACCEPTANCE_EVIDENCE.md), [public production rubric](docs/AUTH_PUBLIC_PRODUCTION_RUBRIC.md), [compatibility](docs/COMPATIBILITY_POLICY.md), [migration](docs/MIGRATION_POLICY.md), [versioning](docs/VERSIONING_RELEASE_POLICY.md), [security](SECURITY.md), [threat-model index](docs/THREAT_MODEL_INDEX.md), and [human actions](docs/HUMAN_ACTION_LEDGER.md).

The supplied GRID/AUTO/CLEANHOUSE rubrics informed structure and evidence discipline only. They are not auth implementations, fresh product acceptance, or authority to change those repositories. Existing readiness documents contain historical claims; revalidate their scope/revision before release. Framework implementation begins only after review of this rubric's architecture and requirements.

## M4 candidate implementation receipt

The isolated candidate adds the [executable verification lane](docs/AUTH_VERIFICATION_LANE.md), automatic supported-operation reports, reviewed dependency setup and npm build integration planning. Canonical promotion and live-product acceptance are not implied. Non-npm build integration remains explicit; full shared MDBO realization registration remains M8. See the retained test receipt before advancing this module.
