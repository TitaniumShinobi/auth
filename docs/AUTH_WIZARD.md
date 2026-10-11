# AUTH canonical wizard contract — v1

The canonical lifecycle and ownership model is [AUTH durability architecture](AUTH_DURABILITY_ARCHITECTURE.md). This document specifies evidence evaluation and bounded operator behavior within that architecture.

AUTH owns reusable authentication/account-lifecycle obligations, deterministic evidence evaluation, regression checks, and authorized integration repair boundaries. Products own their installed authentication system, identities, data, policies, evidence collectors, UI, presentation, transports, and deployed sessions. AUTH is not a required central identity server.

## Setup, runtime independence, and maintenance

**Configure once. Verify once. Operate independently. Detect drift. Repair only when necessary.**

AUTH is a reusable, product-agnostic wizard for first-time setup, diagnosis, bounded repair, and verification. Users must not have to babysit the wizard during normal application use.

- **First setup:** inspect the product, determine applicable capabilities, configure its provider/session/callback/storage/handshake integration, verify the actual end-to-end flow, retain a reviewed known-good baseline, and hand control back to the product.
- **Normal use:** the product runs its installed authentication system and established durability contract directly. No wizard interaction, running wizard process, or recurring AUTH orchestration request may be required merely to continue functioning.
- **Regression or change:** OBSERVE → ASSESS → DECIDE → explicitly authorized bounded ACT → fresh VERIFY. Diagnose the exact broken capability, apply the smallest supported repair, preserve existing applicable behavior, update the baseline only after verification, then exit again.

Every non-pass blocker has exactly one machine-readable execution classification:

- `AUTO_REPAIR_AVAILABLE`: a registered bounded handler exists; exact authorization and post-ACT VERIFY are mandatory.
- `AGENT_INTEGRATION_REQUIRED`: an agent may change only product-specific configuration, UI, routing, deployment, or observation seams named by expected evidence.
- `EXTERNAL_ACTION_REQUIRED`: credentials, provider registration, legal/consent choice, irreversible migration approval, or another external authority is required.
- `AUTH_DEVELOPMENT_REQUIRED`: the reusable AUTH capability/contract is missing or ambiguous; product work stops rather than recreating auth architecture.

“Verify once” means establish the initial baseline; it never permits skipping verification after a change. Drift checks may run through product tests/CI or an explicit diagnostic invocation without inserting the wizard into the runtime request path.

### Wizard versus authentication runtime

The wizard and a hosted identity/provider service are distinct roles, even when code for both exists in this repository. Runtime code reused in a product is not a requirement to keep the wizard running. An explicitly declared external identity authority may still be required for login, refresh, expiry, or revocation under that product's established contract. Such a dependency must be named and verified separately; it must never be silently introduced as an AUTH wizard requirement or relabeled as independent operation.

For the agreed direct GRID ↔ VVAULT setup contract, AUTH performs setup/repair and exits. The established runtime uses the user-specific VVAULT session directly with VVAULT. Repeat repair must resolve and verify the same active instance. Acceptance requires AUTH stopped, direct instance resolution still valid, and no AUTH network request during established runtime. This is a product acceptance example, not a universal hardcoded GRID branch or proof that the current integration meets it. It does not authorize disabling identity/session, consent, device, or revocation checks.

### Completion evidence

Keep these claims separate:

1. **Repair verified:** focused evidence proves the repaired capability and preserves applicable baseline obligations.
2. **Setup accepted:** fresh end-to-end product evidence proves the configured flow, durable bindings, and required runtime independence with the wizard stopped. Retain revision/configuration references, verification results, declared runtime dependencies, and the reviewed baseline without secrets.
3. **Live acceptance:** the actual desktop/browser/service flow succeeds in its intended environment, including callback, session restoration, account isolation, and any declared downstream continuity checks.

A passing source test, reachable health endpoint, repaired error page, or successful build cannot establish the other claims. Missing runtime-independence or live evidence remains INDETERMINATE. Do not update the baseline to hide a regression. This section defines acceptance obligations; it does not claim that new executable checks or live evidence have been added.

## Executable catalog and evidence

`scripts/auth-capability-catalog.mjs` exports immutable capabilities across the declared families: sign in; sign up; identity providers; email identity; enrollment; account linking; optional cross-product enrollment; session lifecycle; relying-party authorization; device/trust; recovery; consent/policy; auth UX; auth/security email; welcome confirmation; security/failure. Each entry names required checks. Import the catalog to generate an observation checklist; do not maintain a copied list. Additional provider runtime support requires an authoritative AUTH release and explicit UPGRADE; a product agent must not implement or adapt provider code locally.

A product's read-only adapter emits JSON observations, preferably from its tests, against its exact repository revision:

```json
{
  "schemaVersion": 1,
  "productId": "example-product",
  "revision": "tested-git-commit-or-worktree-digest",
  "capabilities": {
    "signin": {
      "applicability": "TRUE",
      "implementation": "ESTABLISHED",
      "evidence": ["test-report:credential-login"],
      "checks": {
        "explicit_entry": true,
        "existing_identity_authenticated": true,
        "invalid_credentials_rejected": true
      }
    },
    "providers.password": {
      "applicability": "FALSE",
      "reason": "This product deliberately supports provider authentication only",
      "implementation": "NOT_ESTABLISHED"
    }
  }
}
```

This abbreviated example is INDETERMINATE until every remaining capability has observations or an explicit exclusion. Applicability is TRUE/FALSE/INDETERMINATE. FALSE requires a nonempty policy reason and produces verification NOT_APPLICABLE. Implementation is ESTABLISHED/NOT_ESTABLISHED/INDETERMINATE; ESTABLISHED requires evidence references. Missing or malformed check values are unknown, never successful.

For an applicable capability: a false check or NOT_ESTABLISHED implementation means FAIL; complete true checks with established implementation and evidence mean PASS; otherwise INDETERMINATE. Unknown capability IDs also make the report indeterminate. Overall PASS permits explicitly excluded capabilities; it does not force every authentication method on every product.

Evidence references and booleans are product-adapter attestations, not independently authenticated proof. AUTH evaluates those observations; it does not execute arbitrary commands embedded in JSON or claim a runtime works from filenames. Adapters must collect fresh evidence for `revision`, keep secrets out of reports, and protect baseline reports in CI. Current v1 does not cryptographically verify report provenance.

## Invocation, operators, and regression gates

From another repository, invoke the AUTH checkout explicitly:

```sh
/path/to/auth/bin/auth wizard --adapter /path/to/product/auth-observations.json --operator OBSERVE
/path/to/auth/bin/auth wizard --adapter /path/to/product/auth-observations.json --operator ASSESS
/path/to/auth/bin/auth wizard --adapter /path/to/product/auth-observations.json --operator DECIDE
/path/to/auth/bin/auth wizard --adapter /path/to/product/auth-observations.json --baseline /path/to/product/auth-baseline.json --operator VERIFY
```

Optional `--repo <path>` and `--outcome <description>` attach handoff context; `--capability <catalog-id>` identifies an ACT blocker without narrowing ordinary verification. Handoff reproduction and verification commands are argv arrays, never shell strings or permission to execute.

All four operators are read-only and return the same deterministic evidence assessment with their operator recorded. DECIDE includes per-capability actions to establish applicability, establish implementation, or verify/repair. VERIFY is the default. VERIFY and DECIDE exit 2 on FAIL or INDETERMINATE; OBSERVE/ASSESS report incomplete evidence without a failure exit. Invalid inputs exit 1.

Save a reviewed PASS report as the baseline. Always provide that baseline in change-verification CI. Any previously applicable PASS capability becoming FAIL, INDETERMINATE, missing, or NOT_APPLICABLE causes regression failure—including provider/signup removal after adding magic email. Declared counterpart and email-message records are protected too. Baselines must match the product and a supported catalog version. Catalog 1.1 accepts baselines from 1 and 1.1: prior PASS obligations remain protected, while the new welcome capabilities still require fresh applicability and evidence. A first assessment without a baseline cannot prove preservation of historical behavior.

`scripts/auth-lifecycle.mjs` exports `verifyLifecycle({capability, events})`. Supported traces: `login`, `signup`, `optional-enrollment`, `account-link`, `relying-party`, `magic-email`, `session`. Attach one as an entry's `trace` to include its result in evaluation. Events use explicit evidence: `identity.lookup {exists,id}`, `identity.create {id}`, `identity.authenticate {id}`, `authentication.denied`, `enrollment.decision {optional,accepted}`, `primary.complete`, `primary.blocked`, `account.link {existingId,linkedId}`, `relying-party.accept {identityAuthority}`, `magic.consume {outcome}`, and `session.issue|validate|refresh|logout|revoke|expire {sessionId,success}`. Magic outcomes distinguish valid, expired, replayed, and delivery-failed. Missing or unsupported evidence is indeterminate; ordering violations and contradictory identity/session outcomes fail. Session operations are independently verifiable; one event does not prove the entire session lifecycle. PASS here means the supplied scenario conforms, including an expected denial—not that authentication succeeded.

## Authorized setup and repair

Existing source-kit setup remains available for its configured targets: `bin/auth setup --repo <target> --app <configured-app> --dry-run`, then explicit `--authorize` for writes. Validation remains read-only. Setup authorization is checked before mutation.

The generic API `executeRepair(adapter, {capabilityId, authorization, handlers, observe, baseline})` in `scripts/auth-wizard.mjs` implements ACT. Authorization must be `{authorized:true, productId, revision, capabilityId}` matching the reviewed target. Applicability must be established TRUE. `handlers` is a product-owned Map from a catalog capability ID to a bounded repair function; `observe` collects the post-repair adapter evidence. Unsupported handlers fail before mutation. The handler receives only the authorized target coordinates. Verification runs after the attempt, retains baseline regression checks, and reports repair exceptions as FAIL. Observation errors throw rather than reporting success. No silent destructive repair or automatic rollback is performed.

CLI `wizard --operator ACT` fails closed unless `--act-module` identifies a non-symlink `.mjs` registry inside the declared product repository, the exact capability is registered, and `--authorize` is present. The module exports a `handlers` Map and fresh `observe` function; the same `executeRepair` contract and post-change regression verification apply. JSON evidence alone never registers executable code. AUTH does not invent a fix for a missing policy or reusable capability.

## Optional counterpart enrollment

Declare `counterparts` as an array of entries with unique other `productId` values, the same applicability/implementation/evidence fields, and checks `optional_offer`, `explicit_acceptance`, `decline_preserves_primary_access`, `existing_account_reused`. Product A account completion must stand independently from its optional offer for B. Decline preserves A; an existing B account is reused/link-verified rather than duplicated. Reciprocal offers are separate declarations in B's adapter, only where applicable. No product names are built into these checks. An applicable offer without declared counterparts is indeterminate.

## Authentication/security email boundary

Declare each email in `emails` with unique `id`, `kind`, and applicability/implementation/evidence. Authentication/security kinds require checks: `trigger_defined`, `recipient_defined`, `delivery_adapter`, `template_exists`, `delivery_result`, `duplicate_policy_defined`, `token_url_secrecy`, `expiry_policy_defined`. Policy checks require an explicit bounded policy or documented non-relevance, not a token on every notice.

Allowed kinds are `verification`, `verification_resend`, `magic_link`, `password_recovery`, `account_security_change`, `new_device_notice`, and `welcome`. Welcome is a separate post-success kind; it must not replace verification or magic-link identity proof. Newsletters and marketing messages remain outside AUTH authority and are rejected from this ledger. Applicable authentication-email capabilities without declared messages are indeterminate. Failed delivery, expiry, and replay are separate obligations; none may authenticate an identity. Magic email remains a method feeding the declared login/signup/enrollment lifecycle.

## Welcome and operator handoff

`welcome.confirmation` requires `signup_enrollment_success_confirmed` and `in_product_confirmation_visible`: signup/enrollment completion must be established before the product confirms it. Optional `welcome.email` requires `trigger_after_success`, `template_exists`, `delivery_result`, and `idempotency_policy_defined`. If applicable, declare a distinct `emails` entry with `kind: "welcome"` and checks `trigger_after_success`, `recipient_defined`, `delivery_adapter`, `template_exists`, `delivery_result`, `duplicate_policy_defined`. A TRUE `welcome.email` requires at least one TRUE welcome-message record; an explicit FALSE with policy reason requires none. Welcome messages do not inherit verification-token expiry/secrecy checks. Welcome rendering and delivery remain product-owned; welcome email does not authenticate identity, complete enrollment, or become a mandatory method for every product.

CLI reports include `blockerHandoffs` for unresolved work. Preserve the relevant handoff and evidence for its named `nextOwner`; unknown or unsupported reusable AUTH contracts require AUTH-owned resolution, while established external blockers and operator approval retain their named owners. A handoff does not authorize mutation. Product operators must not manually bypass AUTH, create alternate auth systems, mark missing evidence PASS, skip VERIFY, or modify AUTH from product work. Only a supported bounded ACT with explicit human authorization may repair, followed by fresh observation and VERIFY. See [human instructions](AUTH_OPERATOR_HUMAN.md) and [agent instructions](AUTH_OPERATOR_AGENT.md).

### Transferable blocker data

API users call `createBlockerHandoffs(report, context)` from `scripts/auth-blocker-handoff.mjs`; a genuine PASS produces an empty array. `evaluateAdapter` itself remains a pure assessment API. Context may supply `repository`, `requestedOutcome`, direct-argv `reproductionCommand` and `verificationCommand`, `registeredCapabilities` (IDs or a Map of established handlers), explicit `authorization`, and `externalBlockers` keyed by capability. External ownership requires an explicitly established blocker and reason; it is not inferred from the product name.

Each handoff carries `wizard`, `version`, `catalogVersion`, `target` (product, revision, repository where established), `requestedOutcome`, `capabilityId` (null for an unscoped task), `mdboLineage`, `operator`, `applicability`, `implementation`, `verification`, `reasonCode`, `observedEvidence`, `expectedEvidence`, `capabilityGap`, `actAvailability`, `authorizationRequired`, `authorizationState`, `verificationRequired`, `nextOwner`, both commands, `resumeCondition`, and `instruction`. Missing facts remain null, absent, or NOT_ESTABLISHED; a diagnostic label is not an invented mapped capability. `authorizationState` reports supplied context, not a grant of authority.

| NEXT OWNER | Operator action |
| --- | --- |
| AUTH DEVELOPMENT | STOP product restoration; forward the missing/unsupported reusable contract to AUTH-owned work. |
| PRODUCT INTEGRATION | Forward missing observations, declarations, failed checks, or supported-adapter integration needs to that owner; do not compensate with an ad hoc repair. |
| EXTERNAL AUTHORITY | Forward the established provider/policy/authority blocker to its responsible owner. |
| OPERATOR APPROVAL | Obtain scoped authorization; a supported handler is still required. |
| INDETERMINATE | Establish the cause and owner before attempting ACT. |

`NO_SUPPORTED_REPAIR` also requires STOP, even when the missing piece is a product integration adapter rather than an AUTH contract. A failed ACT cannot be treated as complete; verification is always required before resuming. Never execute a received command automatically or concatenate its argv into shell text.

MDBO lineage is not established for this catalog. Do not infer universal L1 mappings or MDBO certification from its results.

## Validation

Run `bin/npm20 run test:wizard`. The normal `npm test` runs wizard tests first, then the existing build/runtime suite. No provider credentials, network, product edits, or live database are needed by the wizard tests. Product integrations still need their own observed runtime evidence and supported repair adapters.

Relying-party operators: see [Safe relying-party evidence](AUTH_RELYING_PARTY_EVIDENCE.md) for explicit verification ownership, trusted authority conformance, and secret-free collection.

## Durable product integration

Use the [durable product contract](AUTH_PRODUCT_DURABILITY.md) for installed lifecycle protection: `auth setup` now installs the `.auth-kit` verifier, observation entrypoint, provenance and CI gate. Explicit establishment creates the reviewed baseline; `node .auth-kit/verify.mjs verify` automatically validates it and its check-level history. `maintain` reverifies; `advance` and `amend` require separate reviewed authorization. Raw `auth wizard --adapter` remains a diagnostic primitive, not a durable release gate. External required-status protection and live product evidence remain separate obligations.
