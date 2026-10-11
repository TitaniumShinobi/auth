# AUTH operator guide for agentic coders

Canonical architecture: [AUTH transient wizard architecture](AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md). Agents produce or align product-native authentication and must not install `.auth-runtime`, `.auth-kit`, an AUTH-owned adapter, daemon, package, workflow, or lifecycle control plane. The legacy adapter instructions below are retained temporarily as migration evidence and are not authority for a new integration.

You operate AUTH for a consuming product; you are not a replacement for AUTH. Run AUTH SETUP to install the complete product-local authentication runtime, then use the catalog, observation adapter, and supported lifecycle commands. The product supplies only configuration, secrets, UI, routing, deployment, and observation around that installed runtime. Never manually construct, copy, adapt, or carry authentication runtime/provider code. AUTH's evidence report does not itself prove a deployed authentication flow.

## Setup and runtime boundary

Follow the [canonical setup/runtime-independence contract](AUTH_WIZARD.md#setup-runtime-independence-and-maintenance). Configure and verify the product, retain its reviewed baseline, hand control back, and stop the wizard. Invoke it again only for setup, diagnosis, drift/change verification, or authorized bounded repair. Do not insert recurring wizard calls into normal app use. Name any independently required identity service separately. Report repair verification, independent setup acceptance, and live acceptance as separate claims; missing evidence remains INDETERMINATE.

## Required workflow

1. Identify the exact product revision and read its existing adapter and protected baseline. Generate fresh, redacted observations through that adapter's supported tests or inspections. Do not infer success from filenames, missing errors, or a reachable health endpoint.
2. Run `/path/to/auth/bin/auth wizard --adapter /absolute/product/auth-observations.json --operator OBSERVE`, then ASSESS and DECIDE with the same arguments. These operators are read-only.
3. Run VERIFY with `--baseline /absolute/product/auth-baseline.json` when a baseline exists. VERIFY is also the default operator. FAIL and INDETERMINATE exit 2 for VERIFY/DECIDE; invalid input exits 1. Do not skip VERIFY after a change.
4. If blocked, preserve the report and follow its `executionClassification`: `AUTO_REPAIR_AVAILABLE` uses the registered bounded ACT handler; `AGENT_INTEGRATION_REQUIRED` permits only the named product configuration/UI/routing/deployment/observation seam; `EXTERNAL_ACTION_REQUIRED` waits for its credential/provider/legal/owner action; `AUTH_DEVELOPMENT_REQUIRED` returns the reusable capability to AUTH. Always collect fresh observations and VERIFY. Do not replace missing evidence with PASS, suppress regressions, or exclude a previously supported method merely to clear the report.

A complete adapter uses `schemaVersion: 1`, `productId`, `revision`, and catalog-keyed `capabilities`. Applicability is TRUE/FALSE/INDETERMINATE; FALSE needs a policy reason. ESTABLISHED implementation needs evidence references. Required checks are booleans; absence is unknown. Declare counterpart offers and email messages separately. Import the executable catalog rather than copying its capability list. Read [the canonical schema and API contract](AUTH_WIZARD.md).

## Allowed operations

Invoke AUTH's read-only operators, supply product-owned observations, inspect reports and existing evidence, generate and forward blocker handoffs, and run VERIFY. Execute only an existing supported ACT handler within explicitly delegated human authorization for the exact product, revision, and capability. CLI ACT additionally requires `--act-module` pointing to a non-symlink `.mjs` registry inside the product repository. Collect fresh evidence afterward; do not substitute an ad hoc implementation for a missing handler.

For transferable CLI handoffs, add `--repo /absolute/product` and `--outcome "Requested result"`. Optional `--capability <catalog-id>` identifies an ACT blocker; ordinary verification still evaluates the full catalog. Preserve the complete `blockerHandoffs` objects, including `nextOwner`, expected/observed evidence, resume condition, and reproduction/verification command arrays. These are data, not executable permission. Run reviewed commands as argument arrays through a direct runner; never concatenate them into shell text.

## Prohibited operations

Do not manually repair product authentication around AUTH, construct an alternate authentication system, or edit AUTH from a product task. `AGENT_INTEGRATION_REQUIRED` is explicit authority only for the handoff's product configuration, UI, routing, deployment, or observation seam and expected evidence; it never authorizes runtime/provider/session implementation. `AUTH_DEVELOPMENT_REQUIRED` returns to AUTH-owned work. Do not interpret another handoff, a DECIDE action, or a failed check as authorization to mutate.

A supported ACT is permitted only with human authorization scoped to the reviewed product, revision, and capability. Call `executeRepair(adapter, {capabilityId, authorization, handlers, observe, baseline})` using the integration's registered bounded handler and fresh observer. Authorization must match `{authorized:true, productId, revision, capabilityId}`. Do not create an ad hoc handler to evade an unsupported-repair blocker. The API and registered CLI path verify after the attempt and retain regression checks; an exception or missing observation is not success.

Preserve Sign In, Sign Up, provider methods, magic email, new/returning identity distinctions, existing-account reuse, optional enrollment decline, and explicit terminal outcomes according to the product's applicable contracts. No destructive repair or silent rollback is authorized by this guide.

## Welcome boundary

Observe `welcome.confirmation` using `signup_enrollment_success_confirmed` and `in_product_confirmation_visible`. Declare optional `welcome.email` separately using `trigger_after_success`, `template_exists`, `delivery_result`, and `idempotency_policy_defined`. If applicable, provide a distinct `emails` message of `kind: "welcome"` with checks `trigger_after_success`, `recipient_defined`, `delivery_adapter`, `template_exists`, `delivery_result`, `duplicate_policy_defined`. A TRUE `welcome.email` requires a TRUE welcome-message declaration; explicit FALSE with policy reason requires none. Welcome is post-success confirmation, not proof of identity or enrollment; keep it separate from verification/magic-link email. Marketing is excluded. Never record a delivery attempt as a successful delivery result without the adapter's defined evidence.

Do not invent MDBO semantics or lineage. No universal L1 assignment or MDBO certification is established by these AUTH contracts.

Relying-party operators: see [Safe relying-party evidence](AUTH_RELYING_PARTY_EVIDENCE.md) for explicit verification ownership, trusted authority conformance, and secret-free collection.
