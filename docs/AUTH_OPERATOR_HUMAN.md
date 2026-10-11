# AUTH operator guide for humans

AUTH SETUP installs the complete product-local authentication runtime, and AUTH evaluates its authentication and account-lifecycle evidence. The product supplies configuration, secrets, UI, routing, deployment, and observation around that installed runtime. Do not ask a product agent to construct, copy, adapt, or carry authentication runtime/provider code. Running AUTH does not by itself establish that the deployed product works.

## Setup and runtime boundary

Follow the [canonical setup/runtime-independence contract](AUTH_WIZARD.md#setup-runtime-independence-and-maintenance). Configure and verify the product, retain its reviewed baseline, hand control back, and stop the wizard. Invoke it again only for setup, diagnosis, drift/change verification, or authorized bounded repair. Do not insert recurring wizard calls into normal app use. Name any independently required identity service separately. Report repair verification, independent setup acceptance, and live acceptance as separate claims; missing evidence remains INDETERMINATE.

## When to use AUTH

Use the wizard to assess an authentication integration, review a lifecycle change, detect regressions, or prepare a scoped blocker handoff. Do not use it to design product branding, send marketing email, replace product policy, or certify deployment from observation files alone. Use the existing supported setup tools only when their target/configuration contract fits the product.

## Assess a product

Obtain a product-owned JSON observation file for the exact revision being reviewed. It must identify `schemaVersion: 1`, `productId`, `revision`, and observations for the executable capability catalog. Each applicable capability needs implementation evidence and every required check. Exclude a capability only for a documented product-policy reason. See [the adapter contract](AUTH_WIZARD.md) for the complete shape.

Run AUTH from its checkout, using absolute paths to the product observations:

```sh
/path/to/auth/bin/auth wizard --adapter /path/to/product/auth-observations.json --operator OBSERVE
/path/to/auth/bin/auth wizard --adapter /path/to/product/auth-observations.json --operator ASSESS
/path/to/auth/bin/auth wizard --adapter /path/to/product/auth-observations.json --operator DECIDE
/path/to/auth/bin/auth wizard --adapter /path/to/product/auth-observations.json --baseline /path/to/product/auth-baseline.json --operator VERIFY
```

Optional `--repo /absolute/product` and `--outcome "Confirm signup completion"` attach repository and requested-outcome metadata to handoffs. Optional `--capability welcome.confirmation` identifies a catalog capability for an ACT blocker; it does not enable a repair or limit ordinary verification to that capability.

These commands are read-only. VERIFY is the default; VERIFY and DECIDE exit 2 when the result is FAIL or INDETERMINATE. Invalid inputs exit 1. A first assessment can omit the baseline, but cannot then prove preservation of past behavior. Keep a reviewed PASS report as the baseline and supply it for subsequent changes.

PASS means the supplied evidence satisfies the applicable checks. FAIL means a failed check, missing implementation, or regression. INDETERMINATE means evidence or applicability remains unresolved. NOT_APPLICABLE is a per-capability result backed by an explicit exclusion. Never turn missing evidence into PASS or drop a previous capability to make a report green. Reports attest adapter observations; AUTH does not cryptographically prove their origin or run the product from JSON.

## Completion criteria

Complete the assessment only when fresh observations for the reviewed revision produce VERIFY PASS, every applicable implementation is ESTABLISHED with required evidence, every exclusion has a policy reason, no unresolved blockers remain, and baseline PASS obligations are preserved. Retain the report and its evidence references. This is completion of AUTH evidence verification, not independent deployment proof; the product still needs its runtime acceptance evidence.

## Resolve a blocker

Read the report's `blockerHandoffs`. Route the relevant handoff to its `nextOwner`; unknown or unsupported AUTH contracts belong with AUTH's maintainer. Retain the product revision, capability, failure, and evidence. Transfer the complete handoff object: it retains evidence, expected checks, owner, resume condition, and reproduction/verification commands. Commands are argument arrays, not shell text; use a direct argv-capable runner after review, never join them into a shell string. A handoff is a request for scoped resolution, not permission to change files. Do not instruct a product agent to replace AUTH, build an alternate authentication system, or manually patch authentication around the verifier.

The machine decision is `executionClassification`: `AUTO_REPAIR_AVAILABLE`, `AGENT_INTEGRATION_REQUIRED`, `EXTERNAL_ACTION_REQUIRED`, or `AUTH_DEVELOPMENT_REQUIRED`. Agent integration is limited to product configuration, UI, routing, deployment, and observation evidence. Registered ACT remains the preferred automatic path. Every path ends in fresh observation and VERIFY.

Authorize an ACT repair only after reviewing its exact product, revision, capability, and supported handler. The `executeRepair` API requires explicit scoped authorization and a registered product repair handler; it observes fresh evidence and runs VERIFY after the attempt. CLI ACT additionally requires a registered in-product module, exact capability, repository boundary, and `--authorize`; otherwise it fails closed. An unsupported reusable AUTH capability returns `AUTH_DEVELOPMENT_REQUIRED`.

## Successful signup and welcome messages

Applicable `welcome.confirmation` requires evidence that signup/enrollment succeeded and that the product shows an in-product confirmation. A welcome message cannot substitute for successful enrollment.

`welcome.email` is optional: declare it applicable only when the product offers that behavior. Verify a post-success trigger, template, delivery result, and idempotency policy. Declare the message separately in `emails` with `kind: "welcome"` and checks `trigger_after_success`, `recipient_defined`, `delivery_adapter`, `template_exists`, `delivery_result`, `duplicate_policy_defined`. A TRUE welcome-email capability needs a TRUE welcome-message record; an explicit FALSE with policy reason needs none. Verification and magic-link messages remain distinct. Marketing and newsletters are outside this contract. Product code owns rendering and delivery. See [AUTH_WIZARD.md](AUTH_WIZARD.md) for check names and message fields.

The catalog is an executable AUTH contract. Its MDBO lineage has not been established; do not assign universal L1 roots or claim MDBO certification from a wizard report.

Relying-party operators: see [Safe relying-party evidence](AUTH_RELYING_PARTY_EVIDENCE.md) for explicit verification ownership, trusted authority conformance, and secret-free collection.
