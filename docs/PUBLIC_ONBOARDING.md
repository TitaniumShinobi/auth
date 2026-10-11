# Public onboarding

1. Review [the architecture](AUTH_DURABILITY_ARCHITECTURE.md), [support boundary](../SUPPORT.md), and [security policy](../SECURITY.md).
2. Run `bin/auth setup --repo <product> --app <id> --authorize`. AUTH installs the complete product-local runtime and durability kit.
3. Fill only product configuration, secret references, UI, routing, deployment, and `.auth-kit/observer-input.json` observation evidence. Never copy or implement runtime/provider/session code.
4. Run `bin/auth observer scaffold --repo <product> --app <id> --authorize` only to migrate a legacy unestablished placeholder; new SETUP installations are already scaffolded.
5. Use OBSERVE, ASSESS, and DECIDE. Follow each handoff's `executionClassification`:
   - `AUTO_REPAIR_AVAILABLE`: authorize and use the registered bounded ACT handler.
   - `AGENT_INTEGRATION_REQUIRED`: change only the named product seam and provide expected evidence.
   - `EXTERNAL_ACTION_REQUIRED`: obtain credentials, registration, consent, legal choice, or owner approval.
   - `AUTH_DEVELOPMENT_REQUIRED`: stop product work and add the reusable capability to AUTH.
6. Collect fresh observations and VERIFY after every change.
7. ESTABLISH only after locked install, Prisma generation, build, startup/readiness, route acceptance, and product evidence pass.

Normal runtime operation uses the installed product-local system and never requires the AUTH source checkout.
