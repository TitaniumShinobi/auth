# Contributing

Read [the canonical transient-wizard architecture](docs/AUTH_TRANSIENT_WIZARD_ARCHITECTURE.md), [security policy](SECURITY.md), and repository `RULES.md` before changing auth.

auth is licensed under the [Apache License 2.0](LICENSE). Contributors must have the right to submit their contributions and must identify third-party material and any notices or attributions that must be preserved. A `NOTICE` file is added only when such material actually requires one.

Contributions must preserve the transient architecture: auth creates or aligns product-owned native authentication, emits optional evidence, and exits. It must not install a runtime package, adapter, daemon, hidden kit, workflow, or lifecycle control plane. Product integration is limited to configuration, secrets, UI, routing, deployment, and observation; reusable security architecture belongs in reviewed auth profiles.

Before opening a pull request, use the private [auth Request Intake](https://docs.google.com/forms/d/e/1FAIpQLSedgkIPwkanca6XJjb1iL2dI3rOm-4bTNF3dEXaoiT9UHXwAw/viewform) for compatibility requests, suggestions, support questions, or proposed workflows that the canonical wizard does not yet support. Suspected vulnerabilities may also use GitHub's private vulnerability-reporting interface and must not be disclosed in a public issue.

Required checks:

```sh
npm ci
npm test
npm run test:durability
npm run build
```

Use temporary products for lifecycle tests. Never commit credentials, databases, runtime state, identity/session data, generated dependency directories, or private evidence. Changes to compatibility, receipts, lifecycle state, rollback behavior, or generated product artifacts must update canonical documentation in the same change.

Agent-origin changes must also satisfy the repository governance policy and audit requirements. Pull requests should explain compatibility impact, migration behavior, security impact, tests, and rollback.
