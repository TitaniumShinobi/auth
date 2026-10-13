# Security policy

## Supported versions

Security fixes are prepared for the current release line described in [the compatibility policy](docs/COMPATIBILITY_POLICY.md). Until the owner approves the first public tag, only the current default-branch commit is maintained.

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability-reporting interface or the private [auth Request Intake](https://docs.google.com/forms/d/e/1FAIpQLSedgkIPwkanca6XJjb1iL2dI3rOm-4bTNF3dEXaoiT9UHXwAw/viewform). Do not publish exploit details or credentials in a public issue.

Reports should include affected version/commit, impact, minimal reproduction, and suggested containment. Never include real tokens, cookies, provider secrets, identity databases, or user data.

## Security boundary

auth owns its wizard, reviewed native profiles, standards schemas, planning, transaction/recovery rules, and verification semantics. A consuming product owns the generated or aligned authentication source, configuration, persistence, tests, secrets, identities, sessions, and data. auth leaves no runtime service or control plane. Power-loss durability and irreversible/incompatible migrations are not supported guarantees.
