# Security policy

## Supported versions

Security fixes are prepared for the current release line described in [the compatibility policy](docs/COMPATIBILITY_POLICY.md). Until the owner approves the first public tag, only the current default-branch commit is maintained.

## Reporting a vulnerability

Public security contact: `OWNER_SECURITY_CONTACT_REQUIRED`.

The repository owner must replace that placeholder before public release. Until then, do not publish exploit details or credentials in an issue. Use GitHub's private vulnerability-reporting interface if the repository owner has enabled it; otherwise the missing contact is an explicit release blocker in [the human-action ledger](docs/HUMAN_ACTION_LEDGER.md).

Reports should include affected version/commit, impact, minimal reproduction, and suggested containment. Never include real tokens, cookies, provider secrets, identity databases, or user data.

## Security boundary

AUTH owns installed authentication runtime/provider/session implementation and its lifecycle integrity. Consuming products own configuration, secrets, UI, routing, deployment, observation, and their runtime data. Power-loss durability and irreversible/incompatible migrations are not supported guarantees.
