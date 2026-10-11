# Versioning and release policy

AUTH uses semantic versioning after the owner approves the first public release.

- PATCH: backward-compatible security, correctness, verification, or documentation changes.
- MINOR: backward-compatible capability, provider, observer, or lifecycle additions.
- MAJOR: intentional incompatible contract/runtime behavior requiring an explicit migration policy.

A release candidate must come from a clean immutable commit, pass default tests and clean-clone acceptance, contain no unresolved technical defect, preserve the canonical architecture, and have an owner-approved license/security contact. The release manifest records commit and content identity. Tags should be owner-signed and must never be created or pushed by unattended automation.

Ordinary VERIFY and REPAIR cannot advance a version. UPGRADE selects an exact immutable revision and advances lineage only after candidate acceptance and post-publication verification.
