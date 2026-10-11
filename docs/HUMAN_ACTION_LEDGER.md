# AUTH human-action ledger

This ledger contains only decisions or operations that require the repository owner. Engineering, tests, observer generation, reversible integration, and ordinary repairs are not human actions.

| ID | Required owner action | Exact action | Blocking condition |
| --- | --- | --- | --- |
| AUTH-H1 | Choose the repository license | Select a license, add its reviewed text as `LICENSE`, and make package metadata agree. | The current `LICENSE` and package license change are ambiguous untracked/pre-existing working-tree material and are not owner authority. |
| AUTH-H2 | Decide public visibility during hardening | In GitHub: repository **Settings → General → Danger Zone → Change repository visibility**, either keep public knowingly or make private until AUTH-H1/H3 and any confirmed history remediation are complete. | This is an owner risk decision; AUTH does not change repository visibility. |
| AUTH-H3 | Provide a public security-contact method | Choose an address or external disclosure URL, replace `OWNER_SECURITY_CONTACT_REQUIRED` in `SECURITY.md`, and verify that the recipient is monitored. | No security contact may be invented by an agent. |
| AUTH-H4 | Authorize public-history remediation if audit findings are confirmed sensitive | Review the path/commit-only audit receipt without copying secret values. If sensitive material is confirmed, revoke/rotate it first, then explicitly authorize a coordinated `git filter-repo` history rewrite and force-push. | History rewriting is destructive and affects every clone; no rewrite is performed automatically. |
| AUTH-H5 | Register a product's OAuth callbacks | In each chosen provider console, register the exact callback URLs from that product's reviewed native plan. Do not register guessed URLs. | Provider-console ownership and legal consent are external actions. |
| AUTH-H6 | Supply product credentials | Put client IDs/secrets and session/token secrets into the product's approved secret manager; never commit them or paste them into reports. | Credential custody is human-owned. |
| AUTH-H7 | Complete interactive live sign-in and consent | In the owner-approved product environment, complete provider login/consent and retain only redacted evidence for callback, session, refresh, logout, and restart continuity. | Interactive identity/provider consent cannot be automated safely. |
| AUTH-H8 | Approve any authority cutover or irreversible migration | Review an explicit migration plan with backup, compatibility, rollback boundary, identity/session/data invariants, and irreversible steps; approve the exact plan before execution. | AUTH intentionally refuses irreversible migration without this authority. |
| AUTH-H9 | Approve the first public release/tag | After AUTH-H1/H3 and any AUTH-H4 remediation, review the clean-clone receipt and run `git tag -s v<approved-version> <approved-commit>` followed by an explicit push of that tag. | Release identity and signing are owner actions; AUTH does not create or push the tag. |

The ledger is complete only when each applicable row is marked by the owner outside automation. It is not permission for an agent to perform the action.
