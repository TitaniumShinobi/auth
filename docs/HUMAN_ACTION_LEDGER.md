# AUTH human-action ledger

This ledger contains only decisions or operations that require the repository owner. Engineering, tests, observer generation, reversible integration, and ordinary repairs are not human actions.

| ID | Required owner action | Exact action | Blocking condition |
| --- | --- | --- | --- |
| AUTH-H1 | **COMPLETE — Apache License 2.0 selected** | The official unmodified Apache-2.0 text is committed as `LICENSE`; package metadata declares `Apache-2.0`; `private: true` remains. | Completed by explicit owner decision. No `NOTICE` is required unless future material introduces a notice obligation. |
| AUTH-H2 | Decide repository visibility for release | In GitHub: repository **Settings → General → Danger Zone → Change repository visibility**, choose the intended public/private state for release. | This is an owner publication decision, not an executable AUTH defect. |
| AUTH-H3 | Provide a public security-contact method | Choose an address or external disclosure URL, replace `OWNER_SECURITY_CONTACT_REQUIRED` in `SECURITY.md`, and verify that the recipient is monitored. | No security contact may be invented by an agent. |
| AUTH-H4 | Authorize public-history remediation if audit findings are confirmed sensitive | Review the path/commit-only audit receipt without copying secret values. If sensitive material is confirmed, revoke/rotate it first, then explicitly authorize a coordinated `git filter-repo` history rewrite and force-push. | History rewriting is destructive and affects every clone; no rewrite is performed automatically. |
| AUTH-H5 | Register a product's OAuth callbacks | In each chosen provider console, register the exact callback URLs from that product's reviewed native plan. Do not register guessed URLs. | Deployment/operator action; not a public-release prerequisite unless a maintained reference deployment is later adopted. |
| AUTH-H6 | Supply product credentials | Put client IDs/secrets and session/token secrets into the product's approved secret manager; never commit them or paste them into reports. | Deployment/operator action; not a public-release prerequisite. |
| AUTH-H7 | Complete interactive live sign-in and consent | In the owner-approved product environment, complete provider login/consent and retain only redacted evidence for callback, session, refresh, logout, and restart continuity. | Deployment/operator acceptance; not a public-release prerequisite. |
| AUTH-H8 | Approve any authority cutover or irreversible migration | Review an explicit migration plan with backup, compatibility, rollback boundary, identity/session/data invariants, and irreversible steps; approve the exact plan before execution. | Product deployment action. AUTH intentionally refuses irreversible migration without this authority. |
| AUTH-H9 | Approve the first public release/tag | After AUTH-H3 and any required AUTH-H4 remediation, review the clean-clone receipt and run `git tag -s v<approved-version> <approved-commit>` followed by an explicit push of that tag. | Release identity and signing are owner actions; AUTH does not create or push the tag. |

AUTH-H2, H3, H4 when applicable, and H9 are release decisions. AUTH-H5 through H8 are deployment/operator actions and do not block publication of the generic AUTH wizard. The ledger is not permission for an agent to perform any action.
