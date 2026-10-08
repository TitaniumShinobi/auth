# History-preserving verifier upgrades

AUTH can correct its product-local verifier without establishing a new product baseline. This is maintenance infrastructure, never product authentication runtime.

## Integrity model

The original `.auth-kit/contract.json`, `provenance.json`, `baseline/`, `history/`, `observe.mjs`, `ci.mjs`, workflow, and original `runtime/` remain unchanged. In particular, an established product at sequence 1 stays at product-baseline sequence 1.

Verifier upgrades have a separate, append-only hash-linked history in `.auth-kit/upgrades/history/<event-digest>.json`. Each event binds the current product history head and contract digest, previous upgrade head, exact current source revision, old and new runtime digests, operator, reason, and unique authorization run ID. This is a prospective upgrade event, not a retroactive edit of an old baseline. Its new runtime lives in `.auth-kit/upgrades/generations/<event-digest>/`.

The new digest covers the exact runtime file manifest and versioned launcher protocol. The original digest covers original provenance and verifier-entrypoint hash. Subsequent old digests must equal the previous event's new digest. The event digest determines the exact active launcher text. All original runtime/gate hashes remain enforced.

The bootstrap validates original provenance, complete baseline/history chain, observer, current product source/artifact/configuration binding and explicit authorization. It copies only provenance-listed modules, preserving installed inventory/cache behavior. It changes the known historical comparison and adds the upgrade validation hook. Unknown source layouts fail `UNSUPPORTED_INSTALLED_VERIFIER`; there is no blind overwrite fallback.

## Commands

From AUTH: `bin/auth verifier-upgrade prepare <product-root> <authorization.json>`.
From the portable bundle: `node auth-verifier-upgrade.mjs prepare <product-root> <authorization.json>`.

Prepare writes an authorization candidate outside the product with `authorized:false`, expected history/upgrade heads, contract digest, revision, old/new digests, and a fresh run ID. Review these against the established product and reviewed package. Set `authorized:true`, `operator`, and a specific `reason`. Do not alter digest/binding fields to bypass a failed precondition.

Apply: `node auth-verifier-upgrade.mjs apply <product-root> <authorization.json>`.
Then, from the product: `node .auth-kit/verify.mjs verify` with current required authority/runtime evidence supplied normally. Upgrade does not create PASS evidence, waive requirements, refresh evidence TTLs, or advance a baseline. It returns `UPGRADED_VERIFY_REQUIRED`.

Prepare/apply use the installed product binding implementation; a large uncached inventory can still take time. Keep the product quiescent while applying. The shared advancement lock serializes authorized contract changes. Drift between preparation, staging and activation fails closed.

## Atomic activation and recovery

Staging and the prospective upgrade event are written first. Only an atomic rename of `.auth-kit/verify.mjs` activates the generation. Prior to that publication the original entrypoint remains active. The new entrypoint checks event and generation hashes before importing generation modules, then validates the full upgrade and product-history chains. Unrecorded replacement remains `VERIFIER_OR_GATE_DRIFT`.

Caught pre-publication failures remove only this attempt's staging/event and retain the original runtime/history. A hard process termination before publication leaves the original entrypoint active, with inert staging and a lock. Use `node auth-verifier-upgrade.mjs recover <product-root> <same-authorization.json>`: recovery requires the recorded process to be absent, exact authorization, unchanged old entrypoint, unchanged current binding/history, and a matching journal. It cleans only the abandoned generation/event/lock. If activation occurred or state drifted, recovery refuses to roll back. Do not delete locks manually. Process crash semantics are tested; sudden power-loss/filesystem durability and Windows rename behavior need platform acceptance.

## Bootstrap trust and limitations

Verify the distributed ZIP's SHA-256 through the reviewed AUTH handoff, then verify its internal manifest before running it. Bootstrap code is the externally reviewed trust anchor; the old installed verifier need not understand upgrades. Self-consistent local hashes are not a signature from an independent authority. As with the existing contract, a repository writer replacing the entire enforcement system requires an external required status/checkpoint boundary to detect it. No remote branch protection is changed here.

Tests use disposable product repositories, legacy verifier source, synthetic evidence, forced interruption, tampered provenance/events, repeated upgrades, and actual historical regressions. They do not prove live product sign-in or Windows OS behavior. No product auth/session/provider code is changed.
