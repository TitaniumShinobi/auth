# Auth Setup CLI

The lifecycle and ownership authority for this command is [AUTH durability architecture](AUTH_DURABILITY_ARCHITECTURE.md).

`auth/` is a source kit and one-time setup authority. It installs a complete authentication system into each consuming product and is not a forever runtime hub.

For the canonical generic capability wizard, see [AUTH_WIZARD.md](AUTH_WIZARD.md). Setup writes require explicit `--authorize`; review with `--dry-run` first.

The source-kit CLI retains these commands:

```sh
bin/auth setup --repo ../chatty --app chatty --authorize
bin/auth validate --repo ../chatty --app chatty
```

Supported target apps:

- `chatty`
- `cleanhouse`
- `code`
- `vvault`

## Setup

`setup` installs two complementary components into the target repo:

- `.auth-runtime/auth-system/`: the complete product-local authentication runtime, including provider, session, refresh, authorization, persistence, configuration, Prisma, build, and launch sources
- `.auth-kit/`: the durable verification, maintenance, provenance, and repair contract

The runtime installation includes:

- `src/app.ts`, `src/index.ts`, and every required `src/auth/`, `src/persistence/`, and `src/github/` module
- the selected product configuration as `config/example-app.json`
- an independent `package.json`, committed `package-lock.json`, TypeScript configuration, Prisma schema, environment-name template, runtime README, and integrity/provenance manifest

Runtime source is read from the resolved Git `HEAD` commit. Working-tree modifications, untracked files, local dependency directories, and build output are not copied. The manifest binds the installation to the commit/tree, source content, runtime inventory, lockfile, and non-secret configuration. Install dependencies with `npm ci`, generate the product-local Prisma client with `npm run prisma:generate`, then build with `npm run build`; `npm install` is not the canonical path.

The lifecycle kit includes:

- `.auth-kit/auth.config.json`
- `.auth-kit/SYSTEM.md`
- `.auth-kit/reports/latest.md`

The generated report records:

- files changed
- ports recorded
- env var names needed, without values
- OAuth callback URLs
- proof commands
- blockers

Use `--dry-run` to print the report without writing files:

```sh
bin/auth setup --repo ../vvault --app vvault --dry-run
```

## Validate

`validate` is read-only. It checks whether setup evidence exists in the target repo and reports blockers.

```sh
bin/auth validate --repo ../cleanhouse --app cleanhouse
```

Validation does not read `.env*` files and never prints secret values.

## Source Kit vs Installed Runtime

Reusable setup source:

- `bin/auth`
- `scripts/auth-cli.mjs`
- `templates/auth-adapter/`
- `config/<app>.json`
- `docs/LOCAL_PORTS.md`
- `docs/AGENTIC_CODER_PROMPT.md`

Runtime-only service code:

- `src/app.ts`
- `src/index.ts`
- `src/auth/`
- `src/persistence/`
- `src/github/`
- `scripts/open-auth-standalone.sh`

AUTH SETUP installs the complete runtime into `.auth-runtime/auth-system/`. The installed runtime can install its own dependencies, build, and start without this source checkout. Agents must not manually recreate, copy, adapt, or carry runtime/provider implementation. Setup refuses to overwrite an existing runtime; upgrades and repairs require an explicit, reviewed lifecycle operation.

Initial setup is one transaction: runtime, lifecycle bundle, setup configuration, system instructions, report, and verification workflow are staged before publication. Journal revisions use adjacent temporary files and atomic rename. Published artifacts record their post-publication filesystem identity and digest; rollback atomically quarantines each destination and deletes it only when both still agree. Staging cleanup independently requires the recorded device/inode, transaction marker, expected path, and matching journal.

Before a new initial setup, the command processes at most one exact-prefix abandoned transaction journal. A validated incomplete transaction is rolled back; a validated COMPLETE transaction with intact permanent artifacts is finalized. Malformed, symlinked, path-escaping, duplicate, unsupported, or ambiguous recovery evidence is preserved and fails closed. Existing destinations fail preflight and are never overwritten.

This recovery guarantee covers controlled process termination at tested mutation boundaries. It does not claim filesystem power-loss durability because explicit file and directory `fsync` is not implemented.

The immutable committed input, locked dependency installation, product-local Prisma generation, isolated build, startup, readiness, and source-checkout-unavailability proof are implemented in temporary acceptance fixtures. Initial SETUP does not itself freeze operational acceptance; the explicitly authorized `runtime establish` command does so before REPAIR or UPGRADE is allowed.

## Target Repo Commands

```sh
bin/auth setup --repo ../chatty --app chatty --authorize
bin/auth setup --repo ../cleanhouse --app cleanhouse --authorize
bin/auth setup --repo ../code --app code --authorize
bin/auth setup --repo ../vvault --app vvault --authorize
```

Read-only validation:

```sh
bin/auth validate --repo ../chatty --app chatty
bin/auth validate --repo ../cleanhouse --app cleanhouse
bin/auth validate --repo ../code --app code
bin/auth validate --repo ../vvault --app vvault
```

## Runtime lifecycle

```sh
bin/auth runtime establish --repo <product> --app <id> --authorize
bin/auth runtime verify --repo <product> --app <id>
bin/auth runtime repair --repo <product> --app <id> --authorize
bin/auth runtime upgrade --repo <product> --app <id> --target-revision <git-commit> --authorize
bin/auth runtime recover --repo <product> --app <id>
```

`establish` performs locked install, Prisma generation, build, isolated startup/readiness, and auth-route acceptance before freezing authenticated runtime baseline material. `verify` is read-only. `repair` restores only AUTH-owned immutable runtime files from the recorded commit and refuses version changes. `upgrade` accepts a distinct immutable revision before activation and advances baseline lineage only after post-publication verification.

REPAIR and UPGRADE use a recoverable runtime-swap journal. `runtime recover` is the explicit recovery entry point and every mutating lifecycle command invokes the same recovery first. Before authenticated baseline publication, interruption restores the previous runtime; after the published baseline digest and runtime installation identity agree, recovery finalizes the new runtime. REPAIR restart then completes the same immutable version when the restored pre-run runtime was the damaged input. Product files and `.auth-runtime/data/` remain outside the swapped `auth-system/` directory.

Focused tests force real child-process exit at `PREPARED`, `OLD_QUARANTINED`, `NEW_PUBLISHED`, `BASELINE_ADVANCING`, immediately after baseline publication, and `BASELINE_ADVANCED` for both REPAIR and UPGRADE. The restarted CLI must produce and VERIFY a complete matching pair, preserve product/session/data sentinels, and remove all transaction residue. The abrupt-exit and fixture-acceptance controls are inert unless the explicit test-mode environment gate is set.
