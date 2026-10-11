# AUTH focused acceptance evidence

This record distinguishes committed clean-checkout evidence from the hazardous working tree. It contains no credentials or runtime data.

## Commit `992779a`

A local `--no-local` clone of the commit was installed with `npm ci`. Because npm's script policy did not run Prisma's generator during install, the required sequence was explicit:

```text
npm ci
npm run prisma:generate
npm run build
bin/node20 --test dist/test/auth.test.js dist/test/oauth.test.js dist/test/desktopCallbackFailure.test.js dist/test/authorizationCode.test.js dist/test/startup.test.js
```

Results in a local `--no-local` clone before final product-specific source removal: locked install succeeded, Prisma Client 6.12.0 generated, TypeScript built, native durability passed 11/11, committed standards passed 59/59, and the command/wizard suite passed 144/144. Generation initially failed in the restricted sandbox because Prisma attempted to update the read-only user cache; with an isolated HOME it required the pinned engine download, and the narrowly unrestricted run succeeded. A final clean-clone receipt must supersede these repository-level counts after the removal commit; the generated-product evidence below remains valid because it exercises the product-neutral profile bytes.

The 60/60 working-tree result is not equivalent clean-checkout coverage. The additional test is the uncommitted `MCP setup gaps produce a bounded agent integration handoff` case in `src/test/auth-blocker-handoff.test.mjs`, paired with uncommitted catalog changes. Those pre-existing overlapping bytes remain excluded from scoped commits pending provenance reconciliation. The clean commit therefore has 17 catalog families and 59 standards tests; the hazardous working tree has 18 families and 60. Both counts were run explicitly and are not conflated.

## Generated-product independence

From the clean clone, `auth native plan` and authorized `apply` created ten ordinary product-owned files in an empty target: Prisma schema and migration, database preparation script, `src/index.ts`, profile acceptance test, locked package metadata, TypeScript configuration, and `auth-standards.json`. VERIFY passed and found no prohibited persistent artifacts.

The source clone was then renamed out of its original location. Inside the generated product, independent `npm ci`, Prisma generation, migration deployment, TypeScript build, and both runtime tests passed (2/2). With the source still unavailable, the built product started on an isolated loopback port and returned `{"ok":true}` from `/health` and `{"ready":true}` from `/ready`; the process was then stopped. The target contained no `.auth-runtime`, `.auth-kit`, adapter, daemon, copied AUTH package, installed AUTH workflow, or lifecycle control plane.

## Listener restriction classification

Inside the restricted command sandbox, a minimal Node `net.createServer()` bind to `127.0.0.1` failed with `EPERM`. The identical loopback-only probe succeeded outside that restriction on an ephemeral port. With the same narrowly elevated loopback permission, all 46 runtime/startup tests passed. This proves the earlier listener failures were caused by the sandbox boundary, while the unrestricted focused runtime result supplies the previously missing executable evidence.

Product-neutrality, existing-auth alignment, migration rollback, and superseded-machinery removal now have focused executable coverage. Public tracked-source disposition, history sensitivity, legal metadata, and final release authorization remain separate gates.
