# AUTH focused acceptance evidence

This record distinguishes committed clean-checkout evidence from the hazardous working tree. It contains no credentials or runtime data.

## Commit `eb335b2`

A local `--no-local` clone of the commit was installed with `npm ci`. Because npm's script policy did not run Prisma's generator during install, the required sequence was explicit:

```text
npm ci
npm run prisma:generate
npm run build
bin/node20 --test dist/test/auth.test.js dist/test/oauth.test.js dist/test/desktopCallbackFailure.test.js dist/test/authorizationCode.test.js dist/test/startup.test.js
```

Results: locked install succeeded; Prisma Client 6.12.0 generated; TypeScript build succeeded; runtime/startup suite passed 46/46. The native successor suite passed 9/9 and the committed standards suite passed 59/59.

The earlier 60/60 working-tree result is not equivalent clean-checkout coverage. The additional test is the uncommitted `MCP setup gaps produce a bounded agent integration handoff` case in `src/test/auth-blocker-handoff.test.mjs`, paired with uncommitted catalog changes. Those pre-existing overlapping bytes were deliberately excluded from scoped commits pending provenance reconciliation. The clean commit therefore has 17 catalog families and 59 tests; the working tree has 18 families and 60 tests.

## Listener restriction classification

Inside the restricted command sandbox, a minimal Node `net.createServer()` bind to `127.0.0.1` failed with `EPERM`. The identical loopback-only probe succeeded outside that restriction on an ephemeral port. With the same narrowly elevated loopback permission, all 46 runtime/startup tests passed. This proves the earlier listener failures were caused by the sandbox boundary, while the unrestricted focused runtime result supplies the previously missing executable evidence.

This evidence does not resolve product-neutrality, existing-auth alignment, migration, public-artifact disposition, or removal of superseded machinery. Those remain release gates.
