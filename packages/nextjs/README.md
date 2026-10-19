# @aquari-one/nextjs

Official Aquari One Next.js application-session integration.

Provides the `createAquari` adapter, application-side sessions, and token
refresh/session coordination for Next.js applications.

**Security:** Configure authentication on the server, protect credentials, and
use a durable session store when deploying more than one application instance.
Session authentication does not automatically assign application roles.

Requires the `@aquari-one/sdk` core package at the matching release version.
See the [TypeScript/Next.js guide](https://docs.aquari.one/sdks/typescript)
for setup, redirect URIs, and verified examples.

**License:** Apache-2.0 (see `LICENSE` and `NOTICE`).

Source repository (GitLab, authoritative): https://gitlab.com/nousen-group/aquari/aquari-typescript
GitHub read-only mirror: https://github.com/AquariOne/aquari-typescript

The public SDK source is exported from Aquari One’s private monorepo. Contributions and release decisions are managed on GitLab; do not push directly to the GitHub mirror.
