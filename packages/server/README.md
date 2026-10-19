# @aquari-one/server

Official Aquari One trusted-server SDK for JavaScript and TypeScript.

Provides machine API access, issuer operations for supported Passport signal
families, and signed webhook verification.

**Security:** Use only on trusted backends. Protect machine API keys, issuer
credentials, and webhook signing secrets; never import this package into a
browser bundle or ship these credentials to mobile applications.

Requires the `@aquari-one/sdk` core package at the matching release version.
Server/machine API-key scopes are **not** delegated OAuth scopes.

See the [TypeScript integration guide](https://docs.aquari.one/sdks/typescript)
and [issuer API reference](https://docs.aquari.one/issuer-apis).

**License:** Apache-2.0 (see `LICENSE` and `NOTICE`).

Source repository (GitLab, authoritative): https://gitlab.com/nousen-group/aquari/aquari-typescript
GitHub read-only mirror: https://github.com/AquariOne/aquari-typescript

The public SDK source is exported from Aquari One’s private monorepo. Contributions and release decisions are managed on GitLab; do not push directly to the GitHub mirror.
