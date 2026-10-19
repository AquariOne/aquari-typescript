# @aquari-one/sdk

Official Aquari One SDK for JavaScript and TypeScript public clients.

Provides OAuth 2.0 / OpenID Connect authorization, PKCE, discovery, UserInfo,
Passport and Passport signals, cross-application trust reads, and typed errors.

**Security:** Client-side applications must use public OAuth clients with PKCE.
Never embed confidential OAuth secrets, developer API keys, or privileged issuer
credentials in a browser bundle.

The consuming application defines its own authorization policy and roles;
Aquari identity and trust data are not automatic permission grants.

See the [TypeScript integration guide](https://docs.aquari.one/sdks/typescript)
and [scope availability](https://docs.aquari.one/authentication/scopes)
for supported workflows and permissions.

**License:** Apache-2.0 (see `LICENSE` and `NOTICE`).

Source repository (GitLab, authoritative): https://gitlab.com/nousen-group/aquari/aquari-typescript
GitHub read-only mirror: https://github.com/AquariOne/aquari-typescript

The public SDK source is exported from Aquari One’s private monorepo. Contributions and release decisions are managed on GitLab; do not push directly to the GitHub mirror.
