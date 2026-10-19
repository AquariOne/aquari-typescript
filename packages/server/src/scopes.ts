/**
 * Provides machine API scope values for trusted-server Aquari operations.
 */
export const AquariMachineScopes =
  Object.freeze({
    contextRead:
      "machine.context.read",
    healthRead:
      "machine.health.read",
    badgesIssue:
      "issuer.badges.issue",
    badgesRead:
      "issuer.badges.read",
    badgesRevoke:
      "issuer.badges.revoke",
    credentialsIssue:
      "issuer.credentials.issue",
    credentialsRead:
      "issuer.credentials.read",
    credentialsUpdate:
      "issuer.credentials.update",
    credentialsRevoke:
      "issuer.credentials.revoke",
    entitlementsIssue:
      "issuer.entitlements.issue",
    entitlementsRead:
      "issuer.entitlements.read",
    entitlementsUpdate:
      "issuer.entitlements.update",
    entitlementsRevoke:
      "issuer.entitlements.revoke",
    membershipsIssue:
      "issuer.memberships.issue",
    membershipsRead:
      "issuer.memberships.read",
    membershipsUpdate:
      "issuer.memberships.update",
    membershipsRevoke:
      "issuer.memberships.revoke",
    stampsIssue:
      "issuer.stamps.issue",
    stampsRead:
      "issuer.stamps.read",
    stampsRevoke:
      "issuer.stamps.revoke",
  } as const);

/**
 * Represents one Aquari machine API scope value.
 */
export type AquariMachineScope =
  typeof AquariMachineScopes[
    keyof typeof AquariMachineScopes
  ];
