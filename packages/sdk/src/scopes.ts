/**
 * Provides standard OAuth scope values used by Aquari client applications.
 */
export const AquariScopes = Object.freeze({
  openid: "openid",
  profile: "profile",
  email: "email",
  offlineAccess: "offline_access",
  passportRead: "passport.read",
} as const);

/**
 * Represents one standard Aquari OAuth scope value.
 */
export type AquariScope =
  typeof AquariScopes[
    keyof typeof AquariScopes
  ];
