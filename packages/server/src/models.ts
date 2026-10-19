/**
 * Describes the organization, application, environment, key, and scopes bound to the
 * current machine API key.
 */
export interface AquariMachineContext {
  actorType: string;
  apiKeyId: string;
  keyPrefix: string;
  keyName: string;
  organizationId: string;
  applicationId: string;
  environmentId: string;
  environmentName: string;
  environment: string;
  scopes: readonly string[];
}

/**
 * Contains the authenticated machine health response returned by Aquari.
 */
export interface AquariMachineHealth {
  ok: boolean;
  actorType: string;
  apiKeyId: string;
  applicationId: string;
  environment: string;
}

/**
 * Identifies the Aquari issuer that produced a trusted-server signal.
 */
export interface AquariIssuerIdentity {
  type: string;
  id: string;
  name: string;
  logoUrl?: string;
}

/**
 * Configures optional idempotency and cancellation for an issuer create operation.
 */
export interface AquariIssueOptions {
  idempotencyKey?: string;
  signal?: AbortSignal;
}

/**
 * Configures cancellation for a trusted-server Aquari request.
 */
export interface AquariServerRequestOptions {
  signal?: AbortSignal;
}

/**
 * Defines the values used to issue a new badge signal.
 */
export interface AquariBadgeIssueInput {
  subjectId: string;
}

/**
 * Represents an Aquari badge signal returned by the issuer API.
 */
export interface AquariBadgeSignal {
  id: string;
  definitionId: string;
  subjectId: string;
  issuer: AquariIssuerIdentity;
  name: string;
  description?: string;
  criteria?: string;
  imageUrl?: string;
  defaultVisibility: string;
  status: string;
  issuedAt: string;
  revokedAt?: string;
}

/**
 * Contains the signal and issuer metadata returned after a badge issue operation.
 */
export interface AquariBadgeIssueResult {
  signal: AquariBadgeSignal;
  idempotentReplay: boolean;
}

/**
 * Identifies the evidence format attached to an Aquari credential signal.
 */
export type AquariCredentialEvidenceType =
  | "document"
  | "verification_record"
  | "registry_record"
  | "external_reference"
  | (string & {});

/**
 * Defines evidence supplied when a credential signal is issued or updated.
 */
export interface AquariCredentialEvidenceInput {
  type: AquariCredentialEvidenceType;
  reference: string;
  verifiedAt: string;
}

/**
 * Represents evidence attached to an Aquari credential signal.
 */
export interface AquariCredentialEvidence {
  id: string;
  type: string;
  reference: string;
  verifiedAt: string;
  createdAt: string;
}

/**
 * Defines the values used to issue a new credential signal.
 */
export interface AquariCredentialIssueInput {
  subjectId: string;
  expiresAt?: string;
  evidence?: readonly AquariCredentialEvidenceInput[];
}

/**
 * Defines the mutable values used to update an existing credential signal.
 */
export interface AquariCredentialUpdateInput {
  expiresAt?: string;
  evidence?: readonly AquariCredentialEvidenceInput[];
}

/**
 * Represents an Aquari credential signal returned by the issuer API.
 */
export interface AquariCredentialSignal {
  id: string;
  definitionId: string;
  subjectId: string;
  issuer: AquariIssuerIdentity;
  key: string;
  name: string;
  description?: string;
  assuranceLevel: string;
  verificationMethod: string;
  defaultVisibility: string;
  status: string;
  effective: boolean;
  issuedAt: string;
  expiresAt?: string;
  revokedAt?: string;
  evidence: readonly AquariCredentialEvidence[];
}

/**
 * Contains the signal and issuer metadata returned after a credential issue operation.
 */
export interface AquariCredentialIssueResult {
  signal: AquariCredentialSignal;
  idempotentReplay: boolean;
}

/**
 * Defines the values used to issue a new entitlement signal.
 */
export interface AquariEntitlementIssueInput {
  subjectId: string;
  planId?: string;
  status?: "active" | "trialing" | "comped";
  startsAt?: string;
  expiresAt?: string;
}

/**
 * Defines the mutable values used to update an existing entitlement signal.
 */
export interface AquariEntitlementUpdateInput {
  planId?: string;
  status: string;
  startsAt: string;
  expiresAt?: string;
}

/**
 * Represents entitlement plan metadata returned with an Aquari entitlement signal.
 */
export interface AquariEntitlementPlan {
  id: string;
  name: string;
  slug: string;
  billingPeriod: string;
  priceCents: number;
  currency: string;
  status: string;
  createdAt: string;
  updatedAt?: string;
  disabledAt?: string;
}

/**
 * Represents an Aquari entitlement signal returned by the issuer API.
 */
export interface AquariEntitlementSignal {
  id: string;
  definitionId: string;
  subjectId: string;
  issuer: AquariIssuerIdentity;
  name: string;
  description?: string;
  plan?: AquariEntitlementPlan;
  source: string;
  status: string;
  effective: boolean;
  startsAt: string;
  expiresAt?: string;
  revokedAt?: string;
}

/**
 * Contains the signal and issuer metadata returned after a entitlement issue operation.
 */
export interface AquariEntitlementIssueResult {
  signal: AquariEntitlementSignal;
  idempotentReplay: boolean;
}

/**
 * Defines the values used to issue a new membership signal.
 */
export interface AquariMembershipIssueInput {
  subjectId: string;
  roleId?: string;
}

/**
 * Defines the mutable values used to update an existing membership signal.
 */
export interface AquariMembershipUpdateInput {
  /**
   * Assign a formal role definition, or pass null to return the signal to a
   * general application membership.
   */
  roleId?: string | null;
}

/**
 * Represents membership role metadata returned with an Aquari membership signal.
 */
export interface AquariMembershipRole {
  id: string;
  name: string;
  description?: string;
  status: string;
  createdAt: string;
  updatedAt?: string;
  retiredAt?: string;
}

/**
 * Represents an Aquari membership signal returned by the issuer API.
 */
export interface AquariMembershipSignal {
  id: string;
  definitionId?: string;
  subjectId: string;
  issuer: AquariIssuerIdentity;
  type: string;
  role: string;
  roleDefinition?: AquariMembershipRole;
  status: string;
  effective: boolean;
  issuedAt: string;
  revokedAt?: string;
}

/**
 * Contains the signal and issuer metadata returned after a membership issue operation.
 */
export interface AquariMembershipIssueResult {
  signal: AquariMembershipSignal;
  idempotentReplay: boolean;
}

/**
 * Defines the values used to issue a new stamp signal.
 */
export interface AquariStampIssueInput {
  subjectId: string;
  scopeType: string;
  scopeId: string;
  occurredAt: string;
}

/**
 * Represents stamp scope metadata used by Aquari.
 */
export interface AquariStampScope {
  type: string;
  id: string;
}

/**
 * Represents an Aquari stamp signal returned by the issuer API.
 */
export interface AquariStampSignal {
  id: string;
  definitionId: string;
  subjectId: string;
  issuer: AquariIssuerIdentity;
  key: string;
  name: string;
  description?: string;
  imageUrl?: string;
  scope: AquariStampScope;
  occurredAt: string;
  issuedAt: string;
  defaultVisibility: string;
  status: string;
  effective: boolean;
  revokedAt?: string;
}

/**
 * Contains the signal and issuer metadata returned after a stamp issue operation.
 */
export interface AquariStampIssueResult {
  signal: AquariStampSignal;
  idempotentReplay: boolean;
}
