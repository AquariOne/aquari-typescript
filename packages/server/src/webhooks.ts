import {
  createHmac,
  timingSafeEqual,
} from "node:crypto";

import {
  AquariError,
} from "@aquari-one/sdk";

import {
  asIsoDateString,
  asNonEmptyString,
  asOptionalIsoDateString,
  asOptionalString,
  asRecord,
  asStringArray,
  optionalProperty,
} from "./wire.js";

const DEFAULT_WEBHOOK_TOLERANCE_SECONDS =
  300;

const SIGNATURE_PATTERN =
  /^v1=([0-9a-f]{64})$/u;

const KNOWN_EVENT_TYPES =
  new Set<string>([
    "webhook.test",
    "application.connection.created",
    "application.connection.revoked",
    "application.updated",
    "organization.member.added",
    "organization.member.updated",
    "organization.member.removed",
    "organization.ownership.transferred",
    "organization.domain.verified",
    "organization.domain.revoked",
    "passport.visibility.updated",
    "passport.signal.visibility.updated",
  ]);

/**
 * Identifies the reason an Aquari webhook verification attempt failed.
 */
export type AquariWebhookVerificationFailure =
  | "missing_timestamp"
  | "invalid_timestamp"
  | "timestamp_outside_tolerance"
  | "missing_signature"
  | "invalid_signature_format"
  | "signature_mismatch";

/**
 * Configures the webhook verification error operation.
 */
export interface AquariWebhookVerificationErrorOptions {
  reason:
    AquariWebhookVerificationFailure;
  message: string;
}

/**
 * Reports a webhook verification failure before the payload is trusted.
 */
export class AquariWebhookVerificationError
  extends AquariError {
  public readonly reason:
    AquariWebhookVerificationFailure;

  /**
   * Creates a webhook verification error and records the reason the request could not be
   * trusted.
   */
  public constructor(
    options:
      AquariWebhookVerificationErrorOptions,
  ) {
    super(options.message);
    this.reason =
      options.reason;
  }
}

/**
 * Reports a verified webhook whose payload does not match the declared event type.
 */
export class AquariWebhookPayloadError
  extends AquariError {
}

/**
 * Contains the common fields present in every verified Aquari webhook.
 */
export interface AquariWebhookEnvelope {
  id: string;
  type: string;
  version: string;
  createdAt: string;
  organizationId: string;
  applicationId: string;
  environmentId: string;
  data: unknown;
  raw: Readonly<Record<string, unknown>>;
  known: boolean;
}

/**
 * Contains typed data for the Aquari application connection created  webhook event.
 */
export interface AquariApplicationConnectionCreatedData {
  userId: string;
  oAuthClientId: string;
  scopes: readonly string[];
  connectedAt: string;
}

/**
 * Contains typed data for the Aquari application connection revoked  webhook event.
 */
export interface AquariApplicationConnectionRevokedData {
  userId: string;
  oAuthClientIds: readonly string[];
  scopes: readonly string[];
  revokedAt: string;
}

/**
 * Contains typed data for the Aquari application updated  webhook event.
 */
export interface AquariApplicationUpdatedData {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  description?: string;
  logoUrl?: string;
  homepageUrl?: string;
  privacyPolicyUrl?: string;
  termsOfServiceUrl?: string;
  supportUrl?: string;
  supportEmail?: string;
  status: string;
  updatedAt?: string;
}

/**
 * Contains typed data for the Aquari organization member added  webhook event.
 */
export interface AquariOrganizationMemberAddedData {
  memberId: string;
  userId: string;
  role: string;
  joinedAt: string;
}

/**
 * Contains typed data for the Aquari organization member updated  webhook event.
 */
export interface AquariOrganizationMemberUpdatedData {
  memberId: string;
  userId: string;
  role: string;
  applicationId?: string;
  applicationPermissions?: readonly string[];
  updatedAt: string;
}

/**
 * Contains typed data for the Aquari organization member removed  webhook event.
 */
export interface AquariOrganizationMemberRemovedData {
  memberId: string;
  userId: string;
  previousRole: string;
  removedAt: string;
}

/**
 * Contains typed data for the Aquari organization ownership transferred  webhook event.
 */
export interface AquariOrganizationOwnershipTransferredData {
  previousOwnerMemberId: string;
  previousOwnerUserId: string;
  newOwnerMemberId: string;
  newOwnerUserId: string;
  transferredAt: string;
}

/**
 * Contains typed data for the Aquari organization domain verified  webhook event.
 */
export interface AquariOrganizationDomainVerifiedData {
  domainClaimId: string;
  domain: string;
  verifiedAt: string;
  expiresAt: string;
}

/**
 * Contains typed data for the Aquari organization domain revoked  webhook event.
 */
export interface AquariOrganizationDomainRevokedData {
  domainClaimId: string;
  domain: string;
  revokedAt: string;
}

/**
 * Contains typed data for the Aquari passport visibility updated  webhook event.
 */
export interface AquariPassportVisibilityUpdatedData {
  userId: string;
  visibility: string;
  updatedAt: string;
}

/**
 * Contains typed data for the Aquari passport signal visibility updated  webhook event.
 */
export interface AquariPassportSignalVisibilityUpdatedData {
  userId: string;
  sourceType: string;
  sourceId: string;
  visibility: string;
  updatedAt: string;
}

/**
 * Represents a known, typed Aquari webhook event.
 */
export type AquariKnownWebhookEvent =
  | (AquariWebhookEnvelope & {
      type:
        "application.connection.created";
      data:
        AquariApplicationConnectionCreatedData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "application.connection.revoked";
      data:
        AquariApplicationConnectionRevokedData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "application.updated";
      data:
        AquariApplicationUpdatedData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "organization.member.added";
      data:
        AquariOrganizationMemberAddedData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "organization.member.updated";
      data:
        AquariOrganizationMemberUpdatedData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "organization.member.removed";
      data:
        AquariOrganizationMemberRemovedData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "organization.ownership.transferred";
      data:
        AquariOrganizationOwnershipTransferredData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "organization.domain.verified";
      data:
        AquariOrganizationDomainVerifiedData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "organization.domain.revoked";
      data:
        AquariOrganizationDomainRevokedData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "passport.visibility.updated";
      data:
        AquariPassportVisibilityUpdatedData;
    })
  | (AquariWebhookEnvelope & {
      type:
        "passport.signal.visibility.updated";
      data:
        AquariPassportSignalVisibilityUpdatedData;
    })
  | (AquariWebhookEnvelope & {
      type: "webhook.test";
      data:
        Readonly<Record<string, unknown>>;
    });

/**
 * Represents any verified Aquari webhook event, including unknown future event types.
 */
export type AquariWebhookEvent =
  | AquariKnownWebhookEvent
  | AquariWebhookEnvelope;

/**
 * Defines the Aquari webhook signature headers required for verification.
 */
export type AquariWebhookHeaders =
  | Headers
  | Readonly<
      Record<
        string,
        string |
        readonly string[] |
        undefined
      >
    >;

/**
 * Configures webhook signature verification, clock tolerance, and optional replay
 * protection.
 */
export interface VerifyAquariWebhookOptions {
  secret: string;
  headers: AquariWebhookHeaders;
  rawBody: string | Uint8Array;
  toleranceSeconds?: number;
  now?: Date;
}

/**
 * Verifies the Aquari webhook signature and timestamp before the payload is trusted. The
 * function can also use caller-provided replay protection.
 */
export function verifyAquariWebhook(
  options:
    VerifyAquariWebhookOptions,
): AquariWebhookEvent {
  const secret =
    validateSecret(
      options.secret,
    );

  const timestampHeader =
    readHeader(
      options.headers,
      "Aquari-Timestamp",
    );

  if (
    timestampHeader === undefined ||
    timestampHeader.length === 0
  ) {
    throw verificationError(
      "missing_timestamp",
      "Aquari webhook timestamp is missing.",
    );
  }

  if (!/^[0-9]+$/u.test(timestampHeader)) {
    throw verificationError(
      "invalid_timestamp",
      "Aquari webhook timestamp is invalid.",
    );
  }

  const timestamp =
    Number(timestampHeader);

  if (
    !Number.isSafeInteger(timestamp) ||
    timestamp < 0
  ) {
    throw verificationError(
      "invalid_timestamp",
      "Aquari webhook timestamp is invalid.",
    );
  }

  const tolerance =
    options.toleranceSeconds ??
    DEFAULT_WEBHOOK_TOLERANCE_SECONDS;

  if (
    !Number.isFinite(tolerance) ||
    tolerance < 0
  ) {
    throw new RangeError(
      "Aquari webhook toleranceSeconds must be a non-negative finite number.",
    );
  }

  const now =
    Math.floor(
      (
        options.now ??
        new Date()
      ).getTime() /
        1_000,
    );

  if (
    Math.abs(now - timestamp) >
    tolerance
  ) {
    throw verificationError(
      "timestamp_outside_tolerance",
      "Aquari webhook timestamp is outside the accepted tolerance.",
    );
  }

  const signatureHeader =
    readHeader(
      options.headers,
      "Aquari-Signature",
    );

  if (
    signatureHeader === undefined ||
    signatureHeader.length === 0
  ) {
    throw verificationError(
      "missing_signature",
      "Aquari webhook signature is missing.",
    );
  }

  const match =
    SIGNATURE_PATTERN.exec(
      signatureHeader,
    );

  if (match === null) {
    throw verificationError(
      "invalid_signature_format",
      "Aquari webhook signature format is invalid.",
    );
  }

  const providedHex =
    match[1];

  if (providedHex === undefined) {
    throw verificationError(
      "invalid_signature_format",
      "Aquari webhook signature format is invalid.",
    );
  }

  const expected =
    createWebhookSignature(
      secret,
      timestampHeader,
      options.rawBody,
    );

  const provided =
    Buffer.from(
      providedHex,
      "hex",
    );

  if (
    provided.length !==
      expected.length ||
    !timingSafeEqual(
      provided,
      expected,
    )
  ) {
    throw verificationError(
      "signature_mismatch",
      "Aquari webhook signature does not match the payload.",
    );
  }

  return parseWebhookEvent(
    parseRawBody(
      options.rawBody,
    ),
  );
}

function createWebhookSignature(
  secret: string,
  timestamp: string,
  rawBody: string | Uint8Array,
): Buffer {
  const hmac =
    createHmac(
      "sha256",
      secret,
    );

  hmac.update(timestamp);
  hmac.update(".");

  if (typeof rawBody === "string") {
    hmac.update(
      rawBody,
      "utf8",
    );
  } else {
    hmac.update(rawBody);
  }

  return hmac.digest();
}

function parseRawBody(
  rawBody: string | Uint8Array,
): unknown {
  const text =
    typeof rawBody === "string"
      ? rawBody
      : new TextDecoder().decode(
          rawBody,
        );

  try {
    return JSON.parse(text) as unknown;
  } catch (cause) {
    throw new AquariWebhookPayloadError(
      "Aquari webhook body is not valid JSON.",
      {
        cause,
      },
    );
  }
}

function parseWebhookEvent(
  value: unknown,
): AquariWebhookEvent {
  const raw =
    asRecord(
      value,
      "webhook envelope",
    );

  const dataEnvelope =
    asRecord(
      raw["data"],
      "webhook data envelope",
    );

  const payload =
    dataEnvelope["object"];

  const type =
    asNonEmptyString(
      raw["type"],
      "webhook event type",
    );

  const base:
    AquariWebhookEnvelope = {
      id:
        asNonEmptyString(
          raw["id"],
          "webhook event id",
        ),
      type,
      version:
        asNonEmptyString(
          raw["version"],
          "webhook event version",
        ),
      createdAt:
        asIsoDateString(
          raw["created_at"],
          "webhook created_at",
        ),
      organizationId:
        asNonEmptyString(
          raw["organization_id"],
          "webhook organization id",
        ),
      applicationId:
        asNonEmptyString(
          raw["application_id"],
          "webhook application id",
        ),
      environmentId:
        asNonEmptyString(
          raw["environment_id"],
          "webhook environment id",
        ),
      data: payload,
      raw,
      known:
        KNOWN_EVENT_TYPES.has(type),
    };

  switch (type) {
    case "webhook.test":
      return {
        ...base,
        type,
        data:
          asRecord(
            payload,
            "webhook.test payload",
          ),
      };

    case "application.connection.created":
      return {
        ...base,
        type,
        data:
          parseConnectionCreated(
            payload,
          ),
      };

    case "application.connection.revoked":
      return {
        ...base,
        type,
        data:
          parseConnectionRevoked(
            payload,
          ),
      };

    case "application.updated":
      return {
        ...base,
        type,
        data:
          parseApplicationUpdated(
            payload,
          ),
      };

    case "organization.member.added":
      return {
        ...base,
        type,
        data:
          parseMemberAdded(
            payload,
          ),
      };

    case "organization.member.updated":
      return {
        ...base,
        type,
        data:
          parseMemberUpdated(
            payload,
          ),
      };

    case "organization.member.removed":
      return {
        ...base,
        type,
        data:
          parseMemberRemoved(
            payload,
          ),
      };

    case "organization.ownership.transferred":
      return {
        ...base,
        type,
        data:
          parseOwnershipTransferred(
            payload,
          ),
      };

    case "organization.domain.verified":
      return {
        ...base,
        type,
        data:
          parseDomainVerified(
            payload,
          ),
      };

    case "organization.domain.revoked":
      return {
        ...base,
        type,
        data:
          parseDomainRevoked(
            payload,
          ),
      };

    case "passport.visibility.updated":
      return {
        ...base,
        type,
        data:
          parsePassportVisibility(
            payload,
          ),
      };

    case "passport.signal.visibility.updated":
      return {
        ...base,
        type,
        data:
          parseSignalVisibility(
            payload,
          ),
      };

    default:
      return base;
  }
}

function parseConnectionCreated(
  value: unknown,
): AquariApplicationConnectionCreatedData {
  const record =
    asRecord(
      value,
      "application connection created payload",
    );

  return {
    userId:
      asNonEmptyString(
        record["userId"],
        "connection user id",
      ),
    oAuthClientId:
      asNonEmptyString(
        record["oAuthClientId"],
        "connection OAuth client id",
      ),
    scopes:
      asStringArray(
        record["scopes"],
        "connection scopes",
      ),
    connectedAt:
      asIsoDateString(
        record["connectedAt"],
        "connection connectedAt",
      ),
  };
}

function parseConnectionRevoked(
  value: unknown,
): AquariApplicationConnectionRevokedData {
  const record =
    asRecord(
      value,
      "application connection revoked payload",
    );

  return {
    userId:
      asNonEmptyString(
        record["userId"],
        "revoked connection user id",
      ),
    oAuthClientIds:
      asStringArray(
        record["oAuthClientIds"],
        "revoked OAuth client ids",
      ),
    scopes:
      asStringArray(
        record["scopes"],
        "revoked scopes",
      ),
    revokedAt:
      asIsoDateString(
        record["revokedAt"],
        "connection revokedAt",
      ),
  };
}

function parseApplicationUpdated(
  value: unknown,
): AquariApplicationUpdatedData {
  const record =
    asRecord(
      value,
      "application updated payload",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "application id",
      ),
    organizationId:
      asNonEmptyString(
        record["organizationId"],
        "application organization id",
      ),
    name:
      asNonEmptyString(
        record["name"],
        "application name",
      ),
    slug:
      asNonEmptyString(
        record["slug"],
        "application slug",
      ),
    ...optionalProperty(
      "description",
      asOptionalString(
        record["description"],
        "application description",
      ),
    ),
    ...optionalProperty(
      "logoUrl",
      asOptionalString(
        record["logoUrl"],
        "application logo URL",
      ),
    ),
    ...optionalProperty(
      "homepageUrl",
      asOptionalString(
        record["homepageUrl"],
        "application homepage URL",
      ),
    ),
    ...optionalProperty(
      "privacyPolicyUrl",
      asOptionalString(
        record["privacyPolicyUrl"],
        "application privacy policy URL",
      ),
    ),
    ...optionalProperty(
      "termsOfServiceUrl",
      asOptionalString(
        record["termsOfServiceUrl"],
        "application terms URL",
      ),
    ),
    ...optionalProperty(
      "supportUrl",
      asOptionalString(
        record["supportUrl"],
        "application support URL",
      ),
    ),
    ...optionalProperty(
      "supportEmail",
      asOptionalString(
        record["supportEmail"],
        "application support email",
      ),
    ),
    status:
      asNonEmptyString(
        record["status"],
        "application status",
      ),
    ...optionalProperty(
      "updatedAt",
      asOptionalIsoDateString(
        record["updatedAt"],
        "application updatedAt",
      ),
    ),
  };
}

function parseMemberAdded(
  value: unknown,
): AquariOrganizationMemberAddedData {
  const record =
    asRecord(
      value,
      "organization member added payload",
    );

  return {
    memberId:
      asNonEmptyString(
        record["memberId"],
        "member id",
      ),
    userId:
      asNonEmptyString(
        record["userId"],
        "member user id",
      ),
    role:
      asNonEmptyString(
        record["role"],
        "member role",
      ),
    joinedAt:
      asIsoDateString(
        record["joinedAt"],
        "member joinedAt",
      ),
  };
}

function parseMemberUpdated(
  value: unknown,
): AquariOrganizationMemberUpdatedData {
  const record =
    asRecord(
      value,
      "organization member updated payload",
    );

  const permissions =
    record["applicationPermissions"];

  return {
    memberId:
      asNonEmptyString(
        record["memberId"],
        "member id",
      ),
    userId:
      asNonEmptyString(
        record["userId"],
        "member user id",
      ),
    role:
      asNonEmptyString(
        record["role"],
        "member role",
      ),
    ...optionalProperty(
      "applicationId",
      asOptionalString(
        record["applicationId"],
        "member application id",
      ),
    ),
    ...(permissions !== undefined &&
      permissions !== null
      ? {
          applicationPermissions:
            asStringArray(
              permissions,
              "member application permissions",
            ),
        }
      : {}),
    updatedAt:
      asIsoDateString(
        record["updatedAt"],
        "member updatedAt",
      ),
  };
}

function parseMemberRemoved(
  value: unknown,
): AquariOrganizationMemberRemovedData {
  const record =
    asRecord(
      value,
      "organization member removed payload",
    );

  return {
    memberId:
      asNonEmptyString(
        record["memberId"],
        "removed member id",
      ),
    userId:
      asNonEmptyString(
        record["userId"],
        "removed member user id",
      ),
    previousRole:
      asNonEmptyString(
        record["previousRole"],
        "removed member previous role",
      ),
    removedAt:
      asIsoDateString(
        record["removedAt"],
        "member removedAt",
      ),
  };
}

function parseOwnershipTransferred(
  value: unknown,
): AquariOrganizationOwnershipTransferredData {
  const record =
    asRecord(
      value,
      "organization ownership transferred payload",
    );

  return {
    previousOwnerMemberId:
      asNonEmptyString(
        record["previousOwnerMemberId"],
        "previous owner member id",
      ),
    previousOwnerUserId:
      asNonEmptyString(
        record["previousOwnerUserId"],
        "previous owner user id",
      ),
    newOwnerMemberId:
      asNonEmptyString(
        record["newOwnerMemberId"],
        "new owner member id",
      ),
    newOwnerUserId:
      asNonEmptyString(
        record["newOwnerUserId"],
        "new owner user id",
      ),
    transferredAt:
      asIsoDateString(
        record["transferredAt"],
        "ownership transferredAt",
      ),
  };
}

function parseDomainVerified(
  value: unknown,
): AquariOrganizationDomainVerifiedData {
  const record =
    asRecord(
      value,
      "organization domain verified payload",
    );

  return {
    domainClaimId:
      asNonEmptyString(
        record["domainClaimId"],
        "domain claim id",
      ),
    domain:
      asNonEmptyString(
        record["domain"],
        "verified domain",
      ),
    verifiedAt:
      asIsoDateString(
        record["verifiedAt"],
        "domain verifiedAt",
      ),
    expiresAt:
      asIsoDateString(
        record["expiresAt"],
        "domain expiresAt",
      ),
  };
}

function parseDomainRevoked(
  value: unknown,
): AquariOrganizationDomainRevokedData {
  const record =
    asRecord(
      value,
      "organization domain revoked payload",
    );

  return {
    domainClaimId:
      asNonEmptyString(
        record["domainClaimId"],
        "domain claim id",
      ),
    domain:
      asNonEmptyString(
        record["domain"],
        "revoked domain",
      ),
    revokedAt:
      asIsoDateString(
        record["revokedAt"],
        "domain revokedAt",
      ),
  };
}

function parsePassportVisibility(
  value: unknown,
): AquariPassportVisibilityUpdatedData {
  const record =
    asRecord(
      value,
      "Passport visibility payload",
    );

  return {
    userId:
      asNonEmptyString(
        record["userId"],
        "Passport visibility user id",
      ),
    visibility:
      asNonEmptyString(
        record["visibility"],
        "Passport visibility",
      ),
    updatedAt:
      asIsoDateString(
        record["updatedAt"],
        "Passport visibility updatedAt",
      ),
  };
}

function parseSignalVisibility(
  value: unknown,
): AquariPassportSignalVisibilityUpdatedData {
  const record =
    asRecord(
      value,
      "Passport signal visibility payload",
    );

  return {
    userId:
      asNonEmptyString(
        record["userId"],
        "Passport signal visibility user id",
      ),
    sourceType:
      asNonEmptyString(
        record["sourceType"],
        "Passport signal source type",
      ),
    sourceId:
      asNonEmptyString(
        record["sourceId"],
        "Passport signal source id",
      ),
    visibility:
      asNonEmptyString(
        record["visibility"],
        "Passport signal visibility",
      ),
    updatedAt:
      asIsoDateString(
        record["updatedAt"],
        "Passport signal visibility updatedAt",
      ),
  };
}

function readHeader(
  headers: AquariWebhookHeaders,
  name: string,
): string | undefined {
  if (headers instanceof Headers) {
    const value =
      headers.get(name);

    return value ?? undefined;
  }

  const expected =
    name.toLowerCase();

  for (
    const [key, rawValue]
    of Object.entries(headers)
  ) {
    if (
      key.toLowerCase() !==
      expected ||
      rawValue === undefined
    ) {
      continue;
    }

    if (typeof rawValue === "string") {
      return rawValue;
    }

    return rawValue.join(",");
  }

  return undefined;
}

function validateSecret(
  value: string,
): string {
  if (
    value.length === 0 ||
    value !== value.trim()
  ) {
    throw new TypeError(
      "Aquari webhook secret must be a non-empty value without surrounding whitespace.",
    );
  }

  return value;
}

function verificationError(
  reason:
    AquariWebhookVerificationFailure,
  message: string,
): AquariWebhookVerificationError {
  return new AquariWebhookVerificationError({
    reason,
    message,
  });
}
