import type {
  AquariHttpTransport,
} from "@aquari-one/sdk";

import {
  asArray,
  asBoolean,
  asInteger,
  asIsoDateString,
  asNonEmptyString,
  asOptionalIsoDateString,
  asOptionalString,
  asRecord,
  optionalProperty,
} from "./wire.js";

import type {
  AquariBadgeIssueInput,
  AquariBadgeIssueResult,
  AquariBadgeSignal,
  AquariCredentialEvidence,
  AquariCredentialEvidenceInput,
  AquariCredentialIssueInput,
  AquariCredentialIssueResult,
  AquariCredentialSignal,
  AquariCredentialUpdateInput,
  AquariEntitlementIssueInput,
  AquariEntitlementIssueResult,
  AquariEntitlementPlan,
  AquariEntitlementSignal,
  AquariEntitlementUpdateInput,
  AquariIssueOptions,
  AquariIssuerIdentity,
  AquariMembershipIssueInput,
  AquariMembershipIssueResult,
  AquariMembershipRole,
  AquariMembershipSignal,
  AquariMembershipUpdateInput,
  AquariServerRequestOptions,
  AquariStampIssueInput,
  AquariStampIssueResult,
  AquariStampSignal,
} from "./models.js";

interface AuthenticatedTransport {
  transport: AquariHttpTransport;
  headers(): Readonly<Record<string, string>>;
}

/**
 * Groups trusted-server issuer clients for badges, credentials, entitlements, memberships,
 * and stamps.
 */
export class AquariIssuerClient {
  /**
   * Gets badge issuer operations.
   */
  public readonly badges:
    AquariBadgeIssuerClient;

  /**
   * Gets credential issuer operations.
   */
  public readonly credentials:
    AquariCredentialIssuerClient;

  /**
   * Gets entitlement issuer operations.
   */
  public readonly entitlements:
    AquariEntitlementIssuerClient;

  /**
   * Gets membership issuer operations.
   */
  public readonly memberships:
    AquariMembershipIssuerClient;

  /**
   * Gets stamp issuer operations.
   */
  public readonly stamps:
    AquariStampIssuerClient;

  /**
   * Creates the issuer-family clients from the authenticated transport owned by
   * AquariServerClient. Applications normally obtain this client from
   * AquariServerClient.issuer.
   */
  public constructor(
    authenticated:
      AuthenticatedTransport,
  ) {
    this.badges =
      new AquariBadgeIssuerClient(
        authenticated,
      );
    this.credentials =
      new AquariCredentialIssuerClient(
        authenticated,
      );
    this.entitlements =
      new AquariEntitlementIssuerClient(
        authenticated,
      );
    this.memberships =
      new AquariMembershipIssuerClient(
        authenticated,
      );
    this.stamps =
      new AquariStampIssuerClient(
        authenticated,
      );
  }
}

/**
 * Issues, reads, and revokes badge signals from a trusted server.
 */
export class AquariBadgeIssuerClient {
  readonly #authenticated:
    AuthenticatedTransport;

  /**
   * Creates a badge issuer client from the authenticated server transport. Applications
   * normally obtain this client from AquariServerClient.issuer.badges.
   */
  public constructor(
    authenticated:
      AuthenticatedTransport,
  ) {
    this.#authenticated =
      authenticated;
  }

  /**
   * Creates a new issuer signal for the supplied definition and subject. This operation
   * requires a trusted-server machine credential with the matching issuer scope.
   */
  public async issue(
    definitionId: string,
    input: AquariBadgeIssueInput,
    options: AquariIssueOptions = {},
  ): Promise<AquariBadgeIssueResult> {
    const value =
      await issueRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/badge-definitions/${encodeId(definitionId, "definitionId")}/signals`,
        {
          subjectId:
            requiredValue(
              input.subjectId,
              "subjectId",
            ),
        },
        options,
      );

    return parseBadgeIssue(
      value,
    );
  }

  /**
   * Reads the current issuer signal by identifier. This operation requires the matching
   * trusted-server issuer scope.
   */
  public async get(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariBadgeSignal> {
    const value =
      await getRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/badge-signals/${encodeId(signalId, "signalId")}`,
        options,
      );

    return parseBadgeSignal(
      value,
    );
  }

  /**
   * Revokes an existing issuer signal. The signal remains part of its lifecycle history but
   * is no longer active.
   */
  public async revoke(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariBadgeSignal> {
    const value =
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/badge-signals/${encodeId(signalId, "signalId")}/revoke`,
        "POST",
        undefined,
        options,
      );

    return parseBadgeSignal(
      value,
    );
  }
}

/**
 * Issues, reads, updates, expires, and revokes credential signals from a trusted server.
 */
export class AquariCredentialIssuerClient {
  readonly #authenticated:
    AuthenticatedTransport;

  /**
   * Creates a credential issuer client from the authenticated server transport. Applications
   * normally obtain this client from AquariServerClient.issuer.credentials.
   */
  public constructor(
    authenticated:
      AuthenticatedTransport,
  ) {
    this.#authenticated =
      authenticated;
  }

  /**
   * Creates a new issuer signal for the supplied definition and subject. This operation
   * requires a trusted-server machine credential with the matching issuer scope.
   */
  public async issue(
    definitionId: string,
    input:
      AquariCredentialIssueInput,
    options: AquariIssueOptions = {},
  ): Promise<AquariCredentialIssueResult> {
    const value =
      await issueRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/credential-definitions/${encodeId(definitionId, "definitionId")}/signals`,
        credentialBody(input),
        options,
      );

    return parseCredentialIssue(
      value,
    );
  }

  /**
   * Reads the current issuer signal by identifier. This operation requires the matching
   * trusted-server issuer scope.
   */
  public async get(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariCredentialSignal> {
    return parseCredentialSignal(
      await getRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/credential-signals/${encodeId(signalId, "signalId")}`,
        options,
      ),
    );
  }

  /**
   * Updates the mutable state of an existing issuer signal. This operation requires a
   * trusted-server machine credential with the matching issuer scope.
   */
  public async update(
    signalId: string,
    input:
      AquariCredentialUpdateInput,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariCredentialSignal> {
    return parseCredentialSignal(
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/credential-signals/${encodeId(signalId, "signalId")}`,
        "PATCH",
        credentialBody(input),
        options,
      ),
    );
  }

  /**
   * Expires an existing issuer signal. The signal remains part of its lifecycle history but
   * is no longer active.
   */
  public async expire(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariCredentialSignal> {
    return parseCredentialSignal(
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/credential-signals/${encodeId(signalId, "signalId")}/expire`,
        "POST",
        undefined,
        options,
      ),
    );
  }

  /**
   * Revokes an existing issuer signal. The signal remains part of its lifecycle history but
   * is no longer active.
   */
  public async revoke(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariCredentialSignal> {
    return parseCredentialSignal(
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/credential-signals/${encodeId(signalId, "signalId")}/revoke`,
        "POST",
        undefined,
        options,
      ),
    );
  }
}

/**
 * Issues, reads, updates, expires, and revokes entitlement signals from a trusted server.
 */
export class AquariEntitlementIssuerClient {
  readonly #authenticated:
    AuthenticatedTransport;

  /**
   * Creates an entitlement issuer client from the authenticated server transport.
   * Applications normally obtain this client from AquariServerClient.issuer.entitlements.
   */
  public constructor(
    authenticated:
      AuthenticatedTransport,
  ) {
    this.#authenticated =
      authenticated;
  }

  /**
   * Creates a new issuer signal for the supplied definition and subject. This operation
   * requires a trusted-server machine credential with the matching issuer scope.
   */
  public async issue(
    definitionId: string,
    input:
      AquariEntitlementIssueInput,
    options: AquariIssueOptions = {},
  ): Promise<AquariEntitlementIssueResult> {
    const value =
      await issueRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/entitlement-definitions/${encodeId(definitionId, "definitionId")}/signals`,
        entitlementBody(input),
        options,
      );

    return parseEntitlementIssue(
      value,
    );
  }

  /**
   * Reads the current issuer signal by identifier. This operation requires the matching
   * trusted-server issuer scope.
   */
  public async get(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariEntitlementSignal> {
    return parseEntitlementSignal(
      await getRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/entitlement-signals/${encodeId(signalId, "signalId")}`,
        options,
      ),
    );
  }

  /**
   * Updates the mutable state of an existing issuer signal. This operation requires a
   * trusted-server machine credential with the matching issuer scope.
   */
  public async update(
    signalId: string,
    input:
      AquariEntitlementUpdateInput,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariEntitlementSignal> {
    return parseEntitlementSignal(
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/entitlement-signals/${encodeId(signalId, "signalId")}`,
        "PATCH",
        entitlementBody(input),
        options,
      ),
    );
  }

  /**
   * Expires an existing issuer signal. The signal remains part of its lifecycle history but
   * is no longer active.
   */
  public async expire(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariEntitlementSignal> {
    return parseEntitlementSignal(
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/entitlement-signals/${encodeId(signalId, "signalId")}/expire`,
        "POST",
        undefined,
        options,
      ),
    );
  }

  /**
   * Revokes an existing issuer signal. The signal remains part of its lifecycle history but
   * is no longer active.
   */
  public async revoke(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariEntitlementSignal> {
    return parseEntitlementSignal(
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/entitlement-signals/${encodeId(signalId, "signalId")}/revoke`,
        "POST",
        undefined,
        options,
      ),
    );
  }
}

/**
 * Issues, reads, updates, and revokes membership signals from a trusted server.
 */
export class AquariMembershipIssuerClient {
  readonly #authenticated:
    AuthenticatedTransport;

  /**
   * Creates a membership issuer client from the authenticated server transport. Applications
   * normally obtain this client from AquariServerClient.issuer.memberships.
   */
  public constructor(
    authenticated:
      AuthenticatedTransport,
  ) {
    this.#authenticated =
      authenticated;
  }

  /**
   * Creates a new issuer signal for the supplied definition and subject. This operation
   * requires a trusted-server machine credential with the matching issuer scope.
   */
  public async issue(
    input:
      AquariMembershipIssueInput,
    options: AquariIssueOptions = {},
  ): Promise<AquariMembershipIssueResult> {
    const value =
      await issueRequest(
        this.#authenticated,
        "/api/v1/machine/issuer/memberships",
        {
          subjectId:
            requiredValue(
              input.subjectId,
              "subjectId",
            ),
          ...(input.roleId !== undefined
            ? {
                roleId:
                  requiredValue(
                    input.roleId,
                    "roleId",
                  ),
              }
            : {}),
        },
        options,
      );

    return parseMembershipIssue(
      value,
    );
  }

  /**
   * Reads the current issuer signal by identifier. This operation requires the matching
   * trusted-server issuer scope.
   */
  public async get(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariMembershipSignal> {
    return parseMembershipSignal(
      await getRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/membership-signals/${encodeId(signalId, "signalId")}`,
        options,
      ),
    );
  }

  /**
   * Updates the mutable state of an existing issuer signal. This operation requires a
   * trusted-server machine credential with the matching issuer scope.
   */
  public async update(
    signalId: string,
    input:
      AquariMembershipUpdateInput,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariMembershipSignal> {
    return parseMembershipSignal(
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/membership-signals/${encodeId(signalId, "signalId")}`,
        "PATCH",
        {
          roleId:
            input.roleId === undefined ||
            input.roleId === null
              ? null
              : requiredValue(
                  input.roleId,
                  "roleId",
                ),
        },
        options,
      ),
    );
  }

  /**
   * Revokes an existing issuer signal. The signal remains part of its lifecycle history but
   * is no longer active.
   */
  public async revoke(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariMembershipSignal> {
    return parseMembershipSignal(
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/membership-signals/${encodeId(signalId, "signalId")}/revoke`,
        "POST",
        undefined,
        options,
      ),
    );
  }
}

/**
 * Issues, reads, and revokes stamp signals from a trusted server.
 */
export class AquariStampIssuerClient {
  readonly #authenticated:
    AuthenticatedTransport;

  /**
   * Creates a stamp issuer client from the authenticated server transport. Applications
   * normally obtain this client from AquariServerClient.issuer.stamps.
   */
  public constructor(
    authenticated:
      AuthenticatedTransport,
  ) {
    this.#authenticated =
      authenticated;
  }

  /**
   * Creates a new issuer signal for the supplied definition and subject. This operation
   * requires a trusted-server machine credential with the matching issuer scope.
   */
  public async issue(
    definitionId: string,
    input:
      AquariStampIssueInput,
    options: AquariIssueOptions = {},
  ): Promise<AquariStampIssueResult> {
    const value =
      await issueRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/stamp-definitions/${encodeId(definitionId, "definitionId")}/signals`,
        {
          subjectId:
            requiredValue(
              input.subjectId,
              "subjectId",
            ),
          scopeType:
            requiredValue(
              input.scopeType,
              "scopeType",
            ),
          scopeId:
            requiredValue(
              input.scopeId,
              "scopeId",
            ),
          occurredAt:
            validateDate(
              input.occurredAt,
              "occurredAt",
            ),
        },
        options,
      );

    return parseStampIssue(
      value,
    );
  }

  /**
   * Reads the current issuer signal by identifier. This operation requires the matching
   * trusted-server issuer scope.
   */
  public async get(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariStampSignal> {
    return parseStampSignal(
      await getRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/stamp-signals/${encodeId(signalId, "signalId")}`,
        options,
      ),
    );
  }

  /**
   * Revokes an existing issuer signal. The signal remains part of its lifecycle history but
   * is no longer active.
   */
  public async revoke(
    signalId: string,
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariStampSignal> {
    return parseStampSignal(
      await mutationRequest(
        this.#authenticated,
        `/api/v1/machine/issuer/stamp-signals/${encodeId(signalId, "signalId")}/revoke`,
        "POST",
        undefined,
        options,
      ),
    );
  }
}

async function getRequest(
  authenticated:
    AuthenticatedTransport,
  path: string,
  options:
    AquariServerRequestOptions,
): Promise<unknown> {
  return authenticated.transport
    .request<unknown>({
      path,
      method: "GET",
      headers:
        authenticated.headers(),
      ...(options.signal !== undefined
        ? { signal: options.signal }
        : {}),
    });
}

async function issueRequest(
  authenticated:
    AuthenticatedTransport,
  path: string,
  json: unknown,
  options:
    AquariIssueOptions,
): Promise<unknown> {
  const idempotencyKey =
    resolveIdempotencyKey(
      options.idempotencyKey,
    );

  return authenticated.transport
    .request<unknown>({
      path,
      method: "POST",
      headers: {
        ...authenticated.headers(),
        "idempotency-key":
          idempotencyKey,
      },
      json,
      retry: "idempotent",
      ...(options.signal !== undefined
        ? { signal: options.signal }
        : {}),
    });
}

async function mutationRequest(
  authenticated:
    AuthenticatedTransport,
  path: string,
  method: "PATCH" | "POST",
  json: unknown,
  options:
    AquariServerRequestOptions,
): Promise<unknown> {
  return authenticated.transport
    .request<unknown>({
      path,
      method,
      headers:
        authenticated.headers(),
      ...(json !== undefined
        ? { json }
        : {}),
      retry: "never",
      ...(options.signal !== undefined
        ? { signal: options.signal }
        : {}),
    });
}

function resolveIdempotencyKey(
  value: string | undefined,
): string {
  const resolved =
    value ??
    globalThis.crypto.randomUUID();

  if (
    resolved.length === 0 ||
    resolved.length > 200 ||
    resolved !== resolved.trim()
  ) {
    throw new TypeError(
      "Aquari idempotencyKey must be 1 through 200 characters without surrounding whitespace.",
    );
  }

  return resolved;
}

function encodeId(
  value: string,
  label: string,
): string {
  return encodeURIComponent(
    requiredValue(
      value,
      label,
    ),
  );
}

function requiredValue(
  value: string,
  label: string,
): string {
  if (
    value.length === 0 ||
    value !== value.trim()
  ) {
    throw new TypeError(
      `Aquari ${label} must be a non-empty value without surrounding whitespace.`,
    );
  }

  return value;
}

function validateDate(
  value: string,
  label: string,
): string {
  requiredValue(value, label);

  if (
    Number.isNaN(
      Date.parse(value),
    )
  ) {
    throw new TypeError(
      `Aquari ${label} must be an ISO date/time string.`,
    );
  }

  return value;
}

function credentialBody(
  input:
    AquariCredentialIssueInput |
    AquariCredentialUpdateInput,
): Readonly<Record<string, unknown>> {
  return {
    ...(hasSubjectId(input)
      ? {
          subjectId:
            requiredValue(
              input.subjectId,
              "subjectId",
            ),
        }
      : {}),
    ...(input.expiresAt !== undefined
      ? {
          expiresAt:
            validateDate(
              input.expiresAt,
              "expiresAt",
            ),
        }
      : {
          expiresAt: null,
        }),
    ...(input.evidence !== undefined
      ? {
          evidence:
            input.evidence.map(
              mapEvidenceInput,
            ),
        }
      : {
          evidence: null,
        }),
  };
}

function entitlementBody(
  input:
    AquariEntitlementIssueInput |
    AquariEntitlementUpdateInput,
): Readonly<Record<string, unknown>> {
  return {
    ...(hasSubjectId(input)
      ? {
          subjectId:
            requiredValue(
              input.subjectId,
              "subjectId",
            ),
        }
      : {}),
    ...(input.planId !== undefined
      ? {
          planId:
            requiredValue(
              input.planId,
              "planId",
            ),
        }
      : {
          planId: null,
        }),
    ...(input.status !== undefined
      ? {
          status:
            requiredValue(
              input.status,
              "status",
            ),
        }
      : {
          status: null,
        }),
    ...(input.startsAt !== undefined
      ? {
          startsAt:
            validateDate(
              input.startsAt,
              "startsAt",
            ),
        }
      : {
          startsAt: null,
        }),
    ...(input.expiresAt !== undefined
      ? {
          expiresAt:
            validateDate(
              input.expiresAt,
              "expiresAt",
            ),
        }
      : {
          expiresAt: null,
        }),
  };
}

function hasSubjectId(
  input: object,
): input is object & {
  subjectId: string;
} {
  return "subjectId" in input;
}

function mapEvidenceInput(
  item:
    AquariCredentialEvidenceInput,
): Readonly<Record<string, string>> {
  return {
    type:
      requiredValue(
        item.type,
        "evidence.type",
      ),
    reference:
      requiredValue(
        item.reference,
        "evidence.reference",
      ),
    verifiedAt:
      validateDate(
        item.verifiedAt,
        "evidence.verifiedAt",
      ),
  };
}

function parseIssuer(
  value: unknown,
): AquariIssuerIdentity {
  const record =
    asRecord(
      value,
      "issuer identity",
    );

  return {
    type:
      asNonEmptyString(
        record["type"],
        "issuer type",
      ),
    id:
      asNonEmptyString(
        record["id"],
        "issuer id",
      ),
    name:
      asNonEmptyString(
        record["name"],
        "issuer name",
      ),
    ...optionalProperty(
      "logoUrl",
      asOptionalString(
        record["logoUrl"],
        "issuer logo URL",
      ),
    ),
  };
}

function parseBadgeIssue(
  value: unknown,
): AquariBadgeIssueResult {
  const record =
    asRecord(
      value,
      "badge issue response",
    );

  return {
    signal:
      parseBadgeSignal(
        record["signal"],
      ),
    idempotentReplay:
      asBoolean(
        record["idempotentReplay"],
        "badge idempotentReplay",
      ),
  };
}

function parseBadgeSignal(
  value: unknown,
): AquariBadgeSignal {
  const record =
    asRecord(
      value,
      "badge signal",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "badge signal id",
      ),
    definitionId:
      asNonEmptyString(
        record["definitionId"],
        "badge definition id",
      ),
    subjectId:
      asNonEmptyString(
        record["subjectId"],
        "badge subject id",
      ),
    issuer:
      parseIssuer(
        record["issuer"],
      ),
    name:
      asNonEmptyString(
        record["name"],
        "badge name",
      ),
    ...optionalProperty(
      "description",
      asOptionalString(
        record["description"],
        "badge description",
      ),
    ),
    ...optionalProperty(
      "criteria",
      asOptionalString(
        record["criteria"],
        "badge criteria",
      ),
    ),
    ...optionalProperty(
      "imageUrl",
      asOptionalString(
        record["imageUrl"],
        "badge image URL",
      ),
    ),
    defaultVisibility:
      asNonEmptyString(
        record["defaultVisibility"],
        "badge default visibility",
      ),
    status:
      asNonEmptyString(
        record["status"],
        "badge status",
      ),
    issuedAt:
      asIsoDateString(
        record["issuedAt"],
        "badge issuedAt",
      ),
    ...optionalProperty(
      "revokedAt",
      asOptionalIsoDateString(
        record["revokedAt"],
        "badge revokedAt",
      ),
    ),
  };
}

function parseCredentialIssue(
  value: unknown,
): AquariCredentialIssueResult {
  const record =
    asRecord(
      value,
      "credential issue response",
    );

  return {
    signal:
      parseCredentialSignal(
        record["signal"],
      ),
    idempotentReplay:
      asBoolean(
        record["idempotentReplay"],
        "credential idempotentReplay",
      ),
  };
}

function parseCredentialSignal(
  value: unknown,
): AquariCredentialSignal {
  const record =
    asRecord(
      value,
      "credential signal",
    );

  const source =
    asArray(
      record["evidence"],
      "credential evidence",
    );

  const evidence:
    AquariCredentialEvidence[] =
    [];

  for (const item of source) {
    evidence.push(
      parseEvidence(item),
    );
  }

  return {
    id:
      asNonEmptyString(
        record["id"],
        "credential signal id",
      ),
    definitionId:
      asNonEmptyString(
        record["definitionId"],
        "credential definition id",
      ),
    subjectId:
      asNonEmptyString(
        record["subjectId"],
        "credential subject id",
      ),
    issuer:
      parseIssuer(
        record["issuer"],
      ),
    key:
      asNonEmptyString(
        record["key"],
        "credential key",
      ),
    name:
      asNonEmptyString(
        record["name"],
        "credential name",
      ),
    ...optionalProperty(
      "description",
      asOptionalString(
        record["description"],
        "credential description",
      ),
    ),
    assuranceLevel:
      asNonEmptyString(
        record["assuranceLevel"],
        "credential assurance level",
      ),
    verificationMethod:
      asNonEmptyString(
        record["verificationMethod"],
        "credential verification method",
      ),
    defaultVisibility:
      asNonEmptyString(
        record["defaultVisibility"],
        "credential default visibility",
      ),
    status:
      asNonEmptyString(
        record["status"],
        "credential status",
      ),
    effective:
      asBoolean(
        record["effective"],
        "credential effective",
      ),
    issuedAt:
      asIsoDateString(
        record["issuedAt"],
        "credential issuedAt",
      ),
    ...optionalProperty(
      "expiresAt",
      asOptionalIsoDateString(
        record["expiresAt"],
        "credential expiresAt",
      ),
    ),
    ...optionalProperty(
      "revokedAt",
      asOptionalIsoDateString(
        record["revokedAt"],
        "credential revokedAt",
      ),
    ),
    evidence:
      Object.freeze(evidence),
  };
}

function parseEvidence(
  value: unknown,
): AquariCredentialEvidence {
  const record =
    asRecord(
      value,
      "credential evidence",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "credential evidence id",
      ),
    type:
      asNonEmptyString(
        record["type"],
        "credential evidence type",
      ),
    reference:
      asNonEmptyString(
        record["reference"],
        "credential evidence reference",
      ),
    verifiedAt:
      asIsoDateString(
        record["verifiedAt"],
        "credential evidence verifiedAt",
      ),
    createdAt:
      asIsoDateString(
        record["createdAt"],
        "credential evidence createdAt",
      ),
  };
}

function parseEntitlementIssue(
  value: unknown,
): AquariEntitlementIssueResult {
  const record =
    asRecord(
      value,
      "entitlement issue response",
    );

  return {
    signal:
      parseEntitlementSignal(
        record["signal"],
      ),
    idempotentReplay:
      asBoolean(
        record["idempotentReplay"],
        "entitlement idempotentReplay",
      ),
  };
}

function parseEntitlementSignal(
  value: unknown,
): AquariEntitlementSignal {
  const record =
    asRecord(
      value,
      "entitlement signal",
    );

  const plan =
    record["plan"];

  return {
    id:
      asNonEmptyString(
        record["id"],
        "entitlement signal id",
      ),
    definitionId:
      asNonEmptyString(
        record["definitionId"],
        "entitlement definition id",
      ),
    subjectId:
      asNonEmptyString(
        record["subjectId"],
        "entitlement subject id",
      ),
    issuer:
      parseIssuer(
        record["issuer"],
      ),
    name:
      asNonEmptyString(
        record["name"],
        "entitlement name",
      ),
    ...optionalProperty(
      "description",
      asOptionalString(
        record["description"],
        "entitlement description",
      ),
    ),
    ...(plan !== undefined &&
      plan !== null
      ? {
          plan:
            parsePlan(plan),
        }
      : {}),
    source:
      asNonEmptyString(
        record["source"],
        "entitlement source",
      ),
    status:
      asNonEmptyString(
        record["status"],
        "entitlement status",
      ),
    effective:
      asBoolean(
        record["effective"],
        "entitlement effective",
      ),
    startsAt:
      asIsoDateString(
        record["startsAt"],
        "entitlement startsAt",
      ),
    ...optionalProperty(
      "expiresAt",
      asOptionalIsoDateString(
        record["expiresAt"],
        "entitlement expiresAt",
      ),
    ),
    ...optionalProperty(
      "revokedAt",
      asOptionalIsoDateString(
        record["revokedAt"],
        "entitlement revokedAt",
      ),
    ),
  };
}

function parsePlan(
  value: unknown,
): AquariEntitlementPlan {
  const record =
    asRecord(
      value,
      "entitlement plan",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "entitlement plan id",
      ),
    name:
      asNonEmptyString(
        record["name"],
        "entitlement plan name",
      ),
    slug:
      asNonEmptyString(
        record["slug"],
        "entitlement plan slug",
      ),
    billingPeriod:
      asNonEmptyString(
        record["billingPeriod"],
        "entitlement billing period",
      ),
    priceCents:
      asInteger(
        record["priceCents"],
        "entitlement priceCents",
      ),
    currency:
      asNonEmptyString(
        record["currency"],
        "entitlement currency",
      ),
    status:
      asNonEmptyString(
        record["status"],
        "entitlement plan status",
      ),
    createdAt:
      asIsoDateString(
        record["createdAt"],
        "entitlement plan createdAt",
      ),
    ...optionalProperty(
      "updatedAt",
      asOptionalIsoDateString(
        record["updatedAt"],
        "entitlement plan updatedAt",
      ),
    ),
    ...optionalProperty(
      "disabledAt",
      asOptionalIsoDateString(
        record["disabledAt"],
        "entitlement plan disabledAt",
      ),
    ),
  };
}

function parseMembershipIssue(
  value: unknown,
): AquariMembershipIssueResult {
  const record =
    asRecord(
      value,
      "membership issue response",
    );

  return {
    signal:
      parseMembershipSignal(
        record["signal"],
      ),
    idempotentReplay:
      asBoolean(
        record["idempotentReplay"],
        "membership idempotentReplay",
      ),
  };
}

function parseMembershipSignal(
  value: unknown,
): AquariMembershipSignal {
  const record =
    asRecord(
      value,
      "membership signal",
    );

  const role =
    record["roleDefinition"];

  return {
    id:
      asNonEmptyString(
        record["id"],
        "membership signal id",
      ),
    ...optionalProperty(
      "definitionId",
      asOptionalString(
        record["definitionId"],
        "membership definition id",
      ),
    ),
    subjectId:
      asNonEmptyString(
        record["subjectId"],
        "membership subject id",
      ),
    issuer:
      parseIssuer(
        record["issuer"],
      ),
    type:
      asNonEmptyString(
        record["type"],
        "membership type",
      ),
    role:
      asNonEmptyString(
        record["role"],
        "membership role",
      ),
    ...(role !== undefined &&
      role !== null
      ? {
          roleDefinition:
            parseRole(role),
        }
      : {}),
    status:
      asNonEmptyString(
        record["status"],
        "membership status",
      ),
    effective:
      asBoolean(
        record["effective"],
        "membership effective",
      ),
    issuedAt:
      asIsoDateString(
        record["issuedAt"],
        "membership issuedAt",
      ),
    ...optionalProperty(
      "revokedAt",
      asOptionalIsoDateString(
        record["revokedAt"],
        "membership revokedAt",
      ),
    ),
  };
}

function parseRole(
  value: unknown,
): AquariMembershipRole {
  const record =
    asRecord(
      value,
      "membership role definition",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "membership role id",
      ),
    name:
      asNonEmptyString(
        record["name"],
        "membership role name",
      ),
    ...optionalProperty(
      "description",
      asOptionalString(
        record["description"],
        "membership role description",
      ),
    ),
    status:
      asNonEmptyString(
        record["status"],
        "membership role status",
      ),
    createdAt:
      asIsoDateString(
        record["createdAt"],
        "membership role createdAt",
      ),
    ...optionalProperty(
      "updatedAt",
      asOptionalIsoDateString(
        record["updatedAt"],
        "membership role updatedAt",
      ),
    ),
    ...optionalProperty(
      "retiredAt",
      asOptionalIsoDateString(
        record["retiredAt"],
        "membership role retiredAt",
      ),
    ),
  };
}

function parseStampIssue(
  value: unknown,
): AquariStampIssueResult {
  const record =
    asRecord(
      value,
      "stamp issue response",
    );

  return {
    signal:
      parseStampSignal(
        record["signal"],
      ),
    idempotentReplay:
      asBoolean(
        record["idempotentReplay"],
        "stamp idempotentReplay",
      ),
  };
}

function parseStampSignal(
  value: unknown,
): AquariStampSignal {
  const record =
    asRecord(
      value,
      "stamp signal",
    );

  const scope =
    asRecord(
      record["scope"],
      "stamp scope",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "stamp signal id",
      ),
    definitionId:
      asNonEmptyString(
        record["definitionId"],
        "stamp definition id",
      ),
    subjectId:
      asNonEmptyString(
        record["subjectId"],
        "stamp subject id",
      ),
    issuer:
      parseIssuer(
        record["issuer"],
      ),
    key:
      asNonEmptyString(
        record["key"],
        "stamp key",
      ),
    name:
      asNonEmptyString(
        record["name"],
        "stamp name",
      ),
    ...optionalProperty(
      "description",
      asOptionalString(
        record["description"],
        "stamp description",
      ),
    ),
    ...optionalProperty(
      "imageUrl",
      asOptionalString(
        record["imageUrl"],
        "stamp image URL",
      ),
    ),
    scope: {
      type:
        asNonEmptyString(
          scope["type"],
          "stamp scope type",
        ),
      id:
        asNonEmptyString(
          scope["id"],
          "stamp scope id",
        ),
    },
    occurredAt:
      asIsoDateString(
        record["occurredAt"],
        "stamp occurredAt",
      ),
    issuedAt:
      asIsoDateString(
        record["issuedAt"],
        "stamp issuedAt",
      ),
    defaultVisibility:
      asNonEmptyString(
        record["defaultVisibility"],
        "stamp default visibility",
      ),
    status:
      asNonEmptyString(
        record["status"],
        "stamp status",
      ),
    effective:
      asBoolean(
        record["effective"],
        "stamp effective",
      ),
    ...optionalProperty(
      "revokedAt",
      asOptionalIsoDateString(
        record["revokedAt"],
        "stamp revokedAt",
      ),
    ),
  };
}
