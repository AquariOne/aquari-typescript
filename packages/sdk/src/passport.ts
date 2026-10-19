import type {
  AquariHttpTransport,
} from "./transport.js";

import {
  asArray,
  asBoolean,
  asInteger,
  asIsoDateString,
  asNonEmptyString,
  asOptionalIsoDateString,
  asOptionalRecord,
  asOptionalString,
  asRecord,
  asString,
} from "./wire.js";

/**
 * Identifies the Aquari signal family represented by a Passport signal.
 */
export type AquariPassportSignalFamily =
  | "badge"
  | "stamp"
  | "credential"
  | "entitlement"
  | "role"
  | "membership"
  | "unknown";

/**
 * Contains the profile fields exposed by a connected Aquari Passport.
 */
export interface AquariPassportProfile {
  displayName: string;
  handle: string;
  avatarUrl?: string;
  publicUrl: string;
  verified: boolean;
  visibility: string;
}

export interface AquariPassportSignalSummary {
  total: number;
}

/**
 * Represents the connected Passport returned for the authenticated Aquari subject.
 */
export interface AquariPassport {
  id: string;
  passportNumber: string;
  subjectId: string;
  profile: AquariPassportProfile;
  signals: AquariPassportSignalSummary;
}

/**
 * Identifies the resource scope exposed for a public Passport signal.
 */
export interface AquariPublicPassportSignalScope {
  type: string;
  id: string;
}

/**
 * Represents one signal that is visible on a public Aquari Passport.
 */
export interface AquariPublicPassportSignal {
  id: string;
  type: string;
  name: string;
  description: string;
  imageUrl?: string;
  issuer: string;
  issuerLogoUrl?: string;
  issuedAt: string;
  expiresAt?: string;
  verified: boolean;
  occurredAt?: string;
  scope?: AquariPublicPassportSignalScope;
}

/**
 * Represents public Passport data that can be read by handle without an authenticated
 * session.
 */
export interface AquariPublicPassport {
  displayName: string;
  handle: string;
  avatarUrl?: string;
  publicUrl: string;
  verified: boolean;
  signals: readonly AquariPublicPassportSignal[];
}

/**
 * Identifies the issuer that produced a Passport signal.
 */
export interface AquariPassportSignalIssuer {
  type: string;
  id: string;
  name: string;
  logoUrl?: string;
}

/**
 * Identifies the resource scope attached to a Passport signal.
 */
export interface AquariPassportSignalScope {
  type: string;
  id: string;
}

/**
 * Represents one portable signal on an Aquari Passport.
 */
export interface AquariPassportSignal {
  id: string;
  subjectId: string;
  family: AquariPassportSignalFamily;
  sourceType: string;
  definitionId?: string;
  presentationType: string;
  name: string;
  description: string;
  imageUrl?: string;
  issuer: AquariPassportSignalIssuer;
  issuedAt: string;
  expiresAt?: string;
  visibility: string;
  verified: boolean;
  occurredAt?: string;
  scope?: AquariPassportSignalScope;
}

/**
 * Contains one page of Passport signals and cursor pagination state.
 */
export interface AquariPassportSignalPage {
  items: readonly AquariPassportSignal[];
  nextCursor?: string;
  hasMore: boolean;
}

/**
 * Provides an access token and optional cancellation signal for an authenticated Passport
 * request.
 */
export interface AquariAuthenticatedRequestOptions {
  accessToken: string;
  signal?: AbortSignal;
}

/**
 * Configures Passport signal filtering, pagination, and authentication.
 */
export interface AquariPassportSignalsListOptions
  extends AquariAuthenticatedRequestOptions {
  type?: string;
  issuerId?: string;
  definitionId?: string;
  limit?: number;
  cursor?: string;
}

/**
 * Provides authentication and cancellation for a single Passport signal read.
 */
export type AquariPassportSignalGetOptions =
  AquariAuthenticatedRequestOptions;

/**
 * Configures cancellation for a public Passport request.
 */
export interface AquariPublicPassportOptions {
  signal?: AbortSignal;
}

/**
 * Lists and reads signals on the authenticated subject's Passport.
 */
export class AquariPassportSignalsClient {
  readonly #transport:
    AquariHttpTransport;

  /**
   * Creates a Passport signal client that uses the supplied Aquari HTTP transport.
   */
  public constructor(
    transport: AquariHttpTransport,
  ) {
    this.#transport = transport;
  }

  /**
   * Reads one page of Passport signals using the supplied filters and cursor.
   */
  public async list(
    options: AquariPassportSignalsListOptions,
  ): Promise<AquariPassportSignalPage> {
    const params =
      new URLSearchParams();

    if (options.type !== undefined) {
      params.set(
        "type",
        validateFilter(
          options.type,
          "type",
        ),
      );
    }

    if (options.issuerId !== undefined) {
      params.set(
        "issuer_id",
        validateFilter(
          options.issuerId,
          "issuerId",
        ),
      );
    }

    if (
      options.definitionId !==
      undefined
    ) {
      params.set(
        "definition_id",
        validateFilter(
          options.definitionId,
          "definitionId",
        ),
      );
    }

    if (options.limit !== undefined) {
      if (
        !Number.isInteger(options.limit) ||
        options.limit < 1 ||
        options.limit > 100
      ) {
        throw new RangeError(
          "Aquari Passport signal limit must be an integer from 1 through 100.",
        );
      }

      params.set(
        "limit",
        String(options.limit),
      );
    }

    if (options.cursor !== undefined) {
      params.set(
        "cursor",
        validateFilter(
          options.cursor,
          "cursor",
        ),
      );
    }

    const query =
      params.toString();

    const value =
      await this.#transport.request<unknown>({
        path:
          query.length === 0
            ? "/api/v1/passport/signals"
            : `/api/v1/passport/signals?${query}`,
        method: "GET",
        headers:
          bearerHeaders(
            options.accessToken,
          ),
        ...(options.signal !== undefined
          ? { signal: options.signal }
          : {}),
      });

    return parseSignalPage(value);
  }

  /**
   * Reads one Passport signal by identifier for the authenticated subject.
   */
  public async get(
    signalId: string,
    options: AquariPassportSignalGetOptions,
  ): Promise<AquariPassportSignal> {
    const id =
      validatePathValue(
        signalId,
        "signalId",
      );

    const value =
      await this.#transport.request<unknown>({
        path:
          `/api/v1/passport/signals/${encodeURIComponent(id)}`,
        method: "GET",
        headers:
          bearerHeaders(
            options.accessToken,
          ),
        ...(options.signal !== undefined
          ? { signal: options.signal }
          : {}),
      });

    const envelope =
      asRecord(
        value,
        "Passport signal response",
      );

    return parseSignal(
      envelope["signal"],
    );
  }

  public async *iterate(
    options: AquariPassportSignalsListOptions,
  ): AsyncGenerator<
    AquariPassportSignal,
    void,
    undefined
  > {
    let cursor =
      options.cursor;

    for (;;) {
      const page =
        await this.list({
          ...options,
          ...(cursor !== undefined
            ? { cursor }
            : {}),
        });

      for (const item of page.items) {
        yield item;
      }

      if (
        !page.hasMore ||
        page.nextCursor === undefined
      ) {
        return;
      }

      cursor =
        page.nextCursor;
    }
  }
}

/**
 * Reads connected and public Passport data.
 */
export class AquariPassportClient {
  readonly #transport:
    AquariHttpTransport;

  /**
   * Gets Passport signal read operations.
   */
  public readonly signals:
    AquariPassportSignalsClient;

  /**
   * Creates a Passport client and its signal subclient with the supplied Aquari HTTP
   * transport.
   */
  public constructor(
    transport: AquariHttpTransport,
  ) {
    this.#transport = transport;
    this.signals =
      new AquariPassportSignalsClient(
        transport,
      );
  }

  /**
   * Reads the connected Passport for the authenticated subject represented by the supplied
   * access token.
   */
  public async get(
    options: AquariAuthenticatedRequestOptions,
  ): Promise<AquariPassport> {
    const value =
      await this.#transport.request<unknown>({
        path: "/api/v1/passport",
        method: "GET",
        headers:
          bearerHeaders(
            options.accessToken,
          ),
        ...(options.signal !== undefined
          ? { signal: options.signal }
          : {}),
      });

    const envelope =
      asRecord(
        value,
        "Passport response",
      );

    return parsePassport(
      envelope["passport"],
    );
  }

  /**
   * Reads public Passport data for the supplied Aquari handle without using a bearer access
   * token.
   */
  public async getPublic(
    handle: string,
    options:
      AquariPublicPassportOptions = {},
  ): Promise<AquariPublicPassport> {
    const value =
      validatePathValue(
        handle,
        "handle",
      );

    const response =
      await this.#transport.request<unknown>({
        path:
          `/api/v1/public/passports/${encodeURIComponent(value)}`,
        method: "GET",
        ...(options.signal !== undefined
          ? { signal: options.signal }
          : {}),
      });

    return parsePublicPassport(
      response,
    );
  }
}

function bearerHeaders(
  accessToken: string,
): Readonly<Record<string, string>> {
  if (
    accessToken.length === 0 ||
    accessToken !==
      accessToken.trim()
  ) {
    throw new TypeError(
      "Aquari accessToken must be a non-empty value without surrounding whitespace.",
    );
  }

  return {
    authorization:
      `Bearer ${accessToken}`,
  };
}

function validatePathValue(
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

function validateFilter(
  value: string,
  label: string,
): string {
  return validatePathValue(
    value,
    label,
  );
}

function parsePassport(
  value: unknown,
): AquariPassport {
  const record =
    asRecord(
      value,
      "Passport object",
    );

  const profile =
    asRecord(
      record["profile"],
      "Passport profile",
    );

  const signals =
    asRecord(
      record["signals"],
      "Passport signal summary",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "Passport id",
      ),
    passportNumber:
      asNonEmptyString(
        record["passportNumber"],
        "Passport number",
      ),
    subjectId:
      asNonEmptyString(
        record["subjectId"],
        "Passport subject id",
      ),
    profile: {
      displayName:
        asString(
          profile["displayName"],
          "Passport display name",
        ),
      handle:
        asNonEmptyString(
          profile["handle"],
          "Passport handle",
        ),
      ...optionalProperty(
        "avatarUrl",
        asOptionalString(
          profile["avatarUrl"],
          "Passport avatar URL",
        ),
      ),
      publicUrl:
        asNonEmptyString(
          profile["publicUrl"],
          "Passport public URL",
        ),
      verified:
        asBoolean(
          profile["verified"],
          "Passport verified value",
        ),
      visibility:
        asNonEmptyString(
          profile["visibility"],
          "Passport visibility",
        ),
    },
    signals: {
      total:
        asInteger(
          signals["total"],
          "Passport signal total",
        ),
    },
  };
}

function parsePublicPassport(
  value: unknown,
): AquariPublicPassport {
  const record =
    asRecord(
      value,
      "public Passport response",
    );

  const source =
    asArray(
      record["signals"],
      "public Passport signals",
    );

  const signals:
    AquariPublicPassportSignal[] =
    [];

  for (const item of source) {
    signals.push(
      parsePublicSignal(item),
    );
  }

  return {
    displayName:
      asString(
        record["displayName"],
        "public Passport display name",
      ),
    handle:
      asNonEmptyString(
        record["handle"],
        "public Passport handle",
      ),
    ...optionalProperty(
      "avatarUrl",
      asOptionalString(
        record["avatarUrl"],
        "public Passport avatar URL",
      ),
    ),
    publicUrl:
      asNonEmptyString(
        record["publicUrl"],
        "public Passport URL",
      ),
    verified:
      asBoolean(
        record["verified"],
        "public Passport verified value",
      ),
    signals:
      Object.freeze(signals),
  };
}

function parsePublicSignal(
  value: unknown,
): AquariPublicPassportSignal {
  const record =
    asRecord(
      value,
      "public Passport signal",
    );

  const scope =
    asOptionalRecord(
      record["scope"],
      "public Passport signal scope",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "public Passport signal id",
      ),
    type:
      asNonEmptyString(
        record["type"],
        "public Passport signal type",
      ),
    name:
      asNonEmptyString(
        record["name"],
        "public Passport signal name",
      ),
    description:
      asString(
        record["description"],
        "public Passport signal description",
      ),
    ...optionalProperty(
      "imageUrl",
      asOptionalString(
        record["imageUrl"],
        "public Passport signal image URL",
      ),
    ),
    issuer:
      asNonEmptyString(
        record["issuer"],
        "public Passport signal issuer",
      ),
    ...optionalProperty(
      "issuerLogoUrl",
      asOptionalString(
        record["issuerLogoUrl"],
        "public Passport signal issuer logo URL",
      ),
    ),
    issuedAt:
      asIsoDateString(
        record["issuedAt"],
        "public Passport signal issuedAt",
      ),
    ...optionalProperty(
      "expiresAt",
      asOptionalIsoDateString(
        record["expiresAt"],
        "public Passport signal expiresAt",
      ),
    ),
    verified:
      asBoolean(
        record["verified"],
        "public Passport signal verified value",
      ),
    ...optionalProperty(
      "occurredAt",
      asOptionalIsoDateString(
        record["occurredAt"],
        "public Passport signal occurredAt",
      ),
    ),
    ...(scope !== undefined
      ? {
          scope: {
            type:
              asNonEmptyString(
                scope["type"],
                "public Passport signal scope type",
              ),
            id:
              asNonEmptyString(
                scope["id"],
                "public Passport signal scope id",
              ),
          },
        }
      : {}),
  };
}

function parseSignalPage(
  value: unknown,
): AquariPassportSignalPage {
  const record =
    asRecord(
      value,
      "Passport signal page",
    );

  const source =
    asArray(
      record["items"],
      "Passport signal page items",
    );

  const items:
    AquariPassportSignal[] = [];

  for (const item of source) {
    items.push(
      parseSignal(item),
    );
  }

  const page =
    asRecord(
      record["page"],
      "Passport page metadata",
    );

  return {
    items:
      Object.freeze(items),
    ...optionalProperty(
      "nextCursor",
      asOptionalString(
        page["nextCursor"],
        "Passport next cursor",
      ),
    ),
    hasMore:
      asBoolean(
        page["hasMore"],
        "Passport hasMore value",
      ),
  };
}

function parseSignal(
  value: unknown,
): AquariPassportSignal {
  const record =
    asRecord(
      value,
      "Passport signal",
    );

  const issuer =
    asRecord(
      record["issuer"],
      "Passport signal issuer",
    );

  const scope =
    asOptionalRecord(
      record["scope"],
      "Passport signal scope",
    );

  const sourceType =
    asNonEmptyString(
      record["sourceType"],
      "Passport signal sourceType",
    );

  const presentationType =
    asNonEmptyString(
      record["type"],
      "Passport signal type",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "Passport signal id",
      ),
    subjectId:
      asNonEmptyString(
        record["subjectId"],
        "Passport signal subject id",
      ),
    family:
      resolveSignalFamily(
        sourceType,
        presentationType,
      ),
    sourceType,
    ...optionalProperty(
      "definitionId",
      asOptionalString(
        record["definitionId"],
        "Passport signal definition id",
      ),
    ),
    presentationType,
    name:
      asNonEmptyString(
        record["name"],
        "Passport signal name",
      ),
    description:
      asString(
        record["description"],
        "Passport signal description",
      ),
    ...optionalProperty(
      "imageUrl",
      asOptionalString(
        record["imageUrl"],
        "Passport signal image URL",
      ),
    ),
    issuer: {
      type:
        asNonEmptyString(
          issuer["type"],
          "Passport issuer type",
        ),
      id:
        asNonEmptyString(
          issuer["id"],
          "Passport issuer id",
        ),
      name:
        asNonEmptyString(
          issuer["name"],
          "Passport issuer name",
        ),
      ...optionalProperty(
        "logoUrl",
        asOptionalString(
          issuer["logoUrl"],
          "Passport issuer logo URL",
        ),
      ),
    },
    issuedAt:
      asIsoDateString(
        record["issuedAt"],
        "Passport signal issuedAt",
      ),
    ...optionalProperty(
      "expiresAt",
      asOptionalIsoDateString(
        record["expiresAt"],
        "Passport signal expiresAt",
      ),
    ),
    visibility:
      asNonEmptyString(
        record["visibility"],
        "Passport signal visibility",
      ),
    verified:
      asBoolean(
        record["verified"],
        "Passport signal verified value",
      ),
    ...optionalProperty(
      "occurredAt",
      asOptionalIsoDateString(
        record["occurredAt"],
        "Passport signal occurredAt",
      ),
    ),
    ...(scope !== undefined
      ? {
          scope: {
            type:
              asNonEmptyString(
                scope["type"],
                "Passport signal scope type",
              ),
            id:
              asNonEmptyString(
                scope["id"],
                "Passport signal scope id",
              ),
          },
        }
      : {}),
  };
}

function resolveSignalFamily(
  sourceType: string,
  presentationType: string,
): AquariPassportSignalFamily {
  if (
    sourceType === "badge" &&
    presentationType === "badge"
  ) {
    return "badge";
  }

  if (
    sourceType === "passport_stamp" &&
    presentationType === "stamp"
  ) {
    return "stamp";
  }

  if (
    sourceType === "credential" &&
    presentationType === "credential"
  ) {
    return "credential";
  }

  if (
    sourceType === "user_entitlement" &&
    presentationType === "credential"
  ) {
    return "entitlement";
  }

  if (
    sourceType === "app_membership" &&
    presentationType === "role"
  ) {
    return "role";
  }

  if (
    sourceType === "app_membership" &&
    presentationType === "membership"
  ) {
    return "membership";
  }

  return "unknown";
}

function optionalProperty<
  TKey extends string,
  TValue,
>(
  key: TKey,
  value: TValue | undefined,
): Partial<Record<TKey, TValue>> {
  return value === undefined
    ? {}
    : {
        [key]: value,
      } as Record<TKey, TValue>;
}
