/**
 * Maps Aquari validation fields to one or more error messages.
 */
export type AquariErrorDetails =
  Readonly<Record<string, readonly string[]>>;

/**
 * Classifies configuration, transport, timeout, API, and OAuth failures produced by the
 * TypeScript SDK.
 */
export class AquariError extends Error {
  /**
   * Creates the base Aquari SDK error with the supplied message and optional underlying
   * error cause.
   */
  public constructor(
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = new.target.name;
  }
}

/**
 * Reports invalid Aquari SDK configuration.
 */
export class AquariConfigurationError
  extends AquariError {}

/**
 * Defines transport error metadata, including the underlying cause and cancellation state.
 */
export interface AquariTransportErrorOptions
  extends ErrorOptions {
  cancelled?: boolean;
}

/**
 * Reports an HTTP transport, network, cancellation, or response-processing failure.
 */
export class AquariTransportError
  extends AquariError {
  public readonly cancelled: boolean;

  /**
   * Creates a transport error and records whether request cancellation caused the failure.
   */
  public constructor(
    message: string,
    options: AquariTransportErrorOptions = {},
  ) {
    super(message, options);
    this.cancelled = options.cancelled ?? false;
  }
}

/**
 * Reports an Aquari request that exceeded the configured timeout.
 */
export class AquariTimeoutError
  extends AquariTransportError {
  public readonly timeoutMs: number;

  /**
   * Creates a timeout error for the supplied request timeout in milliseconds.
   */
  public constructor(
    timeoutMs: number,
    options?: ErrorOptions,
  ) {
    super(
      `Aquari request timed out after ${String(timeoutMs)}ms.`,
      options,
    );

    this.timeoutMs = timeoutMs;
  }
}

/**
 * Defines metadata used to construct an Aquari API error.
 */
export interface AquariApiErrorOptions {
  status: number;
  code: string | undefined;
  message: string;
  details: AquariErrorDetails | undefined;
}

/**
 * Reports a non-success response returned by an Aquari API endpoint.
 */
export class AquariApiError
  extends AquariError {
  public readonly status: number;

  public readonly code: string | undefined;

  public readonly details:
    AquariErrorDetails | undefined;

  /**
   * Creates a structured Aquari API error from HTTP status, error code, message, and
   * validation details.
   */
  public constructor(
    options: AquariApiErrorOptions,
  ) {
    super(options.message);

    this.status = options.status;
    this.code = options.code;
    this.details = options.details;
  }
}

/**
 * Reports an Aquari API validation failure.
 */
export class AquariValidationError
  extends AquariApiError {
  public get fields(): AquariErrorDetails {
    return this.details ?? {};
  }
}

/**
 * Reports an Aquari API authentication failure.
 */
export class AquariAuthenticationError
  extends AquariApiError {}

/**
 * Reports an Aquari API authorization failure.
 */
export class AquariAuthorizationError
  extends AquariApiError {}

/**
 * Reports an Aquari resource that was not found.
 */
export class AquariNotFoundError
  extends AquariApiError {}

/**
 * Reports an Aquari request that conflicts with current resource state.
 */
export class AquariConflictError
  extends AquariApiError {}

/**
 * Defines rate-limit error metadata, including the optional retry delay.
 */
export interface AquariRateLimitErrorOptions
  extends AquariApiErrorOptions {
  retryAfterMs: number | undefined;
}

/**
 * Reports an Aquari rate-limit response and the optional retry delay.
 */
export class AquariRateLimitError
  extends AquariApiError {
  /**
   * Gets the server-provided retry delay in milliseconds when Aquari supplied one.
   */
  public readonly retryAfterMs:
    number | undefined;

  /**
   * Creates a rate-limit error and preserves the server-provided retry delay when one is
   * available.
   */
  public constructor(
    options: AquariRateLimitErrorOptions,
  ) {
    super(options);
    this.retryAfterMs = options.retryAfterMs;
  }
}

/**
 * Reports an Aquari quota response and the quota metadata returned by the API.
 */
export class AquariQuotaError
  extends AquariApiError {
  public readonly resource: string | undefined;

  public readonly scopeType: string | undefined;

  public readonly scopeId: string | undefined;

  public readonly current: number | undefined;

  public readonly requested: number | undefined;

  public readonly limit: number | undefined;

  public readonly allowance: number | undefined;

  public readonly grace: number | undefined;

  public readonly periodFrom: Date | undefined;

  public readonly periodTo: Date | undefined;

  public readonly enforcement: string | undefined;

  /**
   * Creates a quota error and parses resource, scope, allowance, period, and enforcement
   * metadata from the API error details.
   */
  public constructor(
    options: AquariApiErrorOptions,
  ) {
    super(options);

    this.resource =
      getFirstDetail(options.details, "resource");

    this.scopeType =
      getFirstDetail(options.details, "scopeType");

    this.scopeId =
      getFirstDetail(options.details, "scopeId");

    this.current =
      getNumericDetail(options.details, "current");

    this.requested =
      getNumericDetail(options.details, "requested");

    this.limit =
      getNumericDetail(options.details, "limit");

    this.allowance =
      getNumericDetail(options.details, "allowance");

    this.grace =
      getNumericDetail(options.details, "grace");

    this.periodFrom =
      getDateDetail(options.details, "periodFrom");

    this.periodTo =
      getDateDetail(options.details, "periodTo");

    this.enforcement =
      getFirstDetail(options.details, "enforcement");
  }
}

/**
 * Defines OAuth error metadata returned by Aquari.
 */
export interface AquariOAuthErrorOptions {
  code: string;
  message: string;
  errorDescription?: string;
  errorUri?: string;
}

/**
 * Reports an OAuth or OpenID Connect protocol failure.
 */
export class AquariOAuthError
  extends AquariError {
  public readonly code: string;

  public readonly errorDescription:
    string | undefined;

  public readonly errorUri:
    string | undefined;

  /**
   * Creates an OAuth or OpenID Connect protocol error and preserves the protocol error code
   * and optional metadata.
   */
  public constructor(
    options: AquariOAuthErrorOptions,
  ) {
    super(options.message);
    this.code = options.code;
    this.errorDescription =
      options.errorDescription;
    this.errorUri = options.errorUri;
  }
}

/**
 * Maps an Aquari HTTP error response to the most specific structured SDK error type.
 */
export function classifyAquariApiError(
  options: AquariApiErrorOptions,
  retryAfterMs?: number,
): AquariApiError {
  if (
    options.code === "RateLimitExceeded" ||
    options.status === 429
  ) {
    return new AquariRateLimitError({
      ...options,
      retryAfterMs,
    });
  }

  if (options.code === "QuotaExceeded") {
    return new AquariQuotaError(options);
  }

  if (
    options.code === "ValidationFailed" ||
    options.status === 400
  ) {
    return new AquariValidationError(options);
  }

  if (
    options.code === "Unauthorized" ||
    options.status === 401
  ) {
    return new AquariAuthenticationError(options);
  }

  if (
    options.code === "Forbidden" ||
    options.status === 403
  ) {
    return new AquariAuthorizationError(options);
  }

  if (options.status === 404) {
    return new AquariNotFoundError(options);
  }

  if (
    options.code === "Conflict" ||
    options.status === 409
  ) {
    return new AquariConflictError(options);
  }

  return new AquariApiError(options);
}

function getFirstDetail(
  details: AquariErrorDetails | undefined,
  key: string,
): string | undefined {
  return details?.[key]?.[0];
}

function getNumericDetail(
  details: AquariErrorDetails | undefined,
  key: string,
): number | undefined {
  const value = getFirstDetail(details, key);

  if (value === undefined) {
    return undefined;
  }

  const parsed = Number(value);

  return Number.isFinite(parsed)
    ? parsed
    : undefined;
}

function getDateDetail(
  details: AquariErrorDetails | undefined,
  key: string,
): Date | undefined {
  const value = getFirstDetail(details, key);

  if (value === undefined) {
    return undefined;
  }

  const parsed = new Date(value);

  return Number.isNaN(parsed.getTime())
    ? undefined
    : parsed;
}
