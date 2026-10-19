import {
  normalizeAquariBaseUrl,
  resolveAquariTransportConfiguration,
  type AquariTransportConfiguration,
} from "./config.js";

import {
  AquariConfigurationError,
} from "./errors.js";

import {
  AquariAuthClient,
} from "./auth.js";

import {
  AquariHttpTransport,
} from "./transport.js";

import {
  AquariPassportClient,
} from "./passport.js";

import {
  AquariTrustClient,
} from "./trust.js";

/**
 * Configures an Aquari OAuth client and its HTTP behavior. Do not put a confidential
 * client secret in distributable client code.
 */
export interface AquariClientOptions {
  /**
   * Sets the absolute Aquari issuer URL. Remote issuers must use HTTPS.
   */
  issuer: string | URL;
  /**
   * Sets the OAuth client identifier registered for this application.
   */
  clientId: string;
  /**
   * Confidential clients only. Never bundle a client secret
   * into browser-distributed or device-distributed code.
   */
  clientSecret?: string;
  /**
   * Sets the exact OAuth redirect URI registered for this client.
   */
  redirectUri: string | URL;
  /**
   * Sets the OAuth scopes requested during authorization. Request offline_access when the
   * application needs refresh tokens.
   */
  scopes: readonly string[];
  /**
   * Sets the request timeout in milliseconds.
   */
  timeoutMs?: number;
  /**
   * Sets the maximum number of transport retries after the first request attempt.
   */
  maxRetries?: number;
  /**
   * Caps retry backoff in milliseconds.
   */
  maxRetryDelayMs?: number;
  /**
   * Overrides the fetch implementation used by the SDK.
   */
  fetch?: typeof fetch;
}

/**
 * Provides the main Aquari runtime entry point for authentication, Passport, and trust
 * operations.
 */
export class AquariClient {
  /**
   * Gets the normalized Aquari issuer URL.
   */
  public readonly issuer: string;

  /**
   * Gets the configured OAuth client identifier.
   */
  public readonly clientId: string;

  /**
   * Gets the registered OAuth redirect URI.
   */
  public readonly redirectUri: string;

  /**
   * Gets the OAuth scopes requested by this client.
   */
  public readonly scopes:
    readonly string[];

  /**
   * Gets authentication and token-lifecycle operations.
   */
  public readonly auth:
    AquariAuthClient;

  /**
   * Gets Passport read operations.
   */
  public readonly passport:
    AquariPassportClient;

  /**
   * Gets trust-evaluation operations.
   */
  public readonly trust:
    AquariTrustClient;

  /**
   * Creates the main Aquari client from validated OAuth and HTTP configuration.
   */
  public constructor(
    options: AquariClientOptions,
  ) {
    this.issuer =
      normalizeAquariBaseUrl(
        options.issuer,
      ).toString();

    this.clientId =
      validateClientId(
        options.clientId,
      );

    const clientSecret =
      validateClientSecret(
        options.clientSecret,
      );

    this.redirectUri =
      validateRedirectUri(
        options.redirectUri,
      );

    this.scopes =
      validateScopes(options.scopes);

    const transportConfiguration:
      AquariTransportConfiguration = {
        baseUrl: this.issuer,
      };

    if (options.timeoutMs !== undefined) {
      transportConfiguration.timeoutMs =
        options.timeoutMs;
    }

    if (options.maxRetries !== undefined) {
      transportConfiguration.maxRetries =
        options.maxRetries;
    }

    if (
      options.maxRetryDelayMs !==
      undefined
    ) {
      transportConfiguration
        .maxRetryDelayMs =
        options.maxRetryDelayMs;
    }

    if (options.fetch !== undefined) {
      transportConfiguration.fetch =
        options.fetch;
    }

    const resolvedTransportConfiguration =
      resolveAquariTransportConfiguration(
        transportConfiguration,
      );

    const transport =
      new AquariHttpTransport(
        resolvedTransportConfiguration,
      );

    this.auth =
      new AquariAuthClient(
        {
          issuer: this.issuer,
          clientId: this.clientId,
          redirectUri: this.redirectUri,
          scopes: this.scopes,
          timeoutMs:
            resolvedTransportConfiguration
              .timeoutMs,
          fetch:
            resolvedTransportConfiguration
              .fetch,
          ...(clientSecret !== undefined
            ? { clientSecret }
            : {}),
        },
        transport,
      );

    this.passport =
      new AquariPassportClient(
        transport,
      );

    this.trust =
      new AquariTrustClient(
        transport,
      );
  }
}

function validateClientId(
  value: string,
): string {
  if (
    value.length === 0 ||
    value !== value.trim() ||
    /\s/u.test(value)
  ) {
    throw new AquariConfigurationError(
      "Aquari clientId must be a non-empty value without whitespace.",
    );
  }

  return value;
}

function validateClientSecret(
  value: string | undefined,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (value.length === 0) {
    throw new AquariConfigurationError(
      "Aquari clientSecret must not be empty when provided.",
    );
  }

  return value;
}

function validateRedirectUri(
  value: string | URL,
): string {
  const raw =
    value instanceof URL
      ? value.toString()
      : value;

  if (
    raw.length === 0 ||
    raw !== raw.trim()
  ) {
    throw new AquariConfigurationError(
      "Aquari redirectUri must be a non-empty absolute URI.",
    );
  }

  let url: URL;

  try {
    url = new URL(raw);
  } catch (cause) {
    throw new AquariConfigurationError(
      "Aquari redirectUri must be a valid absolute URI.",
      { cause },
    );
  }

  if (
    url.username.length > 0 ||
    url.password.length > 0
  ) {
    throw new AquariConfigurationError(
      "Aquari redirectUri must not contain credentials.",
    );
  }

  if (url.hash.length > 0) {
    throw new AquariConfigurationError(
      "Aquari redirectUri must not contain a fragment.",
    );
  }

  return raw;
}

function validateScopes(
  values: readonly string[],
): readonly string[] {
  if (values.length === 0) {
    throw new AquariConfigurationError(
      "Aquari scopes must contain at least one explicit scope.",
    );
  }

  const scopes: string[] = [];
  const seen = new Set<string>();

  for (const scope of values) {
    if (
      scope.length === 0 ||
      scope !== scope.trim() ||
      /\s/u.test(scope)
    ) {
      throw new AquariConfigurationError(
        "Aquari scope values must be non-empty and must not contain whitespace.",
      );
    }

    if (seen.has(scope)) {
      throw new AquariConfigurationError(
        "Aquari scope values must not contain duplicates.",
      );
    }

    seen.add(scope);
    scopes.push(scope);
  }

  if (!seen.has("openid")) {
    throw new AquariConfigurationError(
      "Aquari authentication requires the explicit 'openid' scope.",
    );
  }

  return Object.freeze(scopes);
}
