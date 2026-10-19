import {
  AquariConfigurationError,
} from "./errors.js";

/**
 * Defines the default Aquari request timeout in milliseconds.
 */
export const DEFAULT_REQUEST_TIMEOUT_MS =
  15_000;

/**
 * Defines the default number of retry attempts after the first Aquari HTTP request.
 */
export const DEFAULT_MAX_RETRIES = 2;

/**
 * Defines the maximum default retry backoff in milliseconds.
 */
export const DEFAULT_MAX_RETRY_DELAY_MS =
  5_000;

/**
 * Configures the Aquari HTTP transport, including timeout, retry, fetch, and base URL
 * behavior.
 */
export interface AquariTransportConfiguration {
  baseUrl: string | URL;
  timeoutMs?: number;
  maxRetries?: number;
  maxRetryDelayMs?: number;
  fetch?: typeof fetch;
}

/**
 * Contains validated transport configuration used for Aquari HTTP requests.
 */
export interface ResolvedAquariTransportConfiguration {
  baseUrl: URL;
  timeoutMs: number;
  maxRetries: number;
  maxRetryDelayMs: number;
  fetch: typeof fetch;
}

/**
 * Validates Aquari transport options, applies defaults, and returns normalized HTTP
 * configuration.
 */
export function resolveAquariTransportConfiguration(
  configuration: AquariTransportConfiguration,
): ResolvedAquariTransportConfiguration {
  const timeoutMs =
    configuration.timeoutMs ??
    DEFAULT_REQUEST_TIMEOUT_MS;

  const maxRetries =
    configuration.maxRetries ??
    DEFAULT_MAX_RETRIES;

  const maxRetryDelayMs =
    configuration.maxRetryDelayMs ??
    DEFAULT_MAX_RETRY_DELAY_MS;

  requirePositiveInteger(
    timeoutMs,
    "timeoutMs",
  );

  requireNonNegativeInteger(
    maxRetries,
    "maxRetries",
  );

  requireNonNegativeInteger(
    maxRetryDelayMs,
    "maxRetryDelayMs",
  );

  const fetchImplementation =
    configuration.fetch ??
    globalThis.fetch;

  if (typeof fetchImplementation !== "function") {
    throw new AquariConfigurationError(
      "A Fetch API implementation is required.",
    );
  }

  return {
    baseUrl:
      normalizeAquariBaseUrl(
        configuration.baseUrl,
      ),
    timeoutMs,
    maxRetries,
    maxRetryDelayMs,
    fetch: fetchImplementation,
  };
}

/**
 * Validates and normalizes an Aquari base URL while preserving its origin and path
 * identity.
 */
export function normalizeAquariBaseUrl(
  value: string | URL,
): URL {
  let url: URL;

  try {
    url =
      value instanceof URL
        ? new URL(value.toString())
        : new URL(value);
  } catch (cause) {
    throw new AquariConfigurationError(
      "Aquari base URL must be a valid absolute URL.",
      { cause },
    );
  }

  if (
    url.protocol !== "https:" &&
    url.protocol !== "http:"
  ) {
    throw new AquariConfigurationError(
      "Aquari base URL must use HTTPS or HTTP.",
    );
  }

  if (
    url.protocol === "http:" &&
    !isLocalDevelopmentHost(url.hostname)
  ) {
    throw new AquariConfigurationError(
      "Insecure HTTP Aquari URLs are allowed only for local development.",
    );
  }

  if (
    url.username.length > 0 ||
    url.password.length > 0
  ) {
    throw new AquariConfigurationError(
      "Aquari base URL must not contain credentials.",
    );
  }

  if (
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    throw new AquariConfigurationError(
      "Aquari base URL must not contain a query string or fragment.",
    );
  }

  if (!url.pathname.endsWith("/")) {
    url.pathname = `${url.pathname}/`;
  }

  return url;
}

function isLocalDevelopmentHost(
  hostname: string,
): boolean {
  const normalized =
    hostname.toLowerCase();

  return (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized === "[::1]" ||
    normalized === "::1"
  );
}

function requirePositiveInteger(
  value: number,
  name: string,
): void {
  if (
    !Number.isInteger(value) ||
    value <= 0
  ) {
    throw new AquariConfigurationError(
      `${name} must be a positive integer.`,
    );
  }
}

function requireNonNegativeInteger(
  value: number,
  name: string,
): void {
  if (
    !Number.isInteger(value) ||
    value < 0
  ) {
    throw new AquariConfigurationError(
      `${name} must be a non-negative integer.`,
    );
  }
}
