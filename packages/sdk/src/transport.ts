import {
  resolveAquariTransportConfiguration,
  type AquariTransportConfiguration,
  type ResolvedAquariTransportConfiguration,
} from "./config.js";

import {
  AquariApiError,
  AquariConfigurationError,
  AquariTimeoutError,
  AquariTransportError,
  classifyAquariApiError,
  type AquariErrorDetails,
} from "./errors.js";

/**
 * Lists the HTTP methods accepted by the Aquari transport request API.
 */
export type AquariHttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "HEAD"
  | "OPTIONS";

/**
 * Controls whether the Aquari HTTP transport retries a request.
 */
export type AquariRetryMode =
  | "auto"
  | "never"
  | "idempotent";

/**
 * Configures the request operation.
 */
export interface AquariRequestOptions {
  path: string;
  method?: AquariHttpMethod;
  headers?: HeadersInit;
  json?: unknown;
  signal?: AbortSignal;
  retry?: AquariRetryMode;
}

/**
 * Sends Aquari API requests with timeout, retry, cancellation, and structured error
 * handling.
 */
export class AquariHttpTransport {
  readonly #configuration:
    ResolvedAquariTransportConfiguration;

  /**
   * Creates an Aquari HTTP transport with validated timeout, retry, base URL, and fetch
   * behavior.
   */
  public constructor(
    configuration: AquariTransportConfiguration,
  ) {
    this.#configuration =
      resolveAquariTransportConfiguration(
        configuration,
      );
  }

  public async request<T>(
    options: AquariRequestOptions,
  ): Promise<T> {
    const method =
      options.method ?? "GET";

    const retryMode =
      options.retry ?? "auto";

    const retryable =
      isRetryableRequest(
        method,
        retryMode,
      );

    const url =
      resolveRequestUrl(
        this.#configuration.baseUrl,
        options.path,
      );

    let attemptIndex = 0;

    for (;;) {
      const attempt =
        createAttemptSignal(
          this.#configuration.timeoutMs,
          options.signal,
        );

      try {
        const response =
          await this.#configuration.fetch(
            url,
            createRequestInit(
              method,
              options,
              attempt.signal,
            ),
          );

        if (response.ok) {
          return await readSuccessfulResponse<T>(
            response,
          );
        }

        const error =
          await readAquariApiError(response);

        if (
          retryable &&
          attemptIndex <
            this.#configuration.maxRetries &&
          isRetryableStatus(response.status)
        ) {
          const delayMs =
            getRetryDelayMs(
              response,
              attemptIndex,
            );

          if (
            delayMs <=
            this.#configuration
              .maxRetryDelayMs
          ) {
            attempt.cleanup();

            await waitForRetry(
              delayMs,
              options.signal,
            );

            attemptIndex += 1;
            continue;
          }
        }

        throw error;
      } catch (cause) {
        if (cause instanceof AquariApiError) {
          throw cause;
        }

        const didTimeout =
          attempt.didTimeout();

        const wasCancelled =
          options.signal?.aborted === true;

        if (
          retryable &&
          !wasCancelled &&
          attemptIndex <
            this.#configuration.maxRetries
        ) {
          const delayMs =
            getBackoffDelayMs(
              attemptIndex,
            );

          if (
            delayMs <=
            this.#configuration
              .maxRetryDelayMs
          ) {
            attempt.cleanup();

            await waitForRetry(
              delayMs,
              options.signal,
            );

            attemptIndex += 1;
            continue;
          }
        }

        if (didTimeout) {
          throw new AquariTimeoutError(
            this.#configuration.timeoutMs,
            { cause },
          );
        }

        if (wasCancelled) {
          throw new AquariTransportError(
            "Aquari request was cancelled.",
            {
              cause,
              cancelled: true,
            },
          );
        }

        throw new AquariTransportError(
          "Aquari request failed before a valid API response was received.",
          { cause },
        );
      } finally {
        attempt.cleanup();
      }
    }
  }
}

function parseHttpDate(value: string, now: Date): number | undefined {
  const modern = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$/i;
  const obsolete = /^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{2}) (\d{2}):(\d{2}):(\d{2}) GMT$/i;
  const ascii = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})$/i;
  let match = modern.exec(value);
  let shortYear = false;
  let asciiFormat = false;
  if (match === null) { match = obsolete.exec(value); shortYear = match !== null; }
  if (match === null) { match = ascii.exec(value); asciiFormat = match !== null; }
  if (match === null) return undefined;
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const month = months.findIndex((monthName) => monthName.toLowerCase() === (match[asciiFormat ? 2 : 3] ?? "").toLowerCase());
  const day = Number(match[asciiFormat ? 3 : 2]);
  let year = Number(match[asciiFormat ? 7 : 4]);
  if (shortYear) {
    const currentYear = now.getUTCFullYear();
    year += Math.floor(currentYear / 100) * 100;
    if (year > currentYear + 50) year -= 100;
  }
  const hour = Number(match[asciiFormat ? 4 : 5]);
  const minute = Number(match[asciiFormat ? 5 : 6]);
  const second = Number(match[asciiFormat ? 6 : 7]);
  if (day < 1 || hour > 23 || minute > 59 || second > 59) return undefined;
  const date = new Date(0);
  date.setUTCFullYear(year, month, day);
  date.setUTCHours(hour, minute, second, 0);
  const weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month || date.getUTCDate() !== day || weekdays[date.getUTCDay()]?.toLowerCase() !== match[1]?.slice(0, 3).toLowerCase()) return undefined;
  return date.getTime();
}

/**
 * Parses an HTTP Retry-After header and returns the delay in milliseconds when the value
 * is valid.
 */
export function parseRetryAfterMs(
  value: string | null,
  now: Date = new Date(),
): number | undefined {
  if (value === null) {
    return undefined;
  }

  const normalized = value.trim();

  if (/^\d+$/.test(normalized)) {
    return Math.min(Number.MAX_SAFE_INTEGER, Number(normalized) * 1_000);
  }

  const timestamp = parseHttpDate(normalized, now);
  if (timestamp === undefined) {
    return undefined;
  }

  return Math.max(
    0,
    timestamp - now.getTime(),
  );
}

function resolveRequestUrl(
  baseUrl: URL,
  path: string,
): URL {
  if (path.trim().length === 0) {
    throw new AquariConfigurationError(
      "Aquari request path cannot be empty.",
    );
  }

  if (
    /^[a-z][a-z\d+.-]*:/iu.test(path) ||
    path.startsWith("//")
  ) {
    throw new AquariConfigurationError(
      "Aquari request path must be relative to the configured base URL.",
    );
  }

  const url =
    new URL(path, baseUrl);

  if (url.origin !== baseUrl.origin) {
    throw new AquariConfigurationError(
      "Aquari request cannot target another origin.",
    );
  }

  return url;
}

function createRequestInit(
  method: AquariHttpMethod,
  options: AquariRequestOptions,
  signal: AbortSignal,
): RequestInit {
  const headers =
    new Headers(options.headers);

  headers.set(
    "accept",
    "application/json",
  );

  const init: RequestInit = {
    method,
    headers,
    signal,
  };

  if (options.json !== undefined) {
    headers.set(
      "content-type",
      "application/json",
    );

    init.body =
      JSON.stringify(options.json);
  }

  return init;
}

async function readSuccessfulResponse<T>(
  response: Response,
): Promise<T> {
  if (
    response.status === 204 ||
    response.status === 205
  ) {
    return undefined as T;
  }

  const text =
    await response.text();

  if (text.length === 0) {
    return undefined as T;
  }

  const contentType =
    response.headers.get("content-type");

  if (
    contentType?.includes(
      "application/json",
    ) === true
  ) {
    return JSON.parse(text) as T;
  }

  return text as T;
}

async function readAquariApiError(
  response: Response,
): Promise<AquariApiError> {
  const retryAfterMs =
    parseRetryAfterMs(
      response.headers.get("retry-after"),
    );

  const text =
    await response.text();

  const envelope =
    parseAquariErrorEnvelope(text);

  const message =
    envelope.message ??
    (
      response.statusText ||
      `Aquari API request failed with HTTP ${String(response.status)}.`
    );

  return classifyAquariApiError(
    {
      status: response.status,
      code: envelope.code,
      message,
      details: envelope.details,
    },
    retryAfterMs,
  );
}

interface ParsedAquariErrorEnvelope {
  code: string | undefined;
  message: string | undefined;
  details: AquariErrorDetails | undefined;
}

function parseAquariErrorEnvelope(
  text: string,
): ParsedAquariErrorEnvelope {
  if (text.length === 0) {
    return {
      code: undefined,
      message: undefined,
      details: undefined,
    };
  }

  let value: unknown;

  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return {
      code: undefined,
      message: undefined,
      details: undefined,
    };
  }

  if (
    !isRecord(value) ||
    !isRecord(value["error"])
  ) {
    return {
      code: undefined,
      message: undefined,
      details: undefined,
    };
  }

  const error = value["error"];

  return {
    code:
      typeof error["code"] === "string"
        ? error["code"]
        : undefined,

    message:
      typeof error["message"] === "string"
        ? error["message"]
        : undefined,

    details:
      parseErrorDetails(
        error["details"],
      ),
  };
}

function parseErrorDetails(
  value: unknown,
): AquariErrorDetails | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const parsed:
    Record<string, readonly string[]> = {};

  for (
    const [key, rawValue]
    of Object.entries(value)
  ) {
    if (
      Array.isArray(rawValue) &&
      rawValue.every(
        item => typeof item === "string",
      )
    ) {
      parsed[key] =
        rawValue;
    }
  }

  return Object.keys(parsed).length > 0
    ? parsed
    : undefined;
}

function isRecord(
  value: unknown,
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isRetryableRequest(
  method: AquariHttpMethod,
  retryMode: AquariRetryMode,
): boolean {
  if (retryMode === "never") {
    return false;
  }

  if (retryMode === "idempotent") {
    return true;
  }

  return (
    method === "GET" ||
    method === "HEAD" ||
    method === "OPTIONS"
  );
}

function isRetryableStatus(
  status: number,
): boolean {
  return (
    status === 429 ||
    status === 502 ||
    status === 503 ||
    status === 504
  );
}

function getRetryDelayMs(
  response: Response,
  attemptIndex: number,
): number {
  const retryAfterMs =
    parseRetryAfterMs(
      response.headers.get("retry-after"),
    );

  return (
    retryAfterMs ??
    getBackoffDelayMs(attemptIndex)
  );
}

function getBackoffDelayMs(
  attemptIndex: number,
): number {
  const base =
    250 * (2 ** attemptIndex);

  const jitter =
    0.5 + (Math.random() * 0.5);

  return Math.round(
    base * jitter,
  );
}

function createAttemptSignal(
  timeoutMs: number,
  externalSignal: AbortSignal | undefined,
): {
  signal: AbortSignal;
  didTimeout: () => boolean;
  cleanup: () => void;
} {
  const controller =
    new AbortController();

  let timedOut = false;

  const timeout =
    setTimeout(
      () => {
        timedOut = true;

        controller.abort(
          new Error(
            "Aquari request timed out.",
          ),
        );
      },
      timeoutMs,
    );

  const abortFromExternal = (): void => {
    controller.abort(
      externalSignal?.reason,
    );
  };

  if (externalSignal?.aborted === true) {
    abortFromExternal();
  } else {
    externalSignal?.addEventListener(
      "abort",
      abortFromExternal,
      { once: true },
    );
  }

  return {
    signal: controller.signal,

    didTimeout: () => timedOut,

    cleanup: () => {
      clearTimeout(timeout);

      externalSignal?.removeEventListener(
        "abort",
        abortFromExternal,
      );
    },
  };
}

async function waitForRetry(
  delayMs: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (signal?.aborted === true) {
    throw new AquariTransportError(
      "Aquari request was cancelled.",
      {
        cancelled: true,
      },
    );
  }

  if (delayMs <= 0) {
    return;
  }

  await new Promise<void>(
    (resolve, reject) => {
      const timeout =
        setTimeout(
          () => {
            signal?.removeEventListener(
              "abort",
              abort,
            );

            resolve();
          },
          delayMs,
        );

      const abort = (): void => {
        clearTimeout(timeout);

        signal?.removeEventListener(
          "abort",
          abort,
        );

        reject(
          new AquariTransportError(
            "Aquari request was cancelled.",
            {
              cancelled: true,
            },
          ),
        );
      };

      signal?.addEventListener(
        "abort",
        abort,
        { once: true },
      );
    },
  );
}
