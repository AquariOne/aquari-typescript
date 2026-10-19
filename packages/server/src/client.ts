import {
  AquariConfigurationError,
  AquariHttpTransport,
  normalizeAquariBaseUrl,
  resolveAquariTransportConfiguration,
  type AquariTransportConfiguration,
} from "@aquari-one/sdk";

import {
  AquariIssuerClient,
} from "./issuer.js";

import type {
  AquariMachineContext,
  AquariMachineHealth,
  AquariServerRequestOptions,
} from "./models.js";

import {
  asBoolean,
  asNonEmptyString,
  asRecord,
  asStringArray,
} from "./wire.js";

/**
 * Configures trusted-server access to the Aquari machine API. Keep the API key in
 * protected server-side configuration.
 */
export interface AquariServerClientOptions {
  /**
   * Sets the Aquari API base URL used by trusted-server machine requests.
   */
  apiUrl: string | URL;
  /**
   * Sets the machine API key. Keep this value only in protected server-side configuration.
   */
  apiKey: string;
  /**
   * Sets the machine API request timeout in milliseconds.
   */
  timeoutMs?: number;
  /**
   * Sets the maximum number of machine API retries after the first attempt.
   */
  maxRetries?: number;
  /**
   * Caps machine API retry backoff in milliseconds.
   */
  maxRetryDelayMs?: number;
  /**
   * Overrides the fetch implementation used by trusted-server requests.
   */
  fetch?: typeof fetch;
}

/**
 * Provides trusted-server machine and issuer APIs. Use this client only where a machine
 * API key can remain secret.
 */
export class AquariServerClient {
  public readonly apiUrl: string;

  /**
   * Gets authenticated machine-context operations.
   */
  public readonly machine:
    AquariMachineClient;

  /**
   * Gets trusted-server issuer operations.
   */
  public readonly issuer:
    AquariIssuerClient;

  readonly #apiKey: string;

  readonly #transport:
    AquariHttpTransport;

  /**
   * Creates a trusted-server client and binds the supplied machine API key to all machine
   * and issuer requests.
   */
  public constructor(
    options:
      AquariServerClientOptions,
  ) {
    this.apiUrl =
      normalizeAquariBaseUrl(
        options.apiUrl,
      ).toString();

    this.#apiKey =
      validateApiKey(
        options.apiKey,
      );

    const configuration:
      AquariTransportConfiguration = {
        baseUrl: this.apiUrl,
      };

    if (options.timeoutMs !== undefined) {
      configuration.timeoutMs =
        options.timeoutMs;
    }

    if (options.maxRetries !== undefined) {
      configuration.maxRetries =
        options.maxRetries;
    }

    if (
      options.maxRetryDelayMs !==
      undefined
    ) {
      configuration.maxRetryDelayMs =
        options.maxRetryDelayMs;
    }

    if (options.fetch !== undefined) {
      configuration.fetch =
        options.fetch;
    }

    this.#transport =
      new AquariHttpTransport(
        resolveAquariTransportConfiguration(
          configuration,
        ),
      );

    const authenticated = {
      transport: this.#transport,
      headers: (): Readonly<
        Record<string, string>
      > => this.#headers(),
    };

    this.machine =
      new AquariMachineClient(
        authenticated,
      );

    this.issuer =
      new AquariIssuerClient(
        authenticated,
      );
  }

  #headers():
    Readonly<Record<string, string>> {
    return {
      authorization:
        `Bearer ${this.#apiKey}`,
    };
  }
}

interface AuthenticatedTransport {
  transport: AquariHttpTransport;
  headers(): Readonly<Record<string, string>>;
}

/**
 * Reads machine API-key context and service health from Aquari.
 */
export class AquariMachineClient {
  readonly #authenticated:
    AuthenticatedTransport;

  /**
   * Creates a machine client from the authenticated transport owned by AquariServerClient.
   * Applications normally obtain this client from AquariServerClient.machine.
   */
  public constructor(
    authenticated:
      AuthenticatedTransport,
  ) {
    this.#authenticated =
      authenticated;
  }

  /**
   * Reads the machine context bound to the configured API key, including organization,
   * application, environment, and machine scopes.
   */
  public async context(
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariMachineContext> {
    const value =
      await this.#authenticated
        .transport
        .request<unknown>({
          path:
            "/api/v1/machine/context",
          method: "GET",
          headers:
            this.#authenticated
              .headers(),
          ...(options.signal !==
          undefined
            ? {
                signal:
                  options.signal,
              }
            : {}),
        });

    const record =
      asRecord(
        value,
        "machine context",
      );

    return {
      actorType:
        asNonEmptyString(
          record["actorType"],
          "machine actor type",
        ),
      apiKeyId:
        asNonEmptyString(
          record["apiKeyId"],
          "machine API key id",
        ),
      keyPrefix:
        asNonEmptyString(
          record["keyPrefix"],
          "machine key prefix",
        ),
      keyName:
        asNonEmptyString(
          record["keyName"],
          "machine key name",
        ),
      organizationId:
        asNonEmptyString(
          record["organizationId"],
          "machine organization id",
        ),
      applicationId:
        asNonEmptyString(
          record["applicationId"],
          "machine application id",
        ),
      environmentId:
        asNonEmptyString(
          record["environmentId"],
          "machine environment id",
        ),
      environmentName:
        asNonEmptyString(
          record["environmentName"],
          "machine environment name",
        ),
      environment:
        asNonEmptyString(
          record["environment"],
          "machine environment",
        ),
      scopes:
        asStringArray(
          record["scopes"],
          "machine scopes",
        ),
    };
  }

  /**
   * Checks the authenticated Aquari machine API and returns its structured health response.
   */
  public async health(
    options:
      AquariServerRequestOptions = {},
  ): Promise<AquariMachineHealth> {
    const value =
      await this.#authenticated
        .transport
        .request<unknown>({
          path:
            "/api/v1/machine/health",
          method: "GET",
          headers:
            this.#authenticated
              .headers(),
          ...(options.signal !==
          undefined
            ? {
                signal:
                  options.signal,
              }
            : {}),
        });

    const record =
      asRecord(
        value,
        "machine health",
      );

    return {
      ok:
        asBoolean(
          record["ok"],
          "machine health ok",
        ),
      actorType:
        asNonEmptyString(
          record["actorType"],
          "machine health actor type",
        ),
      apiKeyId:
        asNonEmptyString(
          record["apiKeyId"],
          "machine health API key id",
        ),
      applicationId:
        asNonEmptyString(
          record["applicationId"],
          "machine health application id",
        ),
      environment:
        asNonEmptyString(
          record["environment"],
          "machine health environment",
        ),
    };
  }
}

function validateApiKey(
  value: string,
): string {
  if (
    value.length === 0 ||
    value !== value.trim()
  ) {
    throw new AquariConfigurationError(
      "Aquari apiKey must be a non-empty value without surrounding whitespace.",
    );
  }

  return value;
}
