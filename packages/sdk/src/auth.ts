import {
  AquariOAuthError,
} from "./errors.js";

import type {
  AquariHttpTransport,
} from "./transport.js";

import {
  discoverAquariOidc,
  type AquariDiscoveryOptions,
  type AquariOidcDiscovery,
} from "./oidc.js";

import {
  exchangeAquariAuthorizationCode,
  exchangeAquariRefreshToken,
  fetchAquariUserInfo,
  type AquariAuthorizationCodeExchangeResult,
  type AquariIdentity,
  type AquariTokenSet,
} from "./oauth.js";

import {
  createPkcePair,
  createSecureRandomValue,
} from "./pkce.js";

const AUTH_TRANSACTION_MAX_AGE_MS =
  15 * 60 * 1_000;

const AUTH_TRANSACTION_CLOCK_SKEW_MS =
  60 * 1_000;

const TRANSACTION_STATE_PATTERN =
  /^[A-Za-z0-9_-]{43}$/u;

const TRANSACTION_VERIFIER_PATTERN =
  /^[A-Za-z0-9_-]{64}$/u;

/**
 * Lists the supported prompt values for an Aquari authorization request.
 */
export type AquariAuthorizationPrompt =
  | "consent"
  | "login"
  | "none"
  | "select_account";

/**
 * Stores the authorization transaction that binds an OAuth callback to the request that
 * started it. Preserve this value until authorization completes. Treat the PKCE verifier,
 * state, and nonce as sensitive.
 */
export interface AquariAuthorizationTransaction {
  version: 1;
  issuer: string;
  clientId: string;
  redirectUri: string;
  scopes: readonly string[];
  /**
   * Gets the PKCE verifier. Treat this value as sensitive and preserve it only until
   * callback completion.
   */
  codeVerifier: string;
  /**
   * Gets the OAuth state value used to bind the callback to this transaction. Treat it as
   * sensitive.
   */
  state: string;
  /**
   * Gets the OpenID Connect nonce used to validate the returned ID token. Treat it as
   * sensitive.
   */
  nonce: string;
  /**
   * Gets the transaction creation time used to reject stale authorization state.
   */
  createdAt: number;
}

/**
 * Configures an authorization request before the application opens the system browser.
 */
export interface AquariBeginAuthorizationOptions {
  /**
   * Sets the optional OpenID Connect prompt value for this authorization request.
   */
  prompt?: AquariAuthorizationPrompt;
  /**
   * Cancels discovery or authorization preparation when the AbortSignal is aborted.
   */
  signal?: AbortSignal;
}

/**
 * Contains the authorization URL and transaction created when an Aquari authorization
 * request starts.
 */
export interface AquariBeginAuthorizationResult {
  url: string;
  transaction: AquariAuthorizationTransaction;
}

/**
 * Configures cancellation for authorization callback processing.
 */
export interface AquariCompleteAuthorizationOptions {
  /**
   * Cancels token exchange and ID-token validation when the AbortSignal is aborted.
   */
  signal?: AbortSignal;
}

/**
 * Configures cancellation for a refresh-token exchange.
 */
export interface AquariRefreshOptions {
  /**
   * Cancels the refresh-token exchange when the AbortSignal is aborted.
   */
  signal?: AbortSignal;
}

/**
 * Configures cancellation for an Aquari UserInfo request.
 */
export interface AquariUserInfoOptions {
  /**
   * Cancels the UserInfo request when the AbortSignal is aborted.
   */
  signal?: AbortSignal;
}

/**
 * Contains the result of the complete authorization operation.
 */
export type AquariCompleteAuthorizationResult =
  AquariAuthorizationCodeExchangeResult;

/**
 * Defines the normalized OAuth client configuration used by the Aquari authentication
 * client.
 */
export interface AquariAuthClientConfiguration {
  /**
   * Sets the normalized Aquari issuer used for OIDC discovery and callback validation.
   */
  issuer: string;
  /**
   * Sets the OAuth client identifier.
   */
  clientId: string;
  /**
   * Sets the confidential-client secret when this client runs only in a trusted server
   * environment.
   */
  clientSecret?: string;
  /**
   * Sets the exact registered OAuth redirect URI.
   */
  redirectUri: string;
  /**
   * Sets the OAuth scopes bound to each authorization transaction.
   */
  scopes: readonly string[];
  /**
   * Sets the OAuth request timeout in milliseconds.
   */
  timeoutMs: number;
  /**
   * Sets the fetch implementation used for OAuth requests.
   */
  fetch: typeof fetch;
}

/**
 * Configures Aquari OIDC discovery and cache refresh behavior.
 */
export interface AquariDiscoverOptions
  extends AquariDiscoveryOptions {
  /**
   * Forces a new OIDC discovery request instead of using cached metadata.
   */
  forceRefresh?: boolean;
}

/**
 * Provides OIDC discovery, Authorization Code with S256 PKCE, refresh-token rotation, and
 * UserInfo operations.
 */
export class AquariAuthClient {
  readonly #configuration:
    AquariAuthClientConfiguration;

  readonly #transport:
    AquariHttpTransport;

  #cachedDiscovery:
    AquariOidcDiscovery | undefined;

  /**
   * Creates the authentication client from normalized OAuth configuration and an Aquari HTTP
   * transport. Most applications obtain this client from AquariClient authentication
   * accessors.
   */
  public constructor(
    configuration:
      AquariAuthClientConfiguration,
    transport: AquariHttpTransport,
  ) {
    this.#configuration = configuration;
    this.#transport = transport;
  }

  /**
   * Loads and validates Aquari OpenID Connect discovery metadata. The client reuses cached
   * metadata unless the caller requests a refresh.
   */
  public async discover(
    options: AquariDiscoverOptions = {},
  ): Promise<AquariOidcDiscovery> {
    if (
      options.forceRefresh !== true &&
      this.#cachedDiscovery !== undefined
    ) {
      return this.#cachedDiscovery;
    }

    const discoveryOptions:
      AquariDiscoveryOptions = {};

    if (options.signal !== undefined) {
      discoveryOptions.signal =
        options.signal;
    }

    const discovery =
      await discoverAquariOidc(
        this.#transport,
        this.#configuration.issuer,
        discoveryOptions,
      );

    this.#cachedDiscovery = discovery;

    return discovery;
  }

  /**
   * Starts an Authorization Code request. The SDK creates S256 PKCE, state, nonce, and a
   * serializable authorization transaction, then returns the system-browser URL. Preserve
   * the transaction until authorization completes.
   */
  public async begin(
    options:
      AquariBeginAuthorizationOptions = {},
  ): Promise<AquariBeginAuthorizationResult> {
    const discoveryOptions:
      AquariDiscoverOptions = {};

    if (options.signal !== undefined) {
      discoveryOptions.signal =
        options.signal;
    }

    const discovery =
      await this.discover(
        discoveryOptions,
      );

    const pkce =
      await createPkcePair();

    const transaction:
      AquariAuthorizationTransaction = {
        version: 1,
        issuer:
          this.#configuration.issuer,
        clientId:
          this.#configuration.clientId,
        redirectUri:
          this.#configuration.redirectUri,
        scopes: Object.freeze([
          ...this.#configuration.scopes,
        ]),
        codeVerifier:
          pkce.codeVerifier,
        state:
          createSecureRandomValue(32),
        nonce:
          createSecureRandomValue(32),
        createdAt: Date.now(),
      };

    const url =
      new URL(
        discovery.authorizationEndpoint,
      );

    url.searchParams.set(
      "client_id",
      transaction.clientId,
    );

    url.searchParams.set(
      "redirect_uri",
      transaction.redirectUri,
    );

    url.searchParams.set(
      "response_type",
      "code",
    );

    url.searchParams.set(
      "scope",
      transaction.scopes.join(" "),
    );

    url.searchParams.set(
      "state",
      transaction.state,
    );

    url.searchParams.set(
      "nonce",
      transaction.nonce,
    );

    url.searchParams.set(
      "code_challenge",
      pkce.codeChallenge,
    );

    url.searchParams.set(
      "code_challenge_method",
      "S256",
    );

    if (options.prompt !== undefined) {
      url.searchParams.set(
        "prompt",
        options.prompt,
      );
    }

    return {
      url: url.toString(),
      transaction,
    };
  }

  /**
   * Validates the authorization callback against the original transaction, exchanges the
   * authorization code, validates the ID token and nonce, and returns subject-bound session
   * state.
   */
  public async complete(
    callbackUrl: string | URL,
    transaction: AquariAuthorizationTransaction,
    options:
      AquariCompleteAuthorizationOptions = {},
  ): Promise<AquariCompleteAuthorizationResult> {
    const validatedTransaction =
      validateTransaction(
        transaction,
        this.#configuration,
      );

    const callback =
      parseCallbackUrl(
        callbackUrl,
        validatedTransaction.redirectUri,
      );

    const state =
      readSingleCallbackParameter(
        callback,
        "state",
        true,
      );

    if (state !== validatedTransaction.state) {
      throw new AquariOAuthError({
        code: "state_mismatch",
        message:
          "Aquari authorization callback state does not match the initiating transaction.",
      });
    }

    const callbackIssuer =
      readSingleCallbackParameter(
        callback,
        "iss",
        false,
      );

    if (
      callbackIssuer !== undefined &&
      callbackIssuer !==
        validatedTransaction.issuer
    ) {
      throw new AquariOAuthError({
        code: "issuer_mismatch",
        message:
          "Aquari authorization callback issuer does not match the initiating transaction.",
      });
    }

    const oauthError =
      readSingleCallbackParameter(
        callback,
        "error",
        false,
      );

    const code =
      readSingleCallbackParameter(
        callback,
        "code",
        false,
      );

    if (
      oauthError !== undefined &&
      code !== undefined
    ) {
      throw new AquariOAuthError({
        code: "invalid_callback",
        message:
          "Aquari authorization callback cannot contain both a code and an OAuth error.",
      });
    }

    if (oauthError !== undefined) {
      const description =
        readSingleCallbackParameter(
          callback,
          "error_description",
          false,
        );

      const errorUri =
        readSingleCallbackParameter(
          callback,
          "error_uri",
          false,
        );

      throw new AquariOAuthError({
        code: oauthError,
        message:
          description ??
          `Aquari returned OAuth error '${oauthError}'.`,
        ...(description !== undefined
          ? { errorDescription: description }
          : {}),
        ...(errorUri !== undefined
          ? { errorUri }
          : {}),
      });
    }

    if (code === undefined) {
      throw new AquariOAuthError({
        code: "invalid_callback",
        message:
          "Aquari authorization callback does not contain an authorization code.",
      });
    }

    const discoveryOptions:
      AquariDiscoverOptions = {};

    if (options.signal !== undefined) {
      discoveryOptions.signal =
        options.signal;
    }

    const discovery =
      await this.discover(
        discoveryOptions,
      );

    if (
      discovery
        .authorizationResponseIssuerParameterSupported &&
      callbackIssuer === undefined
    ) {
      throw new AquariOAuthError({
        code: "missing_issuer",
        message:
          "Aquari authorization callback is missing the advertised issuer parameter.",
      });
    }

    const exchangeInput = {
      discovery,
      clientId:
        validatedTransaction.clientId,
      redirectUri:
        validatedTransaction.redirectUri,
      code,
      codeVerifier:
        validatedTransaction.codeVerifier,
      requestedScopes:
        validatedTransaction.scopes,
      expectedNonce:
        validatedTransaction.nonce,
      fetch: this.#configuration.fetch,
      timeoutMs:
        this.#configuration.timeoutMs,
      ...(this.#configuration.clientSecret !==
        undefined
        ? {
            clientSecret:
              this.#configuration.clientSecret,
          }
        : {}),
      ...(options.signal !== undefined
        ? { signal: options.signal }
        : {}),
    };

    return await exchangeAquariAuthorizationCode(
      exchangeInput,
    );
  }

  /**
   * Exchanges the current refresh token for a replacement token set. Treat the returned
   * token set as the new session state because Aquari rotates refresh tokens.
   */
  public async refresh(
    tokens: AquariTokenSet,
    options: AquariRefreshOptions = {},
  ): Promise<AquariTokenSet> {
    const discoveryOptions:
      AquariDiscoverOptions = {};

    if (options.signal !== undefined) {
      discoveryOptions.signal =
        options.signal;
    }

    const discovery =
      await this.discover(
        discoveryOptions,
      );

    return await exchangeAquariRefreshToken({
      discovery,
      clientId:
        this.#configuration.clientId,
      tokens,
      fetch: this.#configuration.fetch,
      timeoutMs:
        this.#configuration.timeoutMs,
      ...(this.#configuration.clientSecret !==
        undefined
        ? {
            clientSecret:
              this.#configuration.clientSecret,
          }
        : {}),
      ...(options.signal !== undefined
        ? { signal: options.signal }
        : {}),
    });
  }

  /**
   * Reads Aquari UserInfo with the current access token and returns the subject-bound
   * identity.
   */
  public async userInfo(
    tokens: AquariTokenSet,
    options: AquariUserInfoOptions = {},
  ): Promise<AquariIdentity> {
    const discoveryOptions:
      AquariDiscoverOptions = {};

    if (options.signal !== undefined) {
      discoveryOptions.signal =
        options.signal;
    }

    const discovery =
      await this.discover(
        discoveryOptions,
      );

    return await fetchAquariUserInfo({
      discovery,
      tokens,
      fetch: this.#configuration.fetch,
      timeoutMs:
        this.#configuration.timeoutMs,
      ...(options.signal !== undefined
        ? { signal: options.signal }
        : {}),
    });
  }
}

function validateTransaction(
  value: unknown,
  configuration:
    AquariAuthClientConfiguration,
): AquariAuthorizationTransaction {
  if (!isRecord(value)) {
    throwInvalidTransaction();
  }

  const scopes =
    readTransactionScopes(
      value["scopes"],
    );

  const createdAt =
    value["createdAt"];

  if (
    value["version"] !== 1 ||
    value["issuer"] !==
      configuration.issuer ||
    value["clientId"] !==
      configuration.clientId ||
    value["redirectUri"] !==
      configuration.redirectUri ||
    scopes === undefined ||
    !sameStrings(
      scopes,
      configuration.scopes,
    ) ||
    typeof value["codeVerifier"] !==
      "string" ||
    !TRANSACTION_VERIFIER_PATTERN.test(
      value["codeVerifier"],
    ) ||
    typeof value["state"] !== "string" ||
    !TRANSACTION_STATE_PATTERN.test(
      value["state"],
    ) ||
    typeof value["nonce"] !== "string" ||
    !TRANSACTION_STATE_PATTERN.test(
      value["nonce"],
    ) ||
    typeof createdAt !== "number" ||
    !Number.isFinite(createdAt)
  ) {
    throwInvalidTransaction();
  }

  const now = Date.now();

  if (
    createdAt >
      now + AUTH_TRANSACTION_CLOCK_SKEW_MS ||
    now - createdAt >
      AUTH_TRANSACTION_MAX_AGE_MS
  ) {
    throw new AquariOAuthError({
      code: "expired_transaction",
      message:
        "Aquari authorization transaction is expired or has an invalid timestamp.",
    });
  }

  return {
    version: 1,
    issuer: configuration.issuer,
    clientId: configuration.clientId,
    redirectUri:
      configuration.redirectUri,
    scopes: Object.freeze(scopes),
    codeVerifier:
      value["codeVerifier"],
    state: value["state"],
    nonce: value["nonce"],
    createdAt,
  };
}

function readTransactionScopes(
  value: unknown,
): readonly string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }

  const source: readonly unknown[] =
    value;

  const scopes: string[] = [];

  for (const item of source) {
    if (
      typeof item !== "string" ||
      item.length === 0 ||
      item !== item.trim() ||
      /\s/u.test(item)
    ) {
      return undefined;
    }

    scopes.push(item);
  }

  return scopes;
}

function sameStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
  if (left.length !== right.length) {
    return false;
  }

  return left.every(
    (item, index) =>
      item === right[index],
  );
}

function parseCallbackUrl(
  value: string | URL,
  redirectUri: string,
): URL {
  let callback: URL;

  try {
    callback =
      value instanceof URL
        ? new URL(value.toString())
        : new URL(value);
  } catch {
    throw new AquariOAuthError({
      code: "invalid_callback",
      message:
        "Aquari authorization callback URL is invalid.",
    });
  }

  if (
    callback.hash.length > 0 ||
    !matchesRedirectUri(
      callback,
      new URL(redirectUri),
    )
  ) {
    throw new AquariOAuthError({
      code: "invalid_callback",
      message:
        "Aquari authorization callback URL does not match the configured redirect URI.",
    });
  }

  return callback;
}

function matchesRedirectUri(
  callback: URL,
  redirect: URL,
): boolean {
  if (
    callback.protocol !== redirect.protocol ||
    callback.username !== redirect.username ||
    callback.password !== redirect.password ||
    callback.hostname !== redirect.hostname ||
    callback.port !== redirect.port ||
    callback.pathname !== redirect.pathname
  ) {
    return false;
  }

  const names =
    new Set(
      redirect.searchParams.keys(),
    );

  for (const name of names) {
    const expected =
      redirect.searchParams.getAll(name);

    const remaining =
      callback.searchParams.getAll(name);

    for (const expectedValue of expected) {
      const index =
        remaining.indexOf(
          expectedValue,
        );

      if (index < 0) {
        return false;
      }

      remaining.splice(index, 1);
    }
  }

  return true;
}

function readSingleCallbackParameter(
  callback: URL,
  name: string,
  required: boolean,
): string | undefined {
  const values =
    callback.searchParams.getAll(name);

  if (values.length > 1) {
    throw new AquariOAuthError({
      code: "invalid_callback",
      message:
        `Aquari authorization callback contains multiple '${name}' parameters.`,
    });
  }

  const value = values[0];

  if (
    value === undefined ||
    value.length === 0
  ) {
    if (required) {
      throw new AquariOAuthError({
        code: "invalid_callback",
        message:
          `Aquari authorization callback is missing '${name}'.`,
      });
    }

    return undefined;
  }

  return value;
}

function throwInvalidTransaction(): never {
  throw new AquariOAuthError({
    code: "invalid_transaction",
    message:
      "Aquari authorization transaction is invalid or does not match this client configuration.",
  });
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
