import {
  createRemoteJWKSet,
  customFetch,
  jwtVerify,
  type JWTPayload,
} from "jose";

import {
  AquariOAuthError,
  AquariTimeoutError,
  AquariTransportError,
} from "./errors.js";

import type {
  AquariOidcDiscovery,
} from "./oidc.js";

const CANONICAL_HANDLE_CLAIM =
  "https://aquari.one/claims/canonical_handle";

const VERIFIED_HANDLE_CLAIM =
  "https://aquari.one/claims/verified_handle";

const CLOCK_TOLERANCE_SECONDS = 60;

/**
 * Represents the subject-bound identity returned by Aquari UserInfo.
 */
export interface AquariIdentity {
  subject: string;
  handle?: string;
  canonicalHandle?: string;
  verifiedHandle?: string;
  name?: string;
  pictureUrl?: string;
  email?: string;
  emailVerified?: boolean;
}

/**
 * Contains the OAuth tokens, subject, scopes, and expiration metadata for an Aquari
 * session. Do not log or expose token values.
 */
export interface AquariTokenSet {
  /**
   * Gets the stable Aquari subject identifier bound to this token set.
   */
  subject: string;
  tokenType: "Bearer";
  /**
   * Gets the bearer access token. Do not log or expose this value.
   */
  accessToken: string;
  /**
   * Gets the validated OpenID Connect ID token. Do not log or expose this value.
   */
  idToken: string;
  /**
   * Gets the current refresh token when one is available. Aquari can rotate this value;
   * always persist the replacement token set.
   */
  refreshToken?: string;
  expiresIn: number;
  /**
   * Gets the time when the access token expires.
   */
  expiresAt: number;
  scopes: readonly string[];
}

interface AquariUnboundTokenSet {
  tokenType: "Bearer";
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresIn: number;
  expiresAt: number;
  scopes: readonly string[];
}

export interface AquariAuthorizationCodeExchangeInput {
  discovery: AquariOidcDiscovery;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
  requestedScopes: readonly string[];
  expectedNonce: string;
  fetch: typeof fetch;
  timeoutMs: number;
  signal?: AbortSignal;
}

export interface AquariAuthorizationCodeExchangeResult {
  tokens: AquariTokenSet;
  identity: AquariIdentity;
}

export interface AquariRefreshTokenExchangeInput {
  discovery: AquariOidcDiscovery;
  clientId: string;
  clientSecret?: string;
  tokens: AquariTokenSet;
  fetch: typeof fetch;
  timeoutMs: number;
  signal?: AbortSignal;
}

export interface AquariUserInfoInput {
  discovery: AquariOidcDiscovery;
  tokens: AquariTokenSet;
  fetch: typeof fetch;
  timeoutMs: number;
  signal?: AbortSignal;
}

export async function exchangeAquariAuthorizationCode(
  input: AquariAuthorizationCodeExchangeInput,
): Promise<AquariAuthorizationCodeExchangeResult> {
  requireSupportedClientAuthentication(
    input.discovery,
    input.clientSecret,
  );

  const body =
    new URLSearchParams({
      grant_type: "authorization_code",
      client_id: input.clientId,
      redirect_uri: input.redirectUri,
      code: input.code,
      code_verifier: input.codeVerifier,
    });

  if (input.clientSecret !== undefined) {
    body.set(
      "client_secret",
      input.clientSecret,
    );
  }

  const response =
    await fetchOAuthResponse(
      input.fetch,
      input.discovery.tokenEndpoint,
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type":
            "application/x-www-form-urlencoded",
        },
        body: body.toString(),
        credentials: "omit",
        redirect: "error",
      },
      input.timeoutMs,
      input.signal,
    );

  const parsed =
    await parseJsonResponse(response);

  if (!response.ok) {
    throwOAuthResponseError(
      parsed,
      response.status,
      "token_exchange_failed",
      "token exchange",
    );
  }

  const parsedTokens =
    parseAuthorizationTokenResponse(
      parsed,
      input.requestedScopes,
    );

  const identity =
    await validateIdToken(
      parsedTokens.idToken,
      input.discovery,
      input.clientId,
      input.expectedNonce,
      input.fetch,
      input.timeoutMs,
      input.signal,
    );

  const tokens: AquariTokenSet = {
    subject: identity.subject,
    ...parsedTokens,
  };

  return {
    tokens,
    identity,
  };
}

export async function exchangeAquariRefreshToken(
  input: AquariRefreshTokenExchangeInput,
): Promise<AquariTokenSet> {
  requireSupportedClientAuthentication(
    input.discovery,
    input.clientSecret,
  );

  const currentTokens =
    validateTokenSet(input.tokens);

  const refreshToken =
    currentTokens.refreshToken;

  if (refreshToken === undefined) {
    throw new AquariOAuthError({
      code: "missing_refresh_token",
      message:
        "Aquari cannot refresh this token set because it does not contain a refresh token.",
    });
  }

  const body =
    new URLSearchParams({
      grant_type: "refresh_token",
      client_id: input.clientId,
      refresh_token: refreshToken,
    });

  if (input.clientSecret !== undefined) {
    body.set(
      "client_secret",
      input.clientSecret,
    );
  }

  const response =
    await fetchOAuthResponse(
      input.fetch,
      input.discovery.tokenEndpoint,
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type":
            "application/x-www-form-urlencoded",
        },
        body: body.toString(),
        credentials: "omit",
        redirect: "error",
      },
      input.timeoutMs,
      input.signal,
    );

  const parsed =
    await parseJsonResponse(response);

  if (!response.ok) {
    throwOAuthResponseError(
      parsed,
      response.status,
      "refresh_failed",
      "token refresh",
    );
  }

  const refreshed =
    parseRefreshTokenResponse(
      parsed,
      currentTokens,
    );

  if (
    refreshed.idToken !==
    currentTokens.idToken
  ) {
    const refreshedIdentity =
      await validateIdToken(
        refreshed.idToken,
        input.discovery,
        input.clientId,
        undefined,
        input.fetch,
        input.timeoutMs,
        input.signal,
      );

    if (
      refreshedIdentity.subject !==
      currentTokens.subject
    ) {
      throwInvalidIdToken(
        "Aquari refreshed ID token subject does not match the existing token set.",
      );
    }
  }

  return refreshed;
}

export async function fetchAquariUserInfo(
  input: AquariUserInfoInput,
): Promise<AquariIdentity> {
  const tokens =
    validateTokenSet(input.tokens);

  const response =
    await fetchOAuthResponse(
      input.fetch,
      input.discovery.userInfoEndpoint,
      {
        method: "GET",
        headers: {
          accept: "application/json",
          authorization:
            `Bearer ${tokens.accessToken}`,
        },
        credentials: "omit",
        redirect: "error",
      },
      input.timeoutMs,
      input.signal,
    );

  const parsed =
    await parseJsonResponse(response);

  if (!response.ok) {
    throwOAuthResponseError(
      parsed,
      response.status,
      "userinfo_failed",
      "UserInfo request",
    );
  }

  const identity =
    parseUserInfoResponse(parsed);

  if (identity.subject !== tokens.subject) {
    throw new AquariOAuthError({
      code: "userinfo_subject_mismatch",
      message:
        "Aquari UserInfo subject does not match the authenticated token set.",
    });
  }

  return identity;
}

function requireSupportedClientAuthentication(
  discovery: AquariOidcDiscovery,
  clientSecret: string | undefined,
): void {
  if (
    clientSecret !== undefined &&
    !discovery.tokenEndpointAuthMethodsSupported.includes(
      "client_secret_post",
    )
  ) {
    throw new AquariOAuthError({
      code: "unsupported_client_authentication",
      message:
        "Aquari discovery does not advertise client_secret_post for this confidential client.",
    });
  }
}

async function validateIdToken(
  idToken: string,
  discovery: AquariOidcDiscovery,
  clientId: string,
  expectedNonce: string | undefined,
  fetchImplementation: typeof fetch,
  timeoutMs: number,
  signal: AbortSignal | undefined,
): Promise<AquariIdentity> {
  if (isSignalAborted(signal)) {
    throw new AquariTransportError(
      "Aquari request was cancelled.",
      { cancelled: true },
    );
  }

  const jwks =
    createRemoteJWKSet(
      new URL(discovery.jwksUri),
      {
        timeoutDuration: timeoutMs,
        [customFetch]: (
          url,
          options,
        ) => {
          const combined =
            combineAbortSignals(
              options.signal,
              signal,
            );

          return fetchImplementation(
            url,
            {
              ...options,
              signal: combined.signal,
            },
          ).finally(
            combined.cleanup,
          );
        },
      },
    );

  let payload: JWTPayload;

  try {
    const verified =
      await jwtVerify(
        idToken,
        jwks,
        {
          issuer: discovery.issuer,
          audience: clientId,
          algorithms: ["RS256"],
          clockTolerance:
            CLOCK_TOLERANCE_SECONDS,
        },
      );

    payload = verified.payload;
  } catch {
    if (isSignalAborted(signal)) {
      throw new AquariTransportError(
        "Aquari request was cancelled.",
        { cancelled: true },
      );
    }

    throw new AquariOAuthError({
      code: "invalid_id_token",
      message:
        "Aquari returned an ID token that failed cryptographic or claims validation.",
    });
  }

  if (
    typeof payload.sub !== "string" ||
    payload.sub.length === 0
  ) {
    throwInvalidIdToken(
      "Aquari ID token is missing a valid subject claim.",
    );
  }

  if (typeof payload.exp !== "number") {
    throwInvalidIdToken(
      "Aquari ID token is missing an expiration claim.",
    );
  }

  if (typeof payload.iat !== "number") {
    throwInvalidIdToken(
      "Aquari ID token is missing an issued-at claim.",
    );
  }

  const nowSeconds =
    Math.floor(Date.now() / 1_000);

  if (
    payload.iat >
    nowSeconds + CLOCK_TOLERANCE_SECONDS
  ) {
    throwInvalidIdToken(
      "Aquari ID token has an issued-at time too far in the future.",
    );
  }

  if (expectedNonce !== undefined) {
    const nonce =
      payload["nonce"];

    if (
      typeof nonce !== "string" ||
      nonce !== expectedNonce
    ) {
      throwInvalidIdToken(
        "Aquari ID token nonce does not match the authorization transaction.",
      );
    }
  }

  if (
    Array.isArray(payload.aud) &&
    payload.aud.length > 1 &&
    payload["azp"] !== clientId
  ) {
    throwInvalidIdToken(
      "Aquari ID token with multiple audiences must identify this client as the authorized party.",
    );
  }

  return buildIdentity(payload);
}

function buildIdentity(
  payload: Readonly<Record<string, unknown>>,
): AquariIdentity {
  const subject =
    readRequiredIdentityString(
      payload,
      "sub",
      "Aquari identity is missing a valid subject claim.",
    );

  const handle =
    readOptionalIdentityString(
      payload,
      "preferred_username",
    );

  const canonicalHandle =
    readOptionalIdentityString(
      payload,
      CANONICAL_HANDLE_CLAIM,
    );

  const verifiedHandle =
    readOptionalIdentityString(
      payload,
      VERIFIED_HANDLE_CLAIM,
    );

  const name =
    readOptionalIdentityString(
      payload,
      "name",
    );

  const pictureUrl =
    readOptionalIdentityString(
      payload,
      "picture",
    );

  const email =
    readOptionalIdentityString(
      payload,
      "email",
    );

  const emailVerified =
    readOptionalIdentityBoolean(
      payload,
      "email_verified",
    );

  return {
    subject,
    ...(handle !== undefined
      ? { handle }
      : {}),
    ...(canonicalHandle !== undefined
      ? { canonicalHandle }
      : {}),
    ...(verifiedHandle !== undefined
      ? { verifiedHandle }
      : {}),
    ...(name !== undefined
      ? { name }
      : {}),
    ...(pictureUrl !== undefined
      ? { pictureUrl }
      : {}),
    ...(email !== undefined
      ? { email }
      : {}),
    ...(emailVerified !== undefined
      ? { emailVerified }
      : {}),
  };
}

function parseAuthorizationTokenResponse(
  value: unknown,
  requestedScopes: readonly string[],
): AquariUnboundTokenSet {
  if (!isRecord(value)) {
    throwInvalidTokenResponse();
  }

  const accessToken =
    readRequiredTokenString(
      value,
      "access_token",
    );

  const idToken =
    readRequiredTokenString(
      value,
      "id_token",
    );

  const tokenType =
    readBearerTokenType(value);

  const expiresInValue =
    readExpiresIn(value);

  const refreshToken =
    readOptionalTokenString(
      value,
      "refresh_token",
    );

  const scopes =
    readResponseScopes(
      value,
      requestedScopes,
    );

  return {
    tokenType,
    accessToken,
    idToken,
    ...(refreshToken !== undefined
      ? { refreshToken }
      : {}),
    expiresIn: expiresInValue,
    expiresAt:
      Date.now() +
      (expiresInValue * 1_000),
    scopes,
  };
}

function parseRefreshTokenResponse(
  value: unknown,
  currentTokens: AquariTokenSet,
): AquariTokenSet {
  if (!isRecord(value)) {
    throwInvalidTokenResponse();
  }

  const accessToken =
    readRequiredTokenString(
      value,
      "access_token",
    );

  const tokenType =
    readBearerTokenType(value);

  const expiresInValue =
    readExpiresIn(value);

  const replacementIdToken =
    readOptionalTokenString(
      value,
      "id_token",
    );

  const replacementRefreshToken =
    readOptionalTokenString(
      value,
      "refresh_token",
    );

  const scopes =
    readResponseScopes(
      value,
      currentTokens.scopes,
    );

  const refreshToken =
    replacementRefreshToken ??
    currentTokens.refreshToken;

  return {
    subject: currentTokens.subject,
    tokenType,
    accessToken,
    idToken:
      replacementIdToken ??
      currentTokens.idToken,
    ...(refreshToken !== undefined
      ? { refreshToken }
      : {}),
    expiresIn: expiresInValue,
    expiresAt:
      Date.now() +
      (expiresInValue * 1_000),
    scopes,
  };
}

function validateTokenSet(
  value: unknown,
): AquariTokenSet {
  if (!isRecord(value)) {
    throwInvalidTokenSet();
  }

  if (value["tokenType"] !== "Bearer") {
    throwInvalidTokenSet();
  }

  const subject =
    readTokenSetString(
      value,
      "subject",
    );

  const accessToken =
    readTokenSetString(
      value,
      "accessToken",
    );

  const idToken =
    readTokenSetString(
      value,
      "idToken",
    );

  const refreshToken =
    readOptionalTokenSetString(
      value,
      "refreshToken",
    );

  const expiresIn =
    value["expiresIn"];

  const expiresAt =
    value["expiresAt"];

  if (
    typeof expiresIn !== "number" ||
    !Number.isFinite(expiresIn) ||
    expiresIn <= 0 ||
    typeof expiresAt !== "number" ||
    !Number.isFinite(expiresAt)
  ) {
    throwInvalidTokenSet();
  }

  const scopes =
    readTokenSetScopes(
      value["scopes"],
    );

  return {
    subject,
    tokenType: "Bearer",
    accessToken,
    idToken,
    ...(refreshToken !== undefined
      ? { refreshToken }
      : {}),
    expiresIn,
    expiresAt,
    scopes,
  };
}

function parseUserInfoResponse(
  value: unknown,
): AquariIdentity {
  if (!isRecord(value)) {
    throwInvalidUserInfoResponse();
  }

  try {
    return buildIdentity(value);
  } catch (cause) {
    if (
      cause instanceof AquariOAuthError &&
      cause.code === "invalid_identity"
    ) {
      throwInvalidUserInfoResponse();
    }

    throw cause;
  }
}

function readResponseScopes(
  value: Readonly<Record<string, unknown>>,
  fallback: readonly string[],
): readonly string[] {
  if (!("scope" in value)) {
    return Object.freeze([
      ...fallback,
    ]);
  }

  return parseScopeString(
    value["scope"],
  );
}

function parseScopeString(
  value: unknown,
): readonly string[] {
  if (typeof value !== "string") {
    throwInvalidTokenResponse();
  }

  const scopes =
    value
      .split(" ")
      .filter(
        scope => scope.length > 0,
      );

  if (scopes.length === 0) {
    throwInvalidTokenResponse();
  }

  const seen = new Set<string>();

  for (const scope of scopes) {
    if (
      scope !== scope.trim() ||
      /\s/u.test(scope) ||
      seen.has(scope)
    ) {
      throwInvalidTokenResponse();
    }

    seen.add(scope);
  }

  return Object.freeze(scopes);
}

function readTokenSetScopes(
  value: unknown,
): readonly string[] {
  if (!Array.isArray(value)) {
    throwInvalidTokenSet();
  }

  const source: readonly unknown[] =
    value;

  if (source.length === 0) {
    throwInvalidTokenSet();
  }

  const scopes: string[] = [];
  const seen = new Set<string>();

  for (const item of source) {
    if (
      typeof item !== "string" ||
      item.length === 0 ||
      item !== item.trim() ||
      /\s/u.test(item) ||
      seen.has(item)
    ) {
      throwInvalidTokenSet();
    }

    seen.add(item);
    scopes.push(item);
  }

  return Object.freeze(scopes);
}

async function parseJsonResponse(
  response: Response,
): Promise<unknown> {
  const text =
    await response.text();

  if (text.length === 0) {
    return undefined;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function throwOAuthResponseError(
  value: unknown,
  status: number,
  fallbackCode: string,
  operation: string,
): never {
  if (isRecord(value)) {
    const code =
      readOptionalString(value["error"]);

    if (code !== undefined) {
      const description =
        readOptionalString(
          value["error_description"],
        );

      const errorUri =
        readOptionalString(
          value["error_uri"],
        );

      throw new AquariOAuthError({
        code,
        message:
          description ??
          `Aquari returned OAuth error '${code}'.`,
        ...(description !== undefined
          ? { errorDescription: description }
          : {}),
        ...(errorUri !== undefined
          ? { errorUri }
          : {}),
      });
    }
  }

  throw new AquariOAuthError({
    code: fallbackCode,
    message:
      `Aquari ${operation} failed with HTTP ${String(status)}.`,
  });
}

function readBearerTokenType(
  value: Readonly<Record<string, unknown>>,
): "Bearer" {
  const tokenType =
    readRequiredTokenString(
      value,
      "token_type",
    );

  if (tokenType.toLowerCase() !== "bearer") {
    throw new AquariOAuthError({
      code: "invalid_token_response",
      message:
        "Aquari token response returned an unsupported token type.",
    });
  }

  return "Bearer";
}

function readExpiresIn(
  value: Readonly<Record<string, unknown>>,
): number {
  const expiresIn =
    value["expires_in"];

  if (
    typeof expiresIn !== "number" ||
    !Number.isFinite(expiresIn) ||
    expiresIn <= 0
  ) {
    throwInvalidTokenResponse();
  }

  return expiresIn;
}

function readRequiredTokenString(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string {
  const item =
    readOptionalString(value[key]);

  if (item === undefined) {
    throwInvalidTokenResponse();
  }

  return item;
}

function readOptionalTokenString(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  if (!(key in value)) {
    return undefined;
  }

  const item =
    readOptionalString(value[key]);

  if (item === undefined) {
    throwInvalidTokenResponse();
  }

  return item;
}

function readTokenSetString(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string {
  const item =
    readOptionalString(value[key]);

  if (item === undefined) {
    throwInvalidTokenSet();
  }

  return item;
}

function readOptionalTokenSetString(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  if (!(key in value)) {
    return undefined;
  }

  const item =
    readOptionalString(value[key]);

  if (item === undefined) {
    throwInvalidTokenSet();
  }

  return item;
}

function readRequiredIdentityString(
  value: Readonly<Record<string, unknown>>,
  key: string,
  message: string,
): string {
  const item =
    readOptionalString(value[key]);

  if (item === undefined) {
    throwInvalidIdentity(message);
  }

  return item;
}

function readOptionalIdentityString(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  if (!(key in value)) {
    return undefined;
  }

  const item =
    readOptionalString(value[key]);

  if (item === undefined) {
    throwInvalidIdentity(
      `Aquari identity claim '${key}' is invalid.`,
    );
  }

  return item;
}

function readOptionalIdentityBoolean(
  value: Readonly<Record<string, unknown>>,
  key: string,
): boolean | undefined {
  if (!(key in value)) {
    return undefined;
  }

  const item = value[key];

  if (typeof item !== "boolean") {
    throwInvalidIdentity(
      `Aquari identity claim '${key}' is invalid.`,
    );
  }

  return item;
}

function readOptionalString(
  value: unknown,
): string | undefined {
  return (
    typeof value === "string" &&
    value.length > 0
  )
    ? value
    : undefined;
}

function throwInvalidTokenResponse(): never {
  throw new AquariOAuthError({
    code: "invalid_token_response",
    message:
      "Aquari returned an invalid token response.",
  });
}

function throwInvalidTokenSet(): never {
  throw new AquariOAuthError({
    code: "invalid_token_set",
    message:
      "Aquari refresh requires a valid SDK token set.",
  });
}

function throwInvalidIdentity(
  message: string,
): never {
  throw new AquariOAuthError({
    code: "invalid_identity",
    message,
  });
}

function throwInvalidUserInfoResponse(): never {
  throw new AquariOAuthError({
    code: "invalid_userinfo_response",
    message:
      "Aquari returned an invalid UserInfo response.",
  });
}

function throwInvalidIdToken(
  message: string,
): never {
  throw new AquariOAuthError({
    code: "invalid_id_token",
    message,
  });
}

async function fetchOAuthResponse(
  fetchImplementation: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
  externalSignal: AbortSignal | undefined,
): Promise<Response> {
  const controller =
    new AbortController();

  const timeoutState =
    new AbortController();

  const timeout =
    setTimeout(
      () => {
        timeoutState.abort();
        controller.abort();
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

  try {
    return await fetchImplementation(
      url,
      {
        ...init,
        signal: controller.signal,
      },
    );
  } catch (cause) {
    if (timeoutState.signal.aborted) {
      throw new AquariTimeoutError(
        timeoutMs,
        { cause },
      );
    }

    if (externalSignal?.aborted === true) {
      throw new AquariTransportError(
        "Aquari request was cancelled.",
        {
          cause,
          cancelled: true,
        },
      );
    }

    throw new AquariTransportError(
      "Aquari OAuth request failed before a valid response was received.",
      { cause },
    );
  } finally {
    clearTimeout(timeout);

    externalSignal?.removeEventListener(
      "abort",
      abortFromExternal,
    );
  }
}

function combineAbortSignals(
  primary: AbortSignal,
  secondary: AbortSignal | undefined,
): {
  signal: AbortSignal;
  cleanup: () => void;
} {
  const controller =
    new AbortController();

  const abortFromPrimary = (): void => {
    controller.abort(primary.reason);
  };

  const abortFromSecondary = (): void => {
    controller.abort(secondary?.reason);
  };

  if (primary.aborted) {
    abortFromPrimary();
  } else {
    primary.addEventListener(
      "abort",
      abortFromPrimary,
      { once: true },
    );
  }

  if (secondary?.aborted === true) {
    abortFromSecondary();
  } else {
    secondary?.addEventListener(
      "abort",
      abortFromSecondary,
      { once: true },
    );
  }

  return {
    signal: controller.signal,
    cleanup: () => {
      primary.removeEventListener(
        "abort",
        abortFromPrimary,
      );

      secondary?.removeEventListener(
        "abort",
        abortFromSecondary,
      );
    },
  };
}

function isSignalAborted(
  signal: AbortSignal | undefined,
): boolean {
  return signal?.aborted === true;
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
