import {
  NextResponse,
} from "next/server";

import {
  AquariClient,
  AquariOAuthError,
  type AquariAuthorizationPrompt,
  type AquariAuthorizationTransaction,
  type AquariIdentity,
  type AquariTokenSet,
} from "@aquari-one/sdk";

import {
  InMemoryAquariRefreshLock,
  type AquariRefreshLock,
} from "./lock.js";

import type {
  AquariSessionStore,
} from "./store.js";

const TRANSACTION_TTL_MS =
  15 * 60 * 1_000;

const DEFAULT_SESSION_TTL_SECONDS =
  30 * 24 * 60 * 60;

const ACCESS_TOKEN_REFRESH_SKEW_MS =
  30 * 1_000;

/**
 * Configures the Aquari Next.js adapter, including OAuth settings, session storage,
 * refresh locking, cookies, and HTTP behavior.
 */
export interface CreateAquariOptions {
  /**
   * Sets the absolute Aquari issuer URL used by the core client and Next.js adapter.
   */
  issuer: string | URL;
  /**
   * Sets the OAuth client identifier registered for the Next.js application.
   */
  clientId: string;
  /**
   * Sets the confidential-client secret when the Next.js server uses a confidential OAuth
   * client. Never expose this value to browser code.
   */
  clientSecret?: string;
  /**
   * Sets the exact callback URI registered for the Next.js application.
   */
  redirectUri: string | URL;
  /**
   * Sets the OAuth scopes requested during sign-in. Include offline_access when the session
   * must refresh tokens.
   */
  scopes: readonly string[];
  /**
   * Sets the opaque server-side store for authorization transactions and application
   * sessions. Multi-instance production deployments must use shared storage.
   */
  sessionStore: AquariSessionStore;
  /**
   * Coordinates refresh-token rotation for one logical application session.
   *
   * The default lock is process-local. Multi-instance deployments must pass
   * a lock backed by infrastructure shared by every application instance.
   */
  refreshLock?: AquariRefreshLock;
  /**
   * Sets the Aquari request timeout in milliseconds.
   */
  timeoutMs?: number;
  /**
   * Sets the maximum number of HTTP retries after the first attempt.
   */
  maxRetries?: number;
  /**
   * Caps HTTP retry backoff in milliseconds.
   */
  maxRetryDelayMs?: number;
  /**
   * Overrides the fetch implementation used by the core client.
   */
  fetch?: typeof fetch;
  /**
   * Sets the browser cookie name that identifies opaque application session state.
   */
  sessionCookieName?: string;
  /**
   * Sets an optional same-host or parent domain for the durable application-session
   * cookie. Authorization transaction cookies always remain host-only.
   */
  sessionCookieDomain?: string;
  /**
   * Sets the browser cookie name that identifies the pending authorization transaction.
   */
  transactionCookieName?: string;
  /**
   * Controls whether the adapter marks its cookies Secure. Keep this enabled for HTTPS
   * production deployments.
   */
  secureCookies?: boolean;
  /**
   * Sets the maximum lifetime of opaque application session state in seconds.
   */
  sessionTtlSeconds?: number;
}

/**
 * Configures the local return path and optional OIDC prompt for Next.js sign-in.
 */
export interface AquariSignInOptions {
  /**
   * Sets a local application path for the post-callback redirect. The adapter rejects unsafe
   * external return targets.
   */
  returnTo?: string;
  /**
   * Sets the optional OpenID Connect prompt value for this sign-in request.
   */
  prompt?: AquariAuthorizationPrompt;
}

/**
 * Configures cancellation while a Next.js callback exchanges and validates authorization
 * state.
 */
export interface AquariCallbackOptions {
  /**
   * Cancels callback token exchange and validation when the AbortSignal is aborted.
   */
  signal?: AbortSignal;
}

/**
 * Configures the local return path after the Next.js adapter clears session state.
 */
export interface AquariSignOutOptions {
  /**
   * Sets a local application path for the redirect after local session state is cleared.
   */
  returnTo?: string;
}

/**
 * Contains the current Aquari token set and subject-bound identity.
 */
export interface AquariSession {
  user: {
    subject: string;
    handle?: string;
    name?: string;
    email?: string;
    emailVerified?: boolean;
    pictureUrl?: string;
  };
  scopes: readonly string[];
  expiresAt: Date;
}

/**
 * Defines the Next.js authentication operations provided by the Aquari adapter.
 */
export interface AquariNextAuth {
  /**
   * Creates the Authorization Code with S256 PKCE transaction and redirects the browser
   * to Aquari. The separate callback operation exchanges and validates the returned code.
   */
  signIn(
    request: Request,
    options?: AquariSignInOptions,
  ): Promise<Response>;

  /**
   * Completes the Next.js authorization callback, validates the stored transaction, creates
   * the application session, and redirects to the saved local return path.
   */
  callback(
    request: Request,
    options?: AquariCallbackOptions,
  ): Promise<Response>;

  /**
   * Reads and validates the local Aquari application session. Returns null when no usable
   * session exists.
   */
  getSession(
    request: Request,
  ): Promise<AquariSession | null>;

  /**
   * Returns a usable access token for the current application session. The adapter refreshes
   * expiring tokens under the configured refresh lock before it returns the token.
   */
  getAccessToken(
    request: Request,
  ): Promise<string | null>;

  /**
   * Clears local Aquari session and pending authorization state. This operation does not
   * grant or revoke application permissions.
   */
  signOut(
    request: Request,
    options?: AquariSignOutOptions,
  ): Promise<Response>;
}

/**
 * Contains the core Aquari client and the Next.js authentication adapter.
 */
export interface AquariNext {
  client: AquariClient;
  auth: AquariNextAuth;
}

interface StoredTransaction {
  version: 1;
  transaction:
    AquariAuthorizationTransaction;
  returnTo: string;
}

interface StoredSession {
  version: 1;
  tokens: AquariTokenSet;
  identity: AquariIdentity;
}

interface ResolvedOptions {
  store: AquariSessionStore;
  refreshLock: AquariRefreshLock;
  sessionCookieName: string;
  sessionCookieDomain?: string;
  transactionCookieName: string;
  secureCookies: boolean;
  sessionTtlSeconds: number;
}

/**
 * Creates the Aquari Next.js adapter, core SDK client, cookie/session behavior, and
 * refresh-lock integration from one configuration object.
 */
export function createAquari(
  options: CreateAquariOptions,
): AquariNext {
  const client =
    new AquariClient({
      issuer:
        options.issuer,
      clientId:
        options.clientId,
      redirectUri:
        options.redirectUri,
      scopes:
        options.scopes,
      ...(options.clientSecret !== undefined
        ? {
            clientSecret:
              options.clientSecret,
          }
        : {}),
      ...(options.timeoutMs !== undefined
        ? {
            timeoutMs:
              options.timeoutMs,
          }
        : {}),
      ...(options.maxRetries !== undefined
        ? {
            maxRetries:
              options.maxRetries,
          }
        : {}),
      ...(options.maxRetryDelayMs !==
      undefined
        ? {
            maxRetryDelayMs:
              options.maxRetryDelayMs,
          }
        : {}),
      ...(options.fetch !== undefined
        ? {
            fetch:
              options.fetch,
          }
        : {}),
    });

  const resolved =
    resolveOptions(options);

  const auth:
    AquariNextAuth = {
      signIn:
        (
          request,
          signInOptions = {},
        ) =>
          signIn(
            client,
            resolved,
            request,
            signInOptions,
          ),

      callback:
        (
          request,
          callbackOptions = {},
        ) =>
          callback(
            client,
            resolved,
            request,
            callbackOptions,
          ),

      getSession:
        request =>
          getSession(
            client,
            resolved,
            request,
          ),

      getAccessToken:
        async request => {
          const stored =
            await requireSession(
              client,
              resolved,
              request,
            );

          return stored?.tokens
            .accessToken ??
            null;
        },

      signOut:
        (
          request,
          signOutOptions = {},
        ) =>
          signOut(
            resolved,
            request,
            signOutOptions,
          ),
    };

  return {
    client,
    auth,
  };
}

async function signIn(
  client: AquariClient,
  options: ResolvedOptions,
  request: Request,
  input: AquariSignInOptions,
): Promise<Response> {
  const returnTo =
    normalizeReturnTo(
      request,
      input.returnTo,
    );

  const beginOptions: {
    prompt?: AquariAuthorizationPrompt;
  } = {};

  if (input.prompt !== undefined) {
    beginOptions.prompt =
      input.prompt;
  }

  const authorization =
    await client.auth.begin(
      beginOptions,
    );

  const transactionId =
    createOpaqueId();

  const stored:
    StoredTransaction = {
      version: 1,
      transaction:
        authorization.transaction,
      returnTo,
    };

  await options.store.set(
    transactionKey(
      transactionId,
    ),
    JSON.stringify(stored),
    new Date(
      Date.now() +
        TRANSACTION_TTL_MS,
    ),
  );

  const response =
    redirectResponse(
      authorization.url,
    );

  setResponseCookie(
    response,
    options.transactionCookieName,
    transactionId,
    {
      maxAgeSeconds:
        Math.floor(
          TRANSACTION_TTL_MS /
            1_000,
        ),
      secure:
        options.secureCookies,
    },
  );

  return response;
}

async function callback(
  client: AquariClient,
  options: ResolvedOptions,
  request: Request,
  input: AquariCallbackOptions,
): Promise<Response> {
  const cookies =
    parseCookieHeader(
      request.headers.get(
        "cookie",
      ),
    );

  const transactionId =
    cookies.get(
      options.transactionCookieName,
    );

  if (
    transactionId === undefined
  ) {
    return errorResponse(
      "Aquari authorization transaction cookie is missing.",
      400,
    );
  }

  const key =
    transactionKey(
      transactionId,
    );

  const raw =
    await options.store.get(key);

  if (raw === null) {
    return errorResponse(
      "Aquari authorization transaction is missing or expired.",
      400,
    );
  }

  const stored =
    parseStoredTransaction(raw);

  let completed:
    Awaited<
      ReturnType<
        typeof client.auth.complete
      >
    >;

  try {
    completed =
      await client.auth.complete(
        buildAuthorizationCallbackUrl(request, client.redirectUri),
        stored.transaction,
        input.signal !== undefined
          ? {
              signal:
                input.signal,
            }
          : {},
      );
  } catch (error: unknown) {
    await options.store.delete(
      key,
    );

    throw error;
  }

  await options.store.delete(
    key,
  );

  const sessionId =
    createOpaqueId();

  const session:
    StoredSession = {
      version: 1,
      tokens:
        completed.tokens,
      identity:
        completed.identity,
    };

  const ttlSeconds =
    completed.tokens.refreshToken !==
    undefined
      ? options.sessionTtlSeconds
      : Math.max(
          1,
          Math.floor(
            (
              completed.tokens.expiresAt -
              Date.now()
            ) /
              1_000,
          ),
        );

  await options.store.set(
    sessionKey(sessionId),
    JSON.stringify(session),
    new Date(
      Date.now() +
        ttlSeconds *
          1_000,
    ),
  );

  const response =
    redirectResponse(
      stored.returnTo,
    );

  setResponseCookie(
    response,
    options.sessionCookieName,
    sessionId,
    {
      maxAgeSeconds:
        ttlSeconds,
      secure:
        options.secureCookies,
      ...(options.sessionCookieDomain !==
      undefined
        ? {
            domain:
              options.sessionCookieDomain,
          }
        : {}),
    },
  );

  setResponseCookie(
    response,
    options.transactionCookieName,
    "",
    {
      maxAgeSeconds: 0,
      secure:
        options.secureCookies,
    },
  );

  return response;
}

async function getSession(
  client: AquariClient,
  options: ResolvedOptions,
  request: Request,
): Promise<AquariSession | null> {
  const stored =
    await requireSession(
      client,
      options,
      request,
    );

  if (stored === null) {
    return null;
  }

  return {
    user: {
      subject:
        stored.identity.subject,
      ...(stored.identity.handle !==
      undefined
        ? {
            handle:
              stored.identity.handle,
          }
        : {}),
      ...(stored.identity.name !==
      undefined
        ? {
            name:
              stored.identity.name,
          }
        : {}),
      ...(stored.identity.email !==
      undefined
        ? {
            email:
              stored.identity.email,
          }
        : {}),
      ...(stored.identity.emailVerified !==
      undefined
        ? {
            emailVerified:
              stored.identity
                .emailVerified,
          }
        : {}),
      ...(stored.identity.pictureUrl !==
      undefined
        ? {
            pictureUrl:
              stored.identity
                .pictureUrl,
          }
        : {}),
    },
    scopes:
      stored.tokens.scopes,
    expiresAt:
      new Date(
        stored.tokens.expiresAt,
      ),
  };
}

async function requireSession(
  client: AquariClient,
  options: ResolvedOptions,
  request: Request,
): Promise<StoredSession | null> {
  const cookies =
    parseCookieHeader(
      request.headers.get(
        "cookie",
      ),
    );

  const sessionId =
    cookies.get(
      options.sessionCookieName,
    );

  if (sessionId === undefined) {
    return null;
  }

  const key =
    sessionKey(sessionId);

  const raw =
    await options.store.get(key);

  if (raw === null) {
    return null;
  }

  const stored =
    parseStoredSession(raw);

  if (
    stored.tokens.expiresAt -
      Date.now() >
    ACCESS_TOKEN_REFRESH_SKEW_MS
  ) {
    return stored;
  }

  return await options.refreshLock
    .runExclusive(
      key,
      async () =>
        await refreshSessionUnderLock(
          client,
          options,
          key,
        ),
    );
}

async function refreshSessionUnderLock(
  client: AquariClient,
  options: ResolvedOptions,
  key: string,
): Promise<StoredSession | null> {
  const raw =
    await options.store.get(key);

  if (raw === null) {
    return null;
  }

  let stored =
    parseStoredSession(raw);

  if (
    stored.tokens.expiresAt -
      Date.now() >
    ACCESS_TOKEN_REFRESH_SKEW_MS
  ) {
    return stored;
  }

  if (
    stored.tokens.refreshToken ===
    undefined
  ) {
    await options.store.delete(key);
    return null;
  }

  try {
    const refreshed =
      await client.auth.refresh(
        stored.tokens,
      );

    stored = {
      ...stored,
      tokens:
        refreshed,
    };

    await options.store.set(
      key,
      JSON.stringify(stored),
      new Date(
        Date.now() +
          options.sessionTtlSeconds *
            1_000,
      ),
    );

    return stored;
  } catch (error: unknown) {
    if (
      error instanceof AquariOAuthError &&
      error.code === "invalid_grant"
    ) {
      const currentRaw =
        await options.store.get(key);

      if (currentRaw === raw) {
        await options.store.delete(key);
      }

      return null;
    }

    throw error;
  }
}

async function signOut(
  options: ResolvedOptions,
  request: Request,
  input: AquariSignOutOptions,
): Promise<Response> {
  const cookies =
    parseCookieHeader(
      request.headers.get(
        "cookie",
      ),
    );

  const sessionId =
    cookies.get(
      options.sessionCookieName,
    );

  if (sessionId !== undefined) {
    const key =
      sessionKey(sessionId);

    await options.refreshLock
      .runExclusive(
        key,
        async () => {
          await options.store.delete(
            key,
          );
        },
      );
  }

  const returnTo =
    input.returnTo !== undefined
      ? normalizeReturnTo(
          request,
          input.returnTo,
        )
      : undefined;

  const response =
    returnTo !== undefined
      ? redirectResponse(returnTo)
      : new NextResponse(
          null,
          {
            status: 204,
          },
        );

  setResponseCookie(
    response,
    options.sessionCookieName,
    "",
    {
      maxAgeSeconds: 0,
      secure:
        options.secureCookies,
      ...(options.sessionCookieDomain !==
      undefined
        ? {
            domain:
              options.sessionCookieDomain,
          }
        : {}),
    },
  );

  return response;
}

function resolveOptions(
  options: CreateAquariOptions,
): ResolvedOptions {
  const sessionCookieName =
    validateCookieName(
      options.sessionCookieName ??
      "aquari_session",
    );

  const transactionCookieName =
    validateCookieName(
      options.transactionCookieName ??
      "aquari_auth",
    );

  if (
    sessionCookieName ===
    transactionCookieName
  ) {
    throw new TypeError(
      "Aquari session and transaction cookie names must be different.",
    );
  }

  const ttl =
    options.sessionTtlSeconds ??
    DEFAULT_SESSION_TTL_SECONDS;

  if (
    !Number.isInteger(ttl) ||
    ttl < 60
  ) {
    throw new RangeError(
      "Aquari sessionTtlSeconds must be an integer of at least 60 seconds.",
    );
  }

  const redirectUrl =
    new URL(
      options.redirectUri.toString(),
    );

  const sessionCookieDomain =
    resolveSessionCookieDomain(
      options.sessionCookieDomain,
      redirectUrl.hostname,
    );

  return {
    store:
      options.sessionStore,
    refreshLock:
      options.refreshLock ??
      new InMemoryAquariRefreshLock(),
    sessionCookieName,
    ...(sessionCookieDomain !==
    undefined
      ? {
          sessionCookieDomain,
        }
      : {}),
    transactionCookieName,
    secureCookies:
      options.secureCookies ??
      redirectUrl.protocol ===
        "https:",
    sessionTtlSeconds:
      ttl,
  };
}

function parseStoredTransaction(
  raw: string,
): StoredTransaction {
  const value =
    parseStoredJson(
      raw,
      "authorization transaction",
    );

  if (
    value["version"] !== 1 ||
    typeof value["returnTo"] !==
      "string" ||
    typeof value["transaction"] !==
      "object" ||
    value["transaction"] === null ||
    Array.isArray(
      value["transaction"],
    )
  ) {
    throw new TypeError(
      "Stored Aquari authorization transaction is invalid.",
    );
  }

  return {
    version: 1,
    returnTo:
      value["returnTo"],
    transaction:
      value["transaction"] as
        AquariAuthorizationTransaction,
  };
}

function parseStoredSession(
  raw: string,
): StoredSession {
  const value =
    parseStoredJson(
      raw,
      "session",
    );

  if (
    value["version"] !== 1 ||
    typeof value["tokens"] !==
      "object" ||
    value["tokens"] === null ||
    Array.isArray(
      value["tokens"],
    ) ||
    typeof value["identity"] !==
      "object" ||
    value["identity"] === null ||
    Array.isArray(
      value["identity"],
    )
  ) {
    throw new TypeError(
      "Stored Aquari session is invalid.",
    );
  }

  const tokens =
    value["tokens"] as
      Readonly<Record<
        string,
        unknown
      >>;

  const identity =
    value["identity"] as
      Readonly<Record<
        string,
        unknown
      >>;

  if (
    typeof tokens["subject"] !==
      "string" ||
    typeof tokens["tokenType"] !==
      "string" ||
    tokens["tokenType"] !==
      "Bearer" ||
    typeof tokens["accessToken"] !==
      "string" ||
    typeof tokens["idToken"] !==
      "string" ||
    typeof tokens["expiresIn"] !==
      "number" ||
    typeof tokens["expiresAt"] !==
      "number" ||
    !Array.isArray(tokens["scopes"]) ||
    typeof identity["subject"] !==
      "string"
  ) {
    throw new TypeError(
      "Stored Aquari session is invalid.",
    );
  }

  const rawScopes:
    readonly unknown[] =
    tokens["scopes"];

  const scopes:
    string[] = [];

  for (
    const scope
    of rawScopes
  ) {
    if (typeof scope !== "string") {
      throw new TypeError(
        "Stored Aquari session is invalid.",
      );
    }

    scopes.push(scope);
  }

  const tokenSet:
    AquariTokenSet = {
      subject:
        tokens["subject"],
      tokenType: "Bearer",
      accessToken:
        tokens["accessToken"],
      idToken:
        tokens["idToken"],
      ...(typeof tokens[
        "refreshToken"
      ] === "string"
        ? {
            refreshToken:
              tokens[
                "refreshToken"
              ],
          }
        : {}),
      expiresIn:
        tokens["expiresIn"],
      expiresAt:
        tokens["expiresAt"],
      scopes:
        Object.freeze(scopes),
  };

  const parsedIdentity:
    AquariIdentity = {
      subject:
        identity["subject"],
      ...(typeof identity[
        "handle"
      ] === "string"
        ? {
            handle:
              identity["handle"],
          }
        : {}),
      ...(typeof identity[
        "canonicalHandle"
      ] === "string"
        ? {
            canonicalHandle:
              identity[
                "canonicalHandle"
              ],
          }
        : {}),
      ...(typeof identity[
        "verifiedHandle"
      ] === "string"
        ? {
            verifiedHandle:
              identity[
                "verifiedHandle"
              ],
          }
        : {}),
      ...(typeof identity[
        "name"
      ] === "string"
        ? {
            name:
              identity["name"],
          }
        : {}),
      ...(typeof identity[
        "pictureUrl"
      ] === "string"
        ? {
            pictureUrl:
              identity["pictureUrl"],
          }
        : {}),
      ...(typeof identity[
        "email"
      ] === "string"
        ? {
            email:
              identity["email"],
          }
        : {}),
      ...(typeof identity[
        "emailVerified"
      ] === "boolean"
        ? {
            emailVerified:
              identity[
                "emailVerified"
              ],
          }
        : {}),
    };

  if (
    parsedIdentity.subject !==
    tokenSet.subject
  ) {
    throw new TypeError(
      "Stored Aquari session subject does not match the token subject.",
    );
  }

  return {
    version: 1,
    tokens:
      tokenSet,
    identity:
      parsedIdentity,
  };
}

function parseStoredJson(
  raw: string,
  label: string,
): Readonly<
  Record<string, unknown>
> {
  let value: unknown;

  try {
    value =
      JSON.parse(raw) as unknown;
  } catch {
    throw new TypeError(
      `Stored Aquari ${label} is not valid JSON.`,
    );
  }

  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    throw new TypeError(
      `Stored Aquari ${label} is invalid.`,
    );
  }

  return value as Readonly<
    Record<string, unknown>
  >;
}

function parseCookieHeader(
  header: string | null,
): Map<string, string> {
  const cookies =
    new Map<string, string>();

  if (
    header === null ||
    header.length === 0
  ) {
    return cookies;
  }

  for (
    const part
    of header.split(";")
  ) {
    const separator =
      part.indexOf("=");

    if (separator <= 0) {
      continue;
    }

    const name =
      part.slice(
        0,
        separator,
      ).trim();

    const rawValue =
      part.slice(
        separator + 1,
      ).trim();

    try {
      cookies.set(
        name,
        decodeURIComponent(
          rawValue,
        ),
      );
    } catch {
      continue;
    }
  }

  return cookies;
}

function redirectResponse(
  location: string,
): NextResponse {
  const response =
    new NextResponse(
      null,
      {
        status: 302,
      },
    );

  response.headers.set(
    "location",
    location,
  );

  return response;
}

function setResponseCookie(
  response: NextResponse,
  name: string,
  value: string,
  options: {
    maxAgeSeconds: number;
    secure: boolean;
    domain?: string;
  },
): void {
  response.cookies.set(
    name,
    value,
    {
      path: "/",
      httpOnly: true,
      sameSite: "lax",
      secure:
        options.secure,
      maxAge:
        options.maxAgeSeconds,
      ...(options.domain !== undefined
        ? {
            domain:
              options.domain,
          }
        : {}),
    },
  );
}

function resolveSessionCookieDomain(
  value: string | undefined,
  redirectHostname: string,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  const trimmed =
    value.trim().toLowerCase();

  const normalized =
    trimmed.startsWith(".")
      ? trimmed.slice(1)
      : trimmed;

  if (
    normalized.length === 0 ||
    normalized.length > 253 ||
    normalized.endsWith(".") ||
    normalized.includes("..") ||
    !normalized
      .split(".")
      .every(
        isValidCookieDomainLabel,
      )
  ) {
    throw new TypeError(
      "Aquari sessionCookieDomain must be a valid DNS hostname.",
    );
  }

  const redirectHost =
    redirectHostname.toLowerCase();

  if (
    redirectHost !== normalized &&
    !redirectHost.endsWith(
      `.${normalized}`,
    )
  ) {
    throw new TypeError(
      "Aquari sessionCookieDomain must match the redirect host or one of its parent domains.",
    );
  }

  return normalized;
}

function isValidCookieDomainLabel(
  value: string,
): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u
    .test(value);
}

function normalizeReturnTo(
  request: Request,
  value: string | undefined,
): string {
  const raw =
    value ??
    "/";

  if (
    !raw.startsWith("/") ||
    raw.startsWith("//") ||
    raw.includes("\\")
  ) {
    throw new TypeError(
      "Aquari returnTo must be a local application path.",
    );
  }

  const requestUrl =
    new URL(request.url);

  const target =
    new URL(
      raw,
      requestUrl.origin,
    );

  if (
    target.origin !==
    requestUrl.origin
  ) {
    throw new TypeError(
      "Aquari returnTo must stay on the current application origin.",
    );
  }

  return `${target.pathname}${target.search}${target.hash}`;
}

function validateCookieName(
  value: string,
): string {
  if (
    value.length === 0 ||
    !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u
      .test(value)
  ) {
    throw new TypeError(
      "Aquari cookie names must be valid HTTP cookie names.",
    );
  }

  return value;
}

function transactionKey(
  id: string,
): string {
  return `aquari:transaction:${id}`;
}

function sessionKey(
  id: string,
): string {
  return `aquari:session:${id}`;
}

function createOpaqueId(): string {
  return globalThis.crypto
    .randomUUID()
    .replaceAll("-", "");
}

function errorResponse(
  message: string,
  status: number,
): Response {
  return Response.json(
    {
      error:
        message,
    },
    {
      status,
    },
  );
}

/**
 * Reconstruct the OAuth callback URL from the configured public redirect URI
 * and the response query received by the application.
 *
 * A Next.js Request URL can contain an internal reverse-proxy origin
 * (for example http://127.0.0.1:3201) even though the OAuth client is
 * registered with a public HTTPS redirect URI. The configured redirect URI
 * remains authoritative; only the callback query comes from the request.
 */
function buildAuthorizationCallbackUrl(
  request: Request,
  redirectUri: string | URL,
): URL {
  const callbackUrl = new URL(redirectUri.toString());
  callbackUrl.search = new URL(request.url).search;
  return callbackUrl;
}
