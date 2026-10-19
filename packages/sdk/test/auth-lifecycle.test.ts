import {
  exportJWK,
  generateKeyPair,
  SignJWT,
} from "jose";

import {
  describe,
  expect,
  it,
} from "vitest";

import {
  AquariClient,
} from "../src/client.js";

import {
  AquariOAuthError,
  AquariTimeoutError,
} from "../src/errors.js";

import type {
  AquariTokenSet,
} from "../src/oauth.js";

const ISSUER =
  "https://dev.api.aquari.one/";

const CLIENT_ID = "gemira-web";

const REDIRECT_URI =
  "http://localhost:3000/auth/callback";

const SUBJECT =
  "11111111-1111-1111-1111-111111111111";

function jsonResponse(
  body: unknown,
  status = 200,
): Response {
  return new Response(
    JSON.stringify(body),
    {
      status,
      headers: {
        "content-type":
          "application/json",
      },
    },
  );
}

function discoveryDocument():
Readonly<Record<string, unknown>> {
  return {
    issuer: ISSUER,
    authorization_endpoint:
      `${ISSUER}connect/authorize`,
    token_endpoint:
      `${ISSUER}connect/token`,
    userinfo_endpoint:
      `${ISSUER}connect/userinfo`,
    jwks_uri:
      `${ISSUER}.well-known/jwks`,
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
    ],
    response_types_supported: ["code"],
    code_challenge_methods_supported: [
      "S256",
    ],
    id_token_signing_alg_values_supported: [
      "RS256",
    ],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic",
    ],
    authorization_response_iss_parameter_supported:
      true,
  };
}

function requestUrl(
  input: RequestInfo | URL,
): string {
  if (typeof input === "string") {
    return input;
  }

  if (input instanceof URL) {
    return input.toString();
  }

  return input.url;
}

function requestBody(
  init: RequestInit | undefined,
): string {
  const body = init?.body;

  if (typeof body !== "string") {
    throw new Error(
      "Expected a string request body.",
    );
  }

  return body;
}

function authorizationHeader(
  init: RequestInit | undefined,
): string | null {
  return new Headers(
    init?.headers,
  ).get("authorization");
}

function createClient(
  fetchImplementation: typeof fetch,
  options: {
    clientSecret?: string;
    timeoutMs?: number;
    maxRetries?: number;
  } = {},
): AquariClient {
  return new AquariClient({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    ...(options.clientSecret !== undefined
      ? {
          clientSecret:
            options.clientSecret,
        }
      : {}),
    redirectUri: REDIRECT_URI,
    scopes: [
      "openid",
      "profile",
      "email",
      "offline_access",
    ],
    fetch: fetchImplementation,
    ...(options.timeoutMs !== undefined
      ? { timeoutMs: options.timeoutMs }
      : {}),
    ...(options.maxRetries !== undefined
      ? { maxRetries: options.maxRetries }
      : {}),
  });
}

function currentTokens(
  overrides: Partial<AquariTokenSet> = {},
): AquariTokenSet {
  return {
    subject: SUBJECT,
    tokenType: "Bearer",
    accessToken: "access-old",
    idToken: "id-old",
    refreshToken: "refresh-old",
    expiresIn: 3600,
    expiresAt: Date.now() + 3_600_000,
    scopes: [
      "openid",
      "profile",
      "email",
      "offline_access",
    ],
    ...overrides,
  };
}

async function createSigningMaterial() {
  const pair =
    await generateKeyPair("RS256");

  const exported =
    await exportJWK(pair.publicKey);

  return {
    privateKey: pair.privateKey,
    jwk: {
      ...exported,
      kid: "refresh-key",
      alg: "RS256",
      use: "sig",
    },
  };
}

async function createRefreshIdToken(
  privateKey: CryptoKey,
  audience = CLIENT_ID,
  subject = SUBJECT,
): Promise<string> {
  const now =
    Math.floor(Date.now() / 1_000);

  return await new SignJWT({
    preferred_username:
      "@emmanuel.aquari.one",
  })
    .setProtectedHeader({
      alg: "RS256",
      kid: "refresh-key",
    })
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setSubject(subject)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
}

describe(
  "Aquari token refresh",
  () => {
    it(
      "rotates replacement credentials and validates a replacement ID token",
      async () => {
        const signing =
          await createSigningMaterial();

        const replacementIdToken =
          await createRefreshIdToken(
            signing.privateKey,
          );

        let tokenBody = "";

        const fetchImplementation:
          typeof fetch =
          (input, init) => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/token`
            ) {
              tokenBody =
                requestBody(init);

              return Promise.resolve(
                jsonResponse({
                  token_type: "Bearer",
                  access_token: "access-new",
                  id_token:
                    replacementIdToken,
                  refresh_token:
                    "refresh-new",
                  expires_in: 1800,
                  scope:
                    "openid profile email offline_access",
                }),
              );
            }

            if (
              url ===
              `${ISSUER}.well-known/jwks`
            ) {
              return Promise.resolve(
                jsonResponse({
                  keys: [signing.jwk],
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        const refreshed =
          await client.auth.refresh(
            currentTokens(),
          );

        expect(
          refreshed.accessToken,
        ).toBe("access-new");

        expect(
          refreshed.idToken,
        ).toBe(replacementIdToken);

        expect(
          refreshed.refreshToken,
        ).toBe("refresh-new");

        expect(
          refreshed.expiresIn,
        ).toBe(1800);

        const parameters =
          new URLSearchParams(tokenBody);

        expect(
          parameters.get("grant_type"),
        ).toBe("refresh_token");

        expect(
          parameters.get("refresh_token"),
        ).toBe("refresh-old");

        expect(
          parameters.get("client_id"),
        ).toBe(CLIENT_ID);
      },
    );

    it(
      "preserves the existing refresh and ID tokens when the server does not rotate them",
      async () => {
        const fetchImplementation:
          typeof fetch =
          input => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/token`
            ) {
              return Promise.resolve(
                jsonResponse({
                  token_type: "Bearer",
                  access_token: "access-new",
                  expires_in: 900,
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        const refreshed =
          await client.auth.refresh(
            currentTokens(),
          );

        expect(
          refreshed.idToken,
        ).toBe("id-old");

        expect(
          refreshed.refreshToken,
        ).toBe("refresh-old");

        expect(
          refreshed.scopes,
        ).toEqual([
          "openid",
          "profile",
          "email",
          "offline_access",
        ]);
      },
    );

    it(
      "sends client_secret_post credentials for a confidential refresh",
      async () => {
        let tokenBody = "";

        const fetchImplementation:
          typeof fetch =
          (input, init) => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/token`
            ) {
              tokenBody =
                requestBody(init);

              return Promise.resolve(
                jsonResponse({
                  token_type: "Bearer",
                  access_token: "access-new",
                  expires_in: 900,
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
            {
              clientSecret:
                "server-secret",
            },
          );

        await client.auth.refresh(
          currentTokens(),
        );

        const parameters =
          new URLSearchParams(tokenBody);

        expect(
          parameters.get("client_secret"),
        ).toBe("server-secret");
      },
    );

    it(
      "propagates invalid_grant without retrying the refresh request",
      async () => {
        let tokenCalls = 0;

        const fetchImplementation:
          typeof fetch =
          input => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/token`
            ) {
              tokenCalls += 1;

              return Promise.resolve(
                jsonResponse(
                  {
                    error: "invalid_grant",
                    error_description:
                      "Refresh token is no longer valid.",
                  },
                  400,
                ),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
            { maxRetries: 2 },
          );

        try {
          await client.auth.refresh(
            currentTokens(),
          );

          throw new Error(
            "Expected refresh to fail.",
          );
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(
            AquariOAuthError,
          );

          if (
            error instanceof
            AquariOAuthError
          ) {
            expect(error.code).toBe(
              "invalid_grant",
            );
          }
        }

        expect(tokenCalls).toBe(1);
      },
    );

    it(
      "rejects malformed optional replacement credentials instead of silently discarding them",
      async () => {
        const fetchImplementation:
          typeof fetch =
          input => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/token`
            ) {
              return Promise.resolve(
                jsonResponse({
                  token_type: "Bearer",
                  access_token: "access-new",
                  refresh_token: "",
                  expires_in: 900,
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        await expect(
          client.auth.refresh(
            currentTokens(),
          ),
        ).rejects.toBeInstanceOf(
          AquariOAuthError,
        );
      },
    );

    it(
      "rejects a replacement ID token that is not valid for this client",
      async () => {
        const signing =
          await createSigningMaterial();

        const replacementIdToken =
          await createRefreshIdToken(
            signing.privateKey,
            "different-client",
          );

        const fetchImplementation:
          typeof fetch =
          input => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/token`
            ) {
              return Promise.resolve(
                jsonResponse({
                  token_type: "Bearer",
                  access_token: "access-new",
                  id_token:
                    replacementIdToken,
                  expires_in: 900,
                }),
              );
            }

            if (
              url ===
              `${ISSUER}.well-known/jwks`
            ) {
              return Promise.resolve(
                jsonResponse({
                  keys: [signing.jwk],
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        try {
          await client.auth.refresh(
            currentTokens(),
          );

          throw new Error(
            "Expected refresh to reject the replacement ID token.",
          );
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(
            AquariOAuthError,
          );

          if (
            error instanceof
            AquariOAuthError
          ) {
            expect(error.code).toBe(
              "invalid_id_token",
            );
          }
        }
      },
    );

    it(
      "rejects a replacement ID token for a different subject",
      async () => {
        const signing =
          await createSigningMaterial();

        const replacementIdToken =
          await createRefreshIdToken(
            signing.privateKey,
            CLIENT_ID,
            "22222222-2222-2222-2222-222222222222",
          );

        const fetchImplementation:
          typeof fetch =
          input => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/token`
            ) {
              return Promise.resolve(
                jsonResponse({
                  token_type: "Bearer",
                  access_token: "access-new",
                  id_token:
                    replacementIdToken,
                  expires_in: 900,
                }),
              );
            }

            if (
              url ===
              `${ISSUER}.well-known/jwks`
            ) {
              return Promise.resolve(
                jsonResponse({
                  keys: [signing.jwk],
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        try {
          await client.auth.refresh(
            currentTokens(),
          );

          throw new Error(
            "Expected refresh subject mismatch to fail.",
          );
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(
            AquariOAuthError,
          );

          if (
            error instanceof
            AquariOAuthError
          ) {
            expect(error.code).toBe(
              "invalid_id_token",
            );
          }
        }
      },
    );

    it(
      "requires an existing refresh token",
      async () => {
        const fetchImplementation:
          typeof fetch =
          () =>
            Promise.resolve(
              jsonResponse(
                discoveryDocument(),
              ),
            );

        const client =
          createClient(
            fetchImplementation,
          );

        const tokens =
          currentTokens();

        const withoutRefresh: AquariTokenSet = {
          subject: tokens.subject,
          tokenType: tokens.tokenType,
          accessToken: tokens.accessToken,
          idToken: tokens.idToken,
          expiresIn: tokens.expiresIn,
          expiresAt: tokens.expiresAt,
          scopes: tokens.scopes,
        };

        try {
          await client.auth.refresh(
            withoutRefresh,
          );

          throw new Error(
            "Expected missing refresh token to fail.",
          );
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(
            AquariOAuthError,
          );

          if (
            error instanceof
            AquariOAuthError
          ) {
            expect(error.code).toBe(
              "missing_refresh_token",
            );
          }
        }
      },
    );

    it(
      "classifies an aborted refresh request as a timeout",
      async () => {
        const fetchImplementation:
          typeof fetch =
          (input, init) => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/token`
            ) {
              const signal = init?.signal;

              if (signal == null) {
                return Promise.reject(
                  new Error(
                    "Expected AbortSignal.",
                  ),
                );
              }

              return new Promise<Response>(
                (resolve, reject) => {
                  const fallback =
                    setTimeout(
                      () => {
                        resolve(
                          jsonResponse({
                            unexpected: true,
                          }),
                        );
                      },
                      60_000,
                    );

                  const abort = (): void => {
                    clearTimeout(fallback);

                    reject(
                      new DOMException(
                        "Aborted",
                        "AbortError",
                      ),
                    );
                  };

                  if (signal.aborted) {
                    abort();
                    return;
                  }

                  signal.addEventListener(
                    "abort",
                    abort,
                    { once: true },
                  );
                },
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
            { timeoutMs: 10 },
          );

        await expect(
          client.auth.refresh(
            currentTokens(),
          ),
        ).rejects.toBeInstanceOf(
          AquariTimeoutError,
        );
      },
    );
  },
);

describe(
  "Aquari UserInfo",
  () => {
    it(
      "maps the scope-shaped UserInfo response and sends the bearer access token",
      async () => {
        let bearer = "";

        const fetchImplementation:
          typeof fetch =
          (input, init) => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/userinfo`
            ) {
              bearer =
                authorizationHeader(init) ??
                "";

              return Promise.resolve(
                jsonResponse({
                  sub: SUBJECT,
                  preferred_username:
                    "@emmanuel.aquari.one",
                  "https://aquari.one/claims/canonical_handle":
                    "@emmanuel.aquari.one",
                  "https://aquari.one/claims/verified_handle":
                    "@emmanuel.aquari.one",
                  name: "Emmanuel",
                  picture:
                    "https://example.com/avatar.webp",
                  email:
                    "emmanuel@example.com",
                  email_verified: true,
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        const identity =
          await client.auth.userInfo(
            currentTokens({
              accessToken:
                "access-token-value",
            }),
          );

        expect(identity).toEqual({
          subject: SUBJECT,
          handle:
            "@emmanuel.aquari.one",
          canonicalHandle:
            "@emmanuel.aquari.one",
          verifiedHandle:
            "@emmanuel.aquari.one",
          name: "Emmanuel",
          pictureUrl:
            "https://example.com/avatar.webp",
          email:
            "emmanuel@example.com",
          emailVerified: true,
        });

        expect(bearer).toBe(
          "Bearer access-token-value",
        );
      },
    );

    it(
      "accepts a minimal UserInfo response containing only sub",
      async () => {
        const fetchImplementation:
          typeof fetch =
          input => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/userinfo`
            ) {
              return Promise.resolve(
                jsonResponse({
                  sub: SUBJECT,
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        expect(
          await client.auth.userInfo(
            currentTokens({
              accessToken:
                "access-token-value",
            }),
          ),
        ).toEqual({
          subject: SUBJECT,
        });
      },
    );

    it(
      "rejects UserInfo without a valid subject",
      async () => {
        const fetchImplementation:
          typeof fetch =
          input => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/userinfo`
            ) {
              return Promise.resolve(
                jsonResponse({
                  name: "Emmanuel",
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        try {
          await client.auth.userInfo(
            currentTokens({
              accessToken:
                "access-token-value",
            }),
          );

          throw new Error(
            "Expected invalid UserInfo to fail.",
          );
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(
            AquariOAuthError,
          );

          if (
            error instanceof
            AquariOAuthError
          ) {
            expect(error.code).toBe(
              "invalid_userinfo_response",
            );
          }
        }
      },
    );

    it(
      "rejects UserInfo for a different subject than the token set",
      async () => {
        const fetchImplementation:
          typeof fetch =
          input => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/userinfo`
            ) {
              return Promise.resolve(
                jsonResponse({
                  sub:
                    "22222222-2222-2222-2222-222222222222",
                  name: "Different user",
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        try {
          await client.auth.userInfo(
            currentTokens({
              accessToken:
                "access-token-value",
            }),
          );

          throw new Error(
            "Expected UserInfo subject mismatch to fail.",
          );
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(
            AquariOAuthError,
          );

          if (
            error instanceof
            AquariOAuthError
          ) {
            expect(error.code).toBe(
              "userinfo_subject_mismatch",
            );
          }
        }
      },
    );

    it(
      "rejects malformed known optional UserInfo claims",
      async () => {
        const fetchImplementation:
          typeof fetch =
          input => {
            const url = requestUrl(input);

            if (
              url ===
              `${ISSUER}.well-known/openid-configuration`
            ) {
              return Promise.resolve(
                jsonResponse(
                  discoveryDocument(),
                ),
              );
            }

            if (
              url ===
              `${ISSUER}connect/userinfo`
            ) {
              return Promise.resolve(
                jsonResponse({
                  sub: SUBJECT,
                  email_verified: "yes",
                }),
              );
            }

            return Promise.reject(
              new Error(
                `Unexpected request to ${url}`,
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        try {
          await client.auth.userInfo(
            currentTokens({
              accessToken:
                "access-token-value",
            }),
          );

          throw new Error(
            "Expected malformed UserInfo to fail.",
          );
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(
            AquariOAuthError,
          );

          if (
            error instanceof
            AquariOAuthError
          ) {
            expect(error.code).toBe(
              "invalid_userinfo_response",
            );
          }
        }
      },
    );
  },
);
