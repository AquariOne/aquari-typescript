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
} from "../src/errors.js";

const ISSUER =
  "https://dev.api.aquari.one/";

const CLIENT_ID = "gemira-web";

const REDIRECT_URI =
  "http://localhost:3000/auth/callback";

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

function createClient(
  fetchImplementation: typeof fetch,
  clientSecret?: string,
): AquariClient {
  return new AquariClient({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    ...(clientSecret !== undefined
      ? { clientSecret }
      : {}),
    redirectUri: REDIRECT_URI,
    scopes: [
      "openid",
      "profile",
      "email",
      "offline_access",
    ],
    fetch: fetchImplementation,
    maxRetries: 0,
  });
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
      kid: "test-key",
      alg: "RS256",
      use: "sig",
    },
  };
}

describe(
  "Aquari authorization completion",
  () => {
    it(
      "exchanges the code, validates the ID token, and returns identity plus tokens",
      async () => {
        const signing =
          await createSigningMaterial();

        let idToken = "";
        let tokenRequestBody = "";

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
              tokenRequestBody =
                requestBody(init);

              return Promise.resolve(
                jsonResponse({
                  token_type: "Bearer",
                  access_token:
                    "access-token-value",
                  id_token: idToken,
                  refresh_token:
                    "refresh-token-value",
                  expires_in: 3600,
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

        const authorization =
          await client.auth.begin();

        const now =
          Math.floor(Date.now() / 1_000);

        idToken =
          await new SignJWT({
            nonce:
              authorization.transaction.nonce,
            preferred_username:
              "@emmanuel.aquari.one",
            name: "Emmanuel",
            email:
              "emmanuel@example.com",
            email_verified: true,
            "https://aquari.one/claims/canonical_handle":
              "@emmanuel.aquari.one",
          })
            .setProtectedHeader({
              alg: "RS256",
              kid: "test-key",
            })
            .setIssuer(ISSUER)
            .setAudience(CLIENT_ID)
            .setSubject(
              "11111111-1111-1111-1111-111111111111",
            )
            .setIssuedAt(now)
            .setExpirationTime(
              now + 300,
            )
            .sign(signing.privateKey);

        const callback =
          new URL(REDIRECT_URI);

        callback.searchParams.set(
          "code",
          "authorization-code",
        );

        callback.searchParams.set(
          "state",
          authorization.transaction.state,
        );

        callback.searchParams.set(
          "iss",
          ISSUER,
        );

        const completed =
          await client.auth.complete(
            callback,
            authorization.transaction,
          );

        expect(
          completed.identity.subject,
        ).toBe(
          "11111111-1111-1111-1111-111111111111",
        );

        expect(
          completed.identity.handle,
        ).toBe(
          "@emmanuel.aquari.one",
        );

        expect(
          completed.identity.emailVerified,
        ).toBe(true);

        expect(
          completed.tokens.accessToken,
        ).toBe("access-token-value");

        expect(
          completed.tokens.refreshToken,
        ).toBe("refresh-token-value");

        expect(
          completed.tokens.scopes,
        ).toEqual([
          "openid",
          "profile",
          "email",
          "offline_access",
        ]);

        const tokenParameters =
          new URLSearchParams(
            tokenRequestBody,
          );

        expect(
          tokenParameters.get(
            "grant_type",
          ),
        ).toBe(
          "authorization_code",
        );

        expect(
          tokenParameters.get(
            "code_verifier",
          ),
        ).toBe(
          authorization.transaction
            .codeVerifier,
        );

        expect(
          tokenParameters.get(
            "client_secret",
          ),
        ).toBe(null);
      },
    );

    it(
      "rejects a state mismatch before making another request",
      async () => {
        let calls = 0;

        const fetchImplementation:
          typeof fetch =
          () => {
            calls += 1;

            return Promise.resolve(
              jsonResponse(
                discoveryDocument(),
              ),
            );
          };

        const client =
          createClient(
            fetchImplementation,
          );

        const authorization =
          await client.auth.begin();

        expect(calls).toBe(1);

        const callback =
          new URL(REDIRECT_URI);

        callback.searchParams.set(
          "code",
          "authorization-code",
        );

        callback.searchParams.set(
          "state",
          "not-the-original-state",
        );

        callback.searchParams.set(
          "iss",
          ISSUER,
        );

        await expect(
          client.auth.complete(
            callback,
            authorization.transaction,
          ),
        ).rejects.toMatchObject({
          code: "state_mismatch",
        });

        expect(calls).toBe(1);
      },
    );

    it(
      "surfaces a validated OAuth authorization error without exchanging a code",
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

        const authorization =
          await client.auth.begin();

        const callback =
          new URL(REDIRECT_URI);

        callback.searchParams.set(
          "error",
          "access_denied",
        );

        callback.searchParams.set(
          "error_description",
          "The user denied the request.",
        );

        callback.searchParams.set(
          "state",
          authorization.transaction.state,
        );

        try {
          await client.auth.complete(
            callback,
            authorization.transaction,
          );

          throw new Error(
            "Expected OAuth completion to fail.",
          );
        } catch (error) {
          expect(error).toBeInstanceOf(
            AquariOAuthError,
          );

          if (
            !(error instanceof AquariOAuthError)
          ) {
            throw error;
          }

          expect(error.code).toBe(
            "access_denied",
          );

          expect(
            error.errorDescription,
          ).toBe(
            "The user denied the request.",
          );
        }
      },
    );

    it(
      "requires the issuer parameter on successful callbacks when discovery advertises it",
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

        const authorization =
          await client.auth.begin();

        const callback =
          new URL(REDIRECT_URI);

        callback.searchParams.set(
          "code",
          "authorization-code",
        );

        callback.searchParams.set(
          "state",
          authorization.transaction.state,
        );

        await expect(
          client.auth.complete(
            callback,
            authorization.transaction,
          ),
        ).rejects.toMatchObject({
          code: "missing_issuer",
        });
      },
    );

    it(
      "rejects an ID token with the wrong nonce",
      async () => {
        const signing =
          await createSigningMaterial();

        let idToken = "";

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
                  access_token: "access",
                  id_token: idToken,
                  expires_in: 3600,
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

        const authorization =
          await client.auth.begin();

        const now =
          Math.floor(Date.now() / 1_000);

        idToken =
          await new SignJWT({
            nonce: "wrong-nonce",
          })
            .setProtectedHeader({
              alg: "RS256",
              kid: "test-key",
            })
            .setIssuer(ISSUER)
            .setAudience(CLIENT_ID)
            .setSubject(
              "11111111-1111-1111-1111-111111111111",
            )
            .setIssuedAt(now)
            .setExpirationTime(
              now + 300,
            )
            .sign(signing.privateKey);

        const callback =
          new URL(REDIRECT_URI);

        callback.searchParams.set(
          "code",
          "authorization-code",
        );

        callback.searchParams.set(
          "state",
          authorization.transaction.state,
        );

        callback.searchParams.set(
          "iss",
          ISSUER,
        );

        await expect(
          client.auth.complete(
            callback,
            authorization.transaction,
          ),
        ).rejects.toMatchObject({
          code: "invalid_id_token",
        });
      },
    );

    it(
      "rejects an ID token signed by a key that is not in Aquari JWKS",
      async () => {
        const trustedSigning =
          await createSigningMaterial();

        const untrustedSigning =
          await createSigningMaterial();

        let idToken = "";

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
                  access_token: "access",
                  id_token: idToken,
                  expires_in: 3600,
                }),
              );
            }

            if (
              url ===
              `${ISSUER}.well-known/jwks`
            ) {
              return Promise.resolve(
                jsonResponse({
                  keys: [trustedSigning.jwk],
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

        const authorization =
          await client.auth.begin();

        const now =
          Math.floor(Date.now() / 1_000);

        idToken =
          await new SignJWT({
            nonce:
              authorization.transaction.nonce,
          })
            .setProtectedHeader({
              alg: "RS256",
              kid: "test-key",
            })
            .setIssuer(ISSUER)
            .setAudience(CLIENT_ID)
            .setSubject(
              "11111111-1111-1111-1111-111111111111",
            )
            .setIssuedAt(now)
            .setExpirationTime(
              now + 300,
            )
            .sign(
              untrustedSigning.privateKey,
            );

        const callback =
          new URL(REDIRECT_URI);

        callback.searchParams.set(
          "code",
          "authorization-code",
        );

        callback.searchParams.set(
          "state",
          authorization.transaction.state,
        );

        callback.searchParams.set(
          "iss",
          ISSUER,
        );

        await expect(
          client.auth.complete(
            callback,
            authorization.transaction,
          ),
        ).rejects.toMatchObject({
          code: "invalid_id_token",
        });
      },
    );

    it(
      "sends client_secret_post only when a confidential client secret is configured",
      async () => {
        const signing =
          await createSigningMaterial();

        let idToken = "";
        let tokenRequestBody = "";

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
              tokenRequestBody =
                requestBody(init);

              return Promise.resolve(
                jsonResponse({
                  token_type: "Bearer",
                  access_token: "access",
                  id_token: idToken,
                  expires_in: 3600,
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
            "server-only-secret",
          );

        const authorization =
          await client.auth.begin();

        const now =
          Math.floor(Date.now() / 1_000);

        idToken =
          await new SignJWT({
            nonce:
              authorization.transaction.nonce,
          })
            .setProtectedHeader({
              alg: "RS256",
              kid: "test-key",
            })
            .setIssuer(ISSUER)
            .setAudience(CLIENT_ID)
            .setSubject(
              "11111111-1111-1111-1111-111111111111",
            )
            .setIssuedAt(now)
            .setExpirationTime(
              now + 300,
            )
            .sign(signing.privateKey);

        const callback =
          new URL(REDIRECT_URI);

        callback.searchParams.set(
          "code",
          "authorization-code",
        );

        callback.searchParams.set(
          "state",
          authorization.transaction.state,
        );

        callback.searchParams.set(
          "iss",
          ISSUER,
        );

        await client.auth.complete(
          callback,
          authorization.transaction,
        );

        const tokenParameters =
          new URLSearchParams(
            tokenRequestBody,
          );

        expect(
          tokenParameters.get(
            "client_secret",
          ),
        ).toBe(
          "server-only-secret",
        );
      },
    );

    it(
      "rejects an expired authorization transaction",
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

        const authorization =
          await client.auth.begin();

        const expired = {
          ...authorization.transaction,
          createdAt:
            Date.now() -
            (16 * 60 * 1_000),
        };

        const callback =
          new URL(REDIRECT_URI);

        callback.searchParams.set(
          "code",
          "authorization-code",
        );

        callback.searchParams.set(
          "state",
          authorization.transaction.state,
        );

        callback.searchParams.set(
          "iss",
          ISSUER,
        );

        await expect(
          client.auth.complete(
            callback,
            expired,
          ),
        ).rejects.toMatchObject({
          code: "expired_transaction",
        });
      },
    );
  },
);
