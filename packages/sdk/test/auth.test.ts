import {
  describe,
  expect,
  it,
} from "vitest";

import {
  AquariClient,
} from "../src/client.js";

import {
  AquariConfigurationError,
} from "../src/errors.js";

import {
  createS256CodeChallenge,
} from "../src/pkce.js";

function jsonResponse(
  body: unknown,
): Response {
  return new Response(
    JSON.stringify(body),
    {
      status: 200,
      headers: {
        "content-type":
          "application/json",
      },
    },
  );
}

function discoveryDocument(
  overrides:
    Readonly<Record<string, unknown>> = {},
): Readonly<Record<string, unknown>> {
  return {
    issuer:
      "https://dev.api.aquari.one/",
    authorization_endpoint:
      "https://dev.api.aquari.one/connect/authorize",
    token_endpoint:
      "https://dev.api.aquari.one/connect/token",
    userinfo_endpoint:
      "https://dev.api.aquari.one/connect/userinfo",
    jwks_uri:
      "https://dev.api.aquari.one/.well-known/jwks",
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
    ],
    response_types_supported: [
      "code",
    ],
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
    ...overrides,
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

function createClient(
  fetchImplementation: typeof fetch,
): AquariClient {
  return new AquariClient({
    issuer:
      "https://dev.api.aquari.one/",
    clientId: "gemira-web",
    redirectUri:
      "http://localhost:3000/auth/callback",
    scopes: [
      "openid",
      "profile",
      "passport.read",
    ],
    fetch: fetchImplementation,
    maxRetries: 0,
  });
}

describe(
  "Aquari OIDC discovery",
  () => {
    it(
      "loads and caches validated discovery metadata",
      async () => {
        let calls = 0;

        const fetchImplementation:
          typeof fetch =
          input => {
            calls += 1;

            expect(
              requestUrl(input),
            ).toBe(
              "https://dev.api.aquari.one/.well-known/openid-configuration",
            );

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

        const first =
          await client.auth.discover();

        const second =
          await client.auth.discover();

        expect(first).toBe(second);
        expect(calls).toBe(1);

        expect(
          first.authorizationEndpoint,
        ).toBe(
          "https://dev.api.aquari.one/connect/authorize",
        );

        expect(
          first.codeChallengeMethodsSupported,
        ).toContain("S256");
      },
    );

    it(
      "can explicitly refresh discovery metadata",
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

        await client.auth.discover();

        await client.auth.discover({
          forceRefresh: true,
        });

        expect(calls).toBe(2);
      },
    );

    it(
      "rejects an issuer mismatch",
      async () => {
        const fetchImplementation:
          typeof fetch =
          () =>
            Promise.resolve(
              jsonResponse(
                discoveryDocument({
                  issuer:
                    "https://other.example/",
                }),
              ),
            );

        const client =
          createClient(
            fetchImplementation,
          );

        await expect(
          client.auth.discover(),
        ).rejects.toBeInstanceOf(
          AquariConfigurationError,
        );
      },
    );

    it(
      "rejects discovery without S256",
      async () => {
        const fetchImplementation:
          typeof fetch =
          () =>
            Promise.resolve(
              jsonResponse(
                discoveryDocument({
                  code_challenge_methods_supported:
                    ["plain"],
                }),
              ),
            );

        const client =
          createClient(
            fetchImplementation,
          );

        await expect(
          client.auth.discover(),
        ).rejects.toBeInstanceOf(
          AquariConfigurationError,
        );
      },
    );
  },
);

describe(
  "Aquari authorization begin",
  () => {
    it(
      "builds a secure authorization-code request",
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
          await client.auth.begin({
            prompt: "consent",
          });

        const url =
          new URL(
            authorization.url,
          );

        expect(url.origin).toBe(
          "https://dev.api.aquari.one",
        );

        expect(url.pathname).toBe(
          "/connect/authorize",
        );

        expect(
          url.searchParams.get(
            "client_id",
          ),
        ).toBe("gemira-web");

        expect(
          url.searchParams.get(
            "redirect_uri",
          ),
        ).toBe(
          "http://localhost:3000/auth/callback",
        );

        expect(
          url.searchParams.get(
            "response_type",
          ),
        ).toBe("code");

        expect(
          url.searchParams.get(
            "scope",
          ),
        ).toBe(
          "openid profile passport.read",
        );

        expect(
          url.searchParams.get(
            "code_challenge_method",
          ),
        ).toBe("S256");

        expect(
          url.searchParams.get(
            "prompt",
          ),
        ).toBe("consent");

        expect(
          authorization.transaction.version,
        ).toBe(1);

        expect(
          authorization.transaction.issuer,
        ).toBe(
          "https://dev.api.aquari.one/",
        );

        expect(
          authorization.transaction.state,
        ).toMatch(
          /^[A-Za-z0-9_-]{43}$/u,
        );

        expect(
          authorization.transaction.nonce,
        ).toMatch(
          /^[A-Za-z0-9_-]{43}$/u,
        );

        expect(
          authorization.transaction.codeVerifier,
        ).toMatch(
          /^[A-Za-z0-9_-]{64}$/u,
        );

        const expectedChallenge =
          await createS256CodeChallenge(
            authorization
              .transaction
              .codeVerifier,
          );

        expect(
          url.searchParams.get(
            "code_challenge",
          ),
        ).toBe(
          expectedChallenge,
        );

        expect(
          url.searchParams.get("state"),
        ).toBe(
          authorization.transaction.state,
        );

        expect(
          url.searchParams.get("nonce"),
        ).toBe(
          authorization.transaction.nonce,
        );
      },
    );

    it(
      "does not add unrequested scopes",
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
          new AquariClient({
            issuer:
              "https://dev.api.aquari.one/",
            clientId: "minimal-app",
            redirectUri:
              "https://example.com/callback",
            scopes: ["openid"],
            fetch:
              fetchImplementation,
            maxRetries: 0,
          });

        const authorization =
          await client.auth.begin();

        const url =
          new URL(
            authorization.url,
          );

        expect(
          url.searchParams.get("scope"),
        ).toBe("openid");
      },
    );
  },
);
