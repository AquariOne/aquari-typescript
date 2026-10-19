import {
  describe,
  expect,
  it,
} from "vitest";

import {
  InMemoryAquariSessionStore,
  createAquari,
} from "../src/index.js";

function jsonResponse(
  value: unknown,
): Response {
  return new Response(
    JSON.stringify(value),
    {
      status: 200,
      headers: {
        "content-type":
          "application/json",
      },
    },
  );
}

function discoveryFetch():
  typeof fetch {
  return () =>
    Promise.resolve(
      jsonResponse({
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
        id_token_signing_alg_values_supported: [
          "RS256",
        ],
        code_challenge_methods_supported: [
          "S256",
        ],
        token_endpoint_auth_methods_supported: [
          "none",
          "client_secret_post",
        ],
        authorization_response_iss_parameter_supported:
          true,
      }),
    );
}

describe(
  "@aquari-one/nextjs",
  () => {
    it(
      "starts authorization with an opaque transaction cookie and safe returnTo",
      async () => {
        const aquari =
          createAquari({
            issuer:
              "https://dev.api.aquari.one/",
            clientId:
              "gemira-web",
            redirectUri:
              "https://gemira.app/auth/callback",
            scopes: [
              "openid",
              "profile",
            ],
            sessionStore:
              new InMemoryAquariSessionStore(),
            fetch:
              discoveryFetch(),
          });

        const response =
          await aquari.auth.signIn(
            new Request(
              "https://gemira.app/login",
            ),
            {
              returnTo:
                "/dashboard?hello=1",
            },
          );

        expect(response.status)
          .toBe(302);

        expect(
          response.headers.get(
            "location",
          ),
        ).toContain(
          "/connect/authorize",
        );

        expect(
          response.headers.get(
            "set-cookie",
          ),
        ).toContain(
          "aquari_auth=",
        );
      },
    );

    it(
      "rejects cross-origin returnTo values before redirecting",
      async () => {
        const aquari =
          createAquari({
            issuer:
              "https://dev.api.aquari.one/",
            clientId:
              "gemira-web",
            redirectUri:
              "https://gemira.app/auth/callback",
            scopes: [
              "openid",
            ],
            sessionStore:
              new InMemoryAquariSessionStore(),
            fetch:
              discoveryFetch(),
          });

        await expect(
          aquari.auth.signIn(
            new Request(
              "https://gemira.app/login",
            ),
            {
              returnTo:
                "https://evil.example/",
            },
          ),
        ).rejects.toThrow(
          "local application path",
        );
      },
    );

    it(
      "uses an opaque session cookie and clears it during sign-out",
      async () => {
        const aquari =
          createAquari({
            issuer:
              "https://dev.api.aquari.one/",
            clientId:
              "gemira-web",
            redirectUri:
              "https://gemira.app/auth/callback",
            scopes: [
              "openid",
            ],
            sessionStore:
              new InMemoryAquariSessionStore(),
            fetch:
              discoveryFetch(),
          });

        const response =
          await aquari.auth.signOut(
            new Request(
              "https://gemira.app/account",
              {
                headers: {
                  cookie:
                    "aquari_session=opaque-session-id",
                },
              },
            ),
          );

        expect(response.status)
          .toBe(204);

        expect(
          response.headers.get(
            "set-cookie",
          ),
        ).toContain(
          "Max-Age=0",
        );
      },
    );

    it(
      "expires development in-memory values instead of returning stale data",
      async () => {
        const store =
          new InMemoryAquariSessionStore();

        await expect(
          store.set(
            "expired",
            "value",
            new Date(
              Date.now() - 1,
            ),
          ),
        ).rejects.toThrow(
          RangeError,
        );
      },
    );
  },
);
