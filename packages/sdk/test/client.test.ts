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

describe(
  "AquariClient configuration",
  () => {
    it(
      "normalizes the issuer and preserves explicit scopes",
      () => {
        const client =
          new AquariClient({
            issuer:
              "https://dev.api.aquari.one",
            clientId: "gemira-web",
            redirectUri:
              "http://localhost:3000/auth/callback",
            scopes: [
              "openid",
              "profile",
              "email",
            ],
          });

        expect(client.issuer).toBe(
          "https://dev.api.aquari.one/",
        );

        expect(client.clientId).toBe(
          "gemira-web",
        );

        expect(client.redirectUri).toBe(
          "http://localhost:3000/auth/callback",
        );

        expect(client.scopes).toEqual([
          "openid",
          "profile",
          "email",
        ]);
      },
    );

    it(
      "requires an explicit openid scope",
      () => {
        expect(
          () =>
            new AquariClient({
              issuer:
                "https://dev.api.aquari.one/",
              clientId: "example",
              redirectUri:
                "https://example.com/callback",
              scopes: [
                "profile",
              ],
            }),
        ).toThrow(
          AquariConfigurationError,
        );
      },
    );

    it(
      "rejects duplicate or whitespace-bearing scopes",
      () => {
        expect(
          () =>
            new AquariClient({
              issuer:
                "https://dev.api.aquari.one/",
              clientId: "example",
              redirectUri:
                "https://example.com/callback",
              scopes: [
                "openid",
                "openid",
              ],
            }),
        ).toThrow(
          AquariConfigurationError,
        );

        expect(
          () =>
            new AquariClient({
              issuer:
                "https://dev.api.aquari.one/",
              clientId: "example",
              redirectUri:
                "https://example.com/callback",
              scopes: [
                "openid",
                "passport read",
              ],
            }),
        ).toThrow(
          AquariConfigurationError,
        );
      },
    );

    it(
      "rejects malformed redirect URIs",
      () => {
        expect(
          () =>
            new AquariClient({
              issuer:
                "https://dev.api.aquari.one/",
              clientId: "example",
              redirectUri:
                "/relative/callback",
              scopes: ["openid"],
            }),
        ).toThrow(
          AquariConfigurationError,
        );

        expect(
          () =>
            new AquariClient({
              issuer:
                "https://dev.api.aquari.one/",
              clientId: "example",
              redirectUri:
                "https://example.com/callback#fragment",
              scopes: ["openid"],
            }),
        ).toThrow(
          AquariConfigurationError,
        );
      },
    );

    it(
      "rejects client IDs containing whitespace",
      () => {
        expect(
          () =>
            new AquariClient({
              issuer:
                "https://dev.api.aquari.one/",
              clientId: "gemira web",
              redirectUri:
                "https://example.com/callback",
              scopes: ["openid"],
            }),
        ).toThrow(
          AquariConfigurationError,
        );
      },
    );
  },
);
