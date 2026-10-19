import {
  describe,
  expect,
  it,
} from "vitest";

import {
  AquariClient,
} from "../src/client.js";

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

function jsonResponse(
  value: unknown,
  init?: ResponseInit,
): Response {
  return new Response(
    JSON.stringify(value),
    {
      status: 200,
      headers: {
        "content-type":
          "application/json",
      },
      ...init,
    },
  );
}

function createClient(
  fetchImpl: typeof fetch,
): AquariClient {
  return new AquariClient({
    issuer:
      "https://dev.api.aquari.one/",
    clientId: "gemira-web",
    redirectUri:
      "https://gemira.app/auth/callback",
    scopes: [
      "openid",
      "passport.read",
    ],
    fetch: fetchImpl,
  });
}

describe(
  "Aquari Passport and trust APIs",
  () => {
    it(
      "reads the connected Passport without requiring a subject argument",
      async () => {
        let authorization = "";

        const fetchImpl:
          typeof fetch =
          (input, init) => {
            authorization =
              new Headers(
                init?.headers,
              ).get(
                "authorization",
              ) ?? "";

            expect(
              requestUrl(input),
            ).toBe(
              "https://dev.api.aquari.one/api/v1/passport",
            );

            return Promise.resolve(
              jsonResponse({
                passport: {
                  id:
                    "11111111-1111-1111-1111-111111111111",
                  passportNumber:
                    "AQ-00000001",
                  subjectId:
                    "22222222-2222-2222-2222-222222222222",
                  profile: {
                    displayName:
                      "Emmanuel",
                    handle:
                      "@emmanuel.aquari.one",
                    avatarUrl: null,
                    publicUrl:
                      "https://aquari.one/@emmanuel",
                    verified: true,
                    visibility:
                      "public",
                  },
                  signals: {
                    total: 6,
                  },
                },
              }),
            );
          };

        const passport =
          await createClient(
            fetchImpl,
          ).passport.get({
            accessToken:
              "access-token",
          });

        expect(authorization).toBe(
          "Bearer access-token",
        );

        expect(
          passport.passportNumber,
        ).toBe("AQ-00000001");

        expect(
          passport.signals.total,
        ).toBe(6);
      },
    );

    it(
      "maps signal provenance to ergonomic families while preserving wire types",
      async () => {
        const fetchImpl:
          typeof fetch =
          () =>
            Promise.resolve(
              jsonResponse({
                items: [
                  {
                    id:
                      "33333333-3333-3333-3333-333333333333",
                    subjectId:
                      "22222222-2222-2222-2222-222222222222",
                    sourceType:
                      "user_entitlement",
                    definitionId:
                      "44444444-4444-4444-4444-444444444444",
                    type:
                      "credential",
                    name:
                      "Gemira Pro",
                    description:
                      "Product access",
                    imageUrl: null,
                    issuer: {
                      type:
                        "application",
                      id:
                        "55555555-5555-5555-5555-555555555555",
                      name:
                        "Gemira",
                      logoUrl: null,
                    },
                    issuedAt:
                      "2026-09-24T18:00:00Z",
                    expiresAt: null,
                    visibility:
                      "connected",
                    verified: true,
                  },
                ],
                page: {
                  nextCursor: null,
                  hasMore: false,
                },
              }),
            );

        const page =
          await createClient(
            fetchImpl,
          ).passport.signals.list({
            accessToken:
              "access-token",
          });

        expect(
          page.items[0]?.family,
        ).toBe("entitlement");

        expect(
          page.items[0]
            ?.sourceType,
        ).toBe(
          "user_entitlement",
        );

        expect(
          page.items[0]
            ?.presentationType,
        ).toBe("credential");
      },
    );

    it(
      "keeps Passport cursors opaque while iterating pages",
      async () => {
        let calls = 0;

        const fetchImpl:
          typeof fetch =
          input => {
            calls += 1;

            const url =
              new URL(
                requestUrl(input),
              );

            const second =
              url.searchParams.get(
                "cursor",
              ) === "opaque.next";

            return Promise.resolve(
              jsonResponse({
                items: [
                  {
                    id:
                      second
                        ? "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
                        : "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    subjectId:
                      "22222222-2222-2222-2222-222222222222",
                    sourceType:
                      "badge",
                    definitionId: null,
                    type:
                      "badge",
                    name:
                      second
                        ? "Second"
                        : "First",
                    description: "",
                    imageUrl: null,
                    issuer: {
                      type: "aquari",
                      id: "aquari",
                      name:
                        "Aquari One",
                      logoUrl: null,
                    },
                    issuedAt:
                      "2026-09-24T18:00:00Z",
                    expiresAt: null,
                    visibility:
                      "public",
                    verified: true,
                  },
                ],
                page: {
                  nextCursor:
                    second
                      ? null
                      : "opaque.next",
                  hasMore:
                    !second,
                },
              }),
            );
          };

        const names: string[] =
          [];

        for await (
          const signal
          of createClient(
            fetchImpl,
          ).passport.signals.iterate({
            accessToken:
              "access-token",
            limit: 1,
          })
        ) {
          names.push(
            signal.name,
          );
        }

        expect(names).toEqual([
          "First",
          "Second",
        ]);

        expect(calls).toBe(2);
      },
    );

    it(
      "reads the exact anonymous public Passport shape",
      async () => {
        const fetchImpl:
          typeof fetch =
          input => {
            expect(
              requestUrl(input),
            ).toBe(
              "https://dev.api.aquari.one/api/v1/public/passports/%40emmanuel.aquari.one",
            );

            return Promise.resolve(
              jsonResponse({
                displayName:
                  "Emmanuel",
                handle:
                  "@emmanuel.aquari.one",
                avatarUrl: null,
                publicUrl:
                  "https://aquari.one/@emmanuel",
                verified: true,
                signals: [],
              }),
            );
          };

        const passport =
          await createClient(
            fetchImpl,
          ).passport.getPublic(
            "@emmanuel.aquari.one",
          );

        expect(passport.signals)
          .toEqual([]);
      },
    );

    it(
      "reads trust outcomes with provenance",
      async () => {
        const fetchImpl:
          typeof fetch =
          () =>
            Promise.resolve(
              jsonResponse({
                evaluationId:
                  "11111111-1111-1111-1111-111111111111",
                subjectId:
                  "22222222-2222-2222-2222-222222222222",
                consumerApplicationId:
                  "33333333-3333-3333-3333-333333333333",
                evaluatedAt:
                  "2026-09-24T18:00:00Z",
                outcomes: [
                  {
                    type:
                      "feature",
                    value:
                      "beta-dashboard",
                    supports: [
                      {
                        mappingId:
                          "44444444-4444-4444-4444-444444444444",
                        mappingVersion:
                          3,
                        trustedIssuerId:
                          "55555555-5555-5555-5555-555555555555",
                        signal: {
                          id:
                            "66666666-6666-6666-6666-666666666666",
                          signalFamily:
                            "credential",
                          definitionId:
                            null,
                          authority: {
                            type:
                              "organization",
                            id:
                              "77777777-7777-7777-7777-777777777777",
                          },
                          scope: null,
                          issuedAt:
                            "2026-09-24T17:00:00Z",
                          expiresAt:
                            null,
                        },
                      },
                    ],
                  },
                ],
              }),
            );

        const evaluation =
          await createClient(
            fetchImpl,
          ).trust.evaluate({
            accessToken:
              "access-token",
          });

        expect(
          evaluation
            .outcomes[0]
            ?.supports[0]
            ?.mappingVersion,
        ).toBe(3);
      },
    );

    it(
      "rejects out-of-range signal page sizes before making a request",
      async () => {
        let calls = 0;

        const fetchImpl:
          typeof fetch =
          () => {
            calls += 1;

            return Promise.resolve(
              jsonResponse({}),
            );
          };

        await expect(
          createClient(
            fetchImpl,
          ).passport.signals.list({
            accessToken:
              "access-token",
            limit: 101,
          }),
        ).rejects.toThrow(
          RangeError,
        );

        expect(calls).toBe(0);
      },
    );
  },
);
