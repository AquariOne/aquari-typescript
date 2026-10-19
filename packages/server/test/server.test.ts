import {
  createHmac,
} from "node:crypto";

import {
  describe,
  expect,
  it,
} from "vitest";

import {
  AquariServerClient,
  AquariWebhookVerificationError,
  verifyAquariWebhook,
} from "../src/index.js";

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

describe(
  "AquariServerClient",
  () => {
    it(
      "authenticates machine health with the Aquari API key",
      async () => {
        let authorization = "";

        const fetchImpl:
          typeof fetch =
          (input, init) => {
            expect(
              requestUrl(input),
            ).toBe(
              "https://dev.api.aquari.one/api/v1/machine/health",
            );

            authorization =
              new Headers(
                init?.headers,
              ).get(
                "authorization",
              ) ?? "";

            return Promise.resolve(
              jsonResponse({
                ok: true,
                actorType:
                  "api_key",
                apiKeyId:
                  "11111111-1111-1111-1111-111111111111",
                applicationId:
                  "22222222-2222-2222-2222-222222222222",
                environment:
                  "production",
              }),
            );
          };

        const client =
          new AquariServerClient({
            apiUrl:
              "https://dev.api.aquari.one/",
            apiKey:
              "aqk_test_secret",
            fetch: fetchImpl,
          });

        const health =
          await client.machine
            .health();

        expect(authorization).toBe(
          "Bearer aqk_test_secret",
        );

        expect(health.ok).toBe(true);
      },
    );

    it(
      "generates one stable idempotency key for an issue request",
      async () => {
        let key = "";

        const fetchImpl:
          typeof fetch =
          (input, init) => {
            expect(
              requestUrl(input),
            ).toContain(
              "/badge-definitions/",
            );

            key =
              new Headers(
                init?.headers,
              ).get(
                "idempotency-key",
              ) ?? "";

            return Promise.resolve(
              jsonResponse({
                signal: {
                  id:
                    "11111111-1111-1111-1111-111111111111",
                  definitionId:
                    "22222222-2222-2222-2222-222222222222",
                  subjectId:
                    "33333333-3333-3333-3333-333333333333",
                  issuer: {
                    type:
                      "application",
                    id:
                      "44444444-4444-4444-4444-444444444444",
                    name:
                      "Example",
                    logoUrl:
                      null,
                  },
                  name:
                    "Founder",
                  description:
                    null,
                  criteria:
                    null,
                  imageUrl:
                    null,
                  defaultVisibility:
                    "connected",
                  status:
                    "active",
                  issuedAt:
                    "2026-09-24T18:00:00Z",
                  revokedAt:
                    null,
                },
                idempotentReplay:
                  false,
              }),
            );
          };

        const client =
          new AquariServerClient({
            apiUrl:
              "https://dev.api.aquari.one/",
            apiKey:
              "aqk_test_secret",
            fetch: fetchImpl,
          });

        await client.issuer.badges.issue(
          "22222222-2222-2222-2222-222222222222",
          {
            subjectId:
              "33333333-3333-3333-3333-333333333333",
          },
        );

        expect(key.length)
          .toBeGreaterThan(0);
      },
    );

    it(
      "preserves an application-supplied idempotency key",
      async () => {
        let key = "";

        const fetchImpl:
          typeof fetch =
          (_input, init) => {
            key =
              new Headers(
                init?.headers,
              ).get(
                "idempotency-key",
              ) ?? "";

            return Promise.resolve(
              jsonResponse({
                signal: {
                  id:
                    "11111111-1111-1111-1111-111111111111",
                  definitionId:
                    "22222222-2222-2222-2222-222222222222",
                  subjectId:
                    "33333333-3333-3333-3333-333333333333",
                  issuer: {
                    type:
                      "application",
                    id:
                      "44444444-4444-4444-4444-444444444444",
                    name:
                      "Example",
                    logoUrl:
                      null,
                  },
                  name:
                    "Founder",
                  description:
                    null,
                  criteria:
                    null,
                  imageUrl:
                    null,
                  defaultVisibility:
                    "connected",
                  status:
                    "active",
                  issuedAt:
                    "2026-09-24T18:00:00Z",
                  revokedAt:
                    null,
                },
                idempotentReplay:
                  true,
              }),
            );
          };

        const client =
          new AquariServerClient({
            apiUrl:
              "https://dev.api.aquari.one/",
            apiKey:
              "aqk_test_secret",
            fetch: fetchImpl,
          });

        await client.issuer.badges.issue(
          "22222222-2222-2222-2222-222222222222",
          {
            subjectId:
              "33333333-3333-3333-3333-333333333333",
          },
          {
            idempotencyKey:
              "order_123_founder",
          },
        );

        expect(key).toBe(
          "order_123_founder",
        );
      },
    );
  },
);

describe(
  "Aquari webhook verification",
  () => {
    const secret =
      "whsec_test_example";

    const timestamp =
      "1788297600";

    const body =
      "{\"id\":\"example\"}";

    it(
      "matches the Aquari HMAC conformance vector",
      () => {
        const signature =
          createHmac(
            "sha256",
            secret,
          )
            .update(
              `${timestamp}.${body}`,
            )
            .digest("hex");

        expect(signature).toBe(
          "355f3f5abdc879a7a32dc165cc312529204d8f5b8d7f19ef847fc54e7483ee56",
        );
      },
    );

    it(
      "rejects a modified raw body before JSON parsing",
      () => {
        const signature =
          createHmac(
            "sha256",
            secret,
          )
            .update(
              `${timestamp}.${body}`,
            )
            .digest("hex");

        expect(
          () =>
            verifyAquariWebhook({
              secret,
              headers: {
                "Aquari-Timestamp":
                  timestamp,
                "Aquari-Signature":
                  `v1=${signature}`,
              },
              rawBody:
                "{\"id\":\"modified\"}",
              now:
                new Date(
                  Number(timestamp) *
                    1_000,
                ),
            }),
        ).toThrow(
          AquariWebhookVerificationError,
        );
      },
    );

    it(
      "preserves unknown valid future webhook events",
      () => {
        const rawBody =
          JSON.stringify({
            id:
              "11111111-1111-1111-1111-111111111111",
            type:
              "future.event.created",
            version:
              "2027-01-01",
            created_at:
              "2026-09-24T18:00:00Z",
            organization_id:
              "22222222-2222-2222-2222-222222222222",
            application_id:
              "33333333-3333-3333-3333-333333333333",
            environment_id:
              "44444444-4444-4444-4444-444444444444",
            data: {
              object: {
                future: true,
              },
            },
          });

        const signature =
          createHmac(
            "sha256",
            secret,
          )
            .update(
              `${timestamp}.${rawBody}`,
            )
            .digest("hex");

        const event =
          verifyAquariWebhook({
            secret,
            headers: {
              "Aquari-Timestamp":
                timestamp,
              "Aquari-Signature":
                `v1=${signature}`,
            },
            rawBody,
            now:
              new Date(
                Number(timestamp) *
                  1_000,
              ),
          });

        expect(event.known)
          .toBe(false);

        expect(event.type)
          .toBe(
            "future.event.created",
          );
      },
    );
  },
);
