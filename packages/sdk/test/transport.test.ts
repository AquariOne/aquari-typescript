import {
  describe,
  expect,
  it,
} from "vitest";

import {
  AquariApiError,
  AquariQuotaError,
  AquariRateLimitError,
  AquariTimeoutError,
} from "../src/errors.js";

import {
  AquariHttpTransport,
  parseRetryAfterMs,
} from "../src/transport.js";

function jsonResponse(
  body: unknown,
  init: ResponseInit = {},
): Response {
  const headers =
    new Headers(init.headers);

  headers.set(
    "content-type",
    "application/json",
  );

  return new Response(
    JSON.stringify(body),
    {
      ...init,
      headers,
    },
  );
}

describe(
  "AquariHttpTransport",
  () => {
    it(
      "sends requests relative to the configured Aquari base URL",
      async () => {
        let receivedUrl:
          string | undefined;

        const fetchImpl:
          typeof fetch =
          input => {
            if (typeof input === "string") {
              receivedUrl = input;
            } else if (input instanceof URL) {
              receivedUrl = input.toString();
            } else {
              receivedUrl = input.url;
            }

            return Promise.resolve(
              jsonResponse({
                ok: true,
              }),
            );
          };

        const transport =
          new AquariHttpTransport({
            baseUrl:
              "https://api.aquari.one",
            fetch: fetchImpl,
            maxRetries: 0,
          });

        const result =
          await transport.request<{
            ok: boolean;
          }>({
            path:
              "/api/v1/passport",
          });

        expect(receivedUrl).toBe(
          "https://api.aquari.one/api/v1/passport",
        );

        expect(result.ok).toBe(true);
      },
    );

    it(
      "parses Aquari quota errors",
      async () => {
        const fetchImpl:
          typeof fetch =
          () =>
            Promise.resolve(
              jsonResponse(
                {
                  error: {
                    code:
                      "QuotaExceeded",
                    message: "quota",
                    details: {
                      resource: [
                        "api_request",
                      ],
                      current: ["5"],
                      limit: ["5"],
                    },
                  },
                },
                {
                  status: 403,
                },
              ),
            );

        const transport =
          new AquariHttpTransport({
            baseUrl:
              "https://api.aquari.one",
            fetch: fetchImpl,
            maxRetries: 0,
          });

        try {
          await transport.request({
            path:
              "/api/v1/machine/example",
          });

          throw new Error(
            "Expected request to fail.",
          );
        } catch (error) {
          expect(error).toBeInstanceOf(
            AquariQuotaError,
          );

          if (
            !(
              error instanceof
              AquariQuotaError
            )
          ) {
            throw error;
          }

          expect(error.current).toBe(5);
          expect(error.limit).toBe(5);
        }
      },
    );

    it(
      "preserves Retry-After on rate limits",
      async () => {
        const fetchImpl:
          typeof fetch =
          () =>
            Promise.resolve(
              jsonResponse(
                {
                  error: {
                    code:
                      "RateLimitExceeded",
                    message:
                      "Too many requests.",
                  },
                },
                {
                  status: 429,
                  headers: {
                    "retry-after": "7",
                  },
                },
              ),
            );

        const transport =
          new AquariHttpTransport({
            baseUrl:
              "https://api.aquari.one",
            fetch: fetchImpl,
            maxRetries: 0,
          });

        try {
          await transport.request({
            path:
              "/api/v1/machine/context",
          });

          throw new Error(
            "Expected request to fail.",
          );
        } catch (error) {
          expect(error).toBeInstanceOf(
            AquariRateLimitError,
          );

          if (
            !(
              error instanceof
              AquariRateLimitError
            )
          ) {
            throw error;
          }

          expect(
            error.retryAfterMs,
          ).toBe(7_000);
        }
      },
    );

    it(
      "automatically retries a safe GET",
      async () => {
        let calls = 0;

        const fetchImpl:
          typeof fetch =
          () => {
            calls += 1;

            if (calls === 1) {
              return Promise.resolve(
                jsonResponse(
                  {
                    error: {
                      code:
                        "InternalError",
                      message:
                        "temporary",
                    },
                  },
                  {
                    status: 503,
                    headers: {
                      "retry-after": "0",
                    },
                  },
                ),
              );
            }

            return Promise.resolve(
              jsonResponse({
                ok: true,
              }),
            );
          };

        const transport =
          new AquariHttpTransport({
            baseUrl:
              "https://api.aquari.one",
            fetch: fetchImpl,
            maxRetries: 1,
          });

        const result =
          await transport.request<{
            ok: boolean;
          }>({
            path:
              "/api/v1/passport",
          });

        expect(calls).toBe(2);
        expect(result.ok).toBe(true);
      },
    );

    it(
      "does not retry POST by default",
      async () => {
        let calls = 0;

        const fetchImpl:
          typeof fetch =
          () => {
            calls += 1;

            return Promise.resolve(
              jsonResponse(
                {
                  error: {
                    code:
                      "InternalError",
                    message:
                      "temporary",
                  },
                },
                {
                  status: 503,
                  headers: {
                    "retry-after": "0",
                  },
                },
              ),
            );
          };

        const transport =
          new AquariHttpTransport({
            baseUrl:
              "https://api.aquari.one",
            fetch: fetchImpl,
            maxRetries: 1,
          });

        await expect(
          transport.request({
            path:
              "/api/v1/example",
            method: "POST",
            json: {
              value: true,
            },
          }),
        ).rejects.toBeInstanceOf(
          AquariApiError,
        );

        expect(calls).toBe(1);
      },
    );

    it(
      "retries an explicitly idempotent POST",
      async () => {
        let calls = 0;

        const fetchImpl:
          typeof fetch =
          () => {
            calls += 1;

            if (calls === 1) {
              return Promise.resolve(
                jsonResponse(
                  {
                    error: {
                      code:
                        "InternalError",
                      message:
                        "temporary",
                    },
                  },
                  {
                    status: 503,
                    headers: {
                      "retry-after": "0",
                    },
                  },
                ),
              );
            }

            return Promise.resolve(
              jsonResponse({
                created: true,
              }),
            );
          };

        const transport =
          new AquariHttpTransport({
            baseUrl:
              "https://api.aquari.one",
            fetch: fetchImpl,
            maxRetries: 1,
          });

        const result =
          await transport.request<{
            created: boolean;
          }>({
            path:
              "/api/v1/machine/issuer/example",
            method: "POST",
            retry: "idempotent",
            json: {
              subjectId:
                "00000000-0000-0000-0000-000000000001",
            },
          });

        expect(calls).toBe(2);

        expect(
          result.created,
        ).toBe(true);
      },
    );

    it(
      "turns request timeouts into AquariTimeoutError",
      async () => {
        const fetchImpl:
          typeof fetch =
          (_input, init) =>
            new Promise<Response>(
              (_resolve, reject) => {
                const signal =
                  init?.signal;

                if (signal == null) {
                  reject(
                    new Error(
                      "Expected AbortSignal.",
                    ),
                  );

                  return;
                }

                const abort = (): void => {
                  reject(
                    new Error(
                      "aborted",
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

        const transport =
          new AquariHttpTransport({
            baseUrl:
              "https://api.aquari.one",
            fetch: fetchImpl,
            timeoutMs: 10,
            maxRetries: 0,
          });

        await expect(
          transport.request({
            path:
              "/api/v1/passport",
          }),
        ).rejects.toBeInstanceOf(
          AquariTimeoutError,
        );
      },
    );
  },
);

describe(
  "parseRetryAfterMs",
  () => {
    it(
      "parses delay-seconds",
      () => {
        expect(
          parseRetryAfterMs("7"),
        ).toBe(7_000);
      },
    );

    it(
      "parses an HTTP date",
      () => {
        const now =
          new Date(
            "2026-09-24T00:00:00Z",
          );

        expect(
          parseRetryAfterMs(
            "Thu, 24 Sep 2026 00:00:05 GMT",
            now,
          ),
        ).toBe(5_000);
      },
    );

    it(
      "returns undefined for malformed values",
      () => {
        expect(
          parseRetryAfterMs(
            "definitely-not-valid",
          ),
        ).toBeUndefined();
      },
    );
  },
);
