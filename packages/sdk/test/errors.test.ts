import {
  describe,
  expect,
  it,
} from "vitest";

import {
  AquariAuthenticationError,
  AquariAuthorizationError,
  AquariConflictError,
  AquariNotFoundError,
  AquariQuotaError,
  AquariRateLimitError,
  AquariValidationError,
  classifyAquariApiError,
} from "../src/errors.js";

describe(
  "Aquari API error classification",
  () => {
    const base = {
      message: "example",
      details: undefined,
    };

    it(
      "classifies validation errors",
      () => {
        expect(
          classifyAquariApiError({
            ...base,
            status: 400,
            code: "ValidationFailed",
          }),
        ).toBeInstanceOf(
          AquariValidationError,
        );
      },
    );

    it(
      "distinguishes authentication from authorization",
      () => {
        expect(
          classifyAquariApiError({
            ...base,
            status: 401,
            code: "Unauthorized",
          }),
        ).toBeInstanceOf(
          AquariAuthenticationError,
        );

        expect(
          classifyAquariApiError({
            ...base,
            status: 403,
            code: "Forbidden",
          }),
        ).toBeInstanceOf(
          AquariAuthorizationError,
        );
      },
    );

    it(
      "classifies not-found and conflict responses",
      () => {
        expect(
          classifyAquariApiError({
            ...base,
            status: 404,
            code:
              "PassportSignalNotFound",
          }),
        ).toBeInstanceOf(
          AquariNotFoundError,
        );

        expect(
          classifyAquariApiError({
            ...base,
            status: 409,
            code: "Conflict",
          }),
        ).toBeInstanceOf(
          AquariConflictError,
        );
      },
    );

    it(
      "exposes typed quota metadata",
      () => {
        const error =
          classifyAquariApiError({
            status: 403,
            code: "QuotaExceeded",
            message: "quota",
            details: {
              resource: [
                "api_request",
              ],
              scopeType: [
                "organization",
              ],
              scopeId: [
                "00000000-0000-0000-0000-000000000001",
              ],
              current: ["10"],
              requested: ["2"],
              limit: ["10"],
              allowance: ["9"],
              grace: ["1"],
              periodFrom: [
                "2026-09-01T00:00:00.0000000+00:00",
              ],
              periodTo: [
                "2026-10-01T00:00:00.0000000+00:00",
              ],
              enforcement: ["hard"],
            },
          });

        expect(error).toBeInstanceOf(
          AquariQuotaError,
        );

        if (
          !(error instanceof AquariQuotaError)
        ) {
          throw new Error(
            "Expected AquariQuotaError.",
          );
        }

        expect(error.resource).toBe(
          "api_request",
        );

        expect(error.current).toBe(10);
        expect(error.requested).toBe(2);
        expect(error.limit).toBe(10);
        expect(error.allowance).toBe(9);
        expect(error.grace).toBe(1);
        expect(error.enforcement).toBe(
          "hard",
        );

        expect(
          error.periodFrom,
        ).toBeInstanceOf(Date);
      },
    );

    it(
      "preserves Retry-After metadata",
      () => {
        const error =
          classifyAquariApiError(
            {
              ...base,
              status: 429,
              code:
                "RateLimitExceeded",
            },
            7_000,
          );

        expect(error).toBeInstanceOf(
          AquariRateLimitError,
        );

        if (
          !(
            error instanceof
            AquariRateLimitError
          )
        ) {
          throw new Error(
            "Expected AquariRateLimitError.",
          );
        }

        expect(
          error.retryAfterMs,
        ).toBe(7_000);
      },
    );
  },
);
