import {
  describe,
  expect,
  it,
} from "vitest";

import {
  DEFAULT_MAX_RETRIES,
  DEFAULT_MAX_RETRY_DELAY_MS,
  DEFAULT_REQUEST_TIMEOUT_MS,
  normalizeAquariBaseUrl,
  resolveAquariTransportConfiguration,
} from "../src/config.js";

import {
  AquariConfigurationError,
} from "../src/errors.js";

describe(
  "Aquari transport configuration",
  () => {
    it(
      "normalizes a secure base URL",
      () => {
        const url =
          normalizeAquariBaseUrl(
            "https://api.aquari.one",
          );

        expect(url.toString()).toBe(
          "https://api.aquari.one/",
        );
      },
    );

    it(
      "allows HTTP for localhost development",
      () => {
        const url =
          normalizeAquariBaseUrl(
            "http://localhost:4100",
          );

        expect(url.toString()).toBe(
          "http://localhost:4100/",
        );
      },
    );

    it(
      "rejects insecure non-local HTTP",
      () => {
        expect(
          () =>
            normalizeAquariBaseUrl(
              "http://api.aquari.one",
            ),
        ).toThrow(
          AquariConfigurationError,
        );
      },
    );

    it(
      "rejects URL credentials, query strings, and fragments",
      () => {
        expect(
          () =>
            normalizeAquariBaseUrl(
              "https://user:pass@api.aquari.one",
            ),
        ).toThrow(
          AquariConfigurationError,
        );

        expect(
          () =>
            normalizeAquariBaseUrl(
              "https://api.aquari.one/?x=1",
            ),
        ).toThrow(
          AquariConfigurationError,
        );

        expect(
          () =>
            normalizeAquariBaseUrl(
              "https://api.aquari.one/#x",
            ),
        ).toThrow(
          AquariConfigurationError,
        );
      },
    );

    it(
      "applies the SDK transport defaults",
      () => {
        const configuration =
          resolveAquariTransportConfiguration({
            baseUrl:
              "https://api.aquari.one",
          });

        expect(
          configuration.timeoutMs,
        ).toBe(
          DEFAULT_REQUEST_TIMEOUT_MS,
        );

        expect(
          configuration.maxRetries,
        ).toBe(
          DEFAULT_MAX_RETRIES,
        );

        expect(
          configuration.maxRetryDelayMs,
        ).toBe(
          DEFAULT_MAX_RETRY_DELAY_MS,
        );
      },
    );
  },
);
