import {
  describe,
  expect,
  it,
} from "vitest";

import {
  createPkcePair,
  createS256CodeChallenge,
  createSecureRandomValue,
} from "../src/pkce.js";

describe(
  "Aquari PKCE primitives",
  () => {
    it(
      "matches the RFC 7636 S256 example",
      async () => {
        const challenge =
          await createS256CodeChallenge(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
          );

        expect(challenge).toBe(
          "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        );
      },
    );

    it(
      "creates an RFC-compatible verifier and challenge",
      async () => {
        const pair =
          await createPkcePair();

        expect(
          pair.codeVerifier,
        ).toMatch(
          /^[A-Za-z0-9_-]{64}$/u,
        );

        expect(
          pair.codeChallenge,
        ).toMatch(
          /^[A-Za-z0-9_-]{43}$/u,
        );

        expect(
          await createS256CodeChallenge(
            pair.codeVerifier,
          ),
        ).toBe(
          pair.codeChallenge,
        );
      },
    );

    it(
      "creates independent secure random values",
      () => {
        const first =
          createSecureRandomValue(32);

        const second =
          createSecureRandomValue(32);

        expect(first).toMatch(
          /^[A-Za-z0-9_-]{43}$/u,
        );

        expect(second).toMatch(
          /^[A-Za-z0-9_-]{43}$/u,
        );

        expect(first).not.toBe(second);
      },
    );
  },
);
