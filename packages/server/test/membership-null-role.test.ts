import {
  describe,
  expect,
  it,
} from "vitest";

import { AquariServerClient } from "../src/index.js";

describe(
  "Aquari membership updates",
  () => {
    it(
      "serializes an explicit null roleId when clearing a formal role",
      async () => {
        let requestBody:
          | string
          | undefined;

        const fetchImpl:
          typeof fetch =
          (_input, init) => {
            if (
              typeof init?.body ===
              "string"
            ) {
              requestBody =
                init.body;
            }

            return Promise.reject(
              new Error(
                "Stop after request capture.",
              ),
            );
          };

        const client =
          new AquariServerClient({
            apiUrl:
              "https://api.example.test/",
            apiKey: "test-key",
            maxRetries: 0,
            fetch: fetchImpl,
          });

        await client.issuer.memberships
          .update(
            "11111111-1111-4111-8111-111111111111",
            {
              roleId: null,
            },
          )
          .catch(() => undefined);

        expect(requestBody).toBe(
          JSON.stringify({
            roleId: null,
          }),
        );
      },
    );
  },
);
