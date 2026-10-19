import { describe, expect, it } from "vitest";
import { AquariHttpTransport, parseRetryAfterMs } from "../src/transport.js";
import { AquariRateLimitError } from "../src/errors.js";

describe("Retry-After conformance", () => {
  const now = new Date("2026-10-05T00:00:00Z");
  it.each(["-1", "+1", "0x10", "1.5", "", "2026-10-05T00:00:12Z", "not-a-date", "Foo, 05 Oct 2026 00:00:12 GMT", "Mon, 31 Feb 2026 00:00:12 GMT"])("rejects malformed header %s", (value) => {
    expect(parseRetryAfterMs(value, now)).toBeUndefined();
  });
  it.each(["mon, 05 oct 2026 00:00:12 gmt", "Mon, 05 Oct 2026 00:00:12 GMT", "Monday, 05-Oct-26 00:00:12 GMT", "Mon Oct  5 00:00:12 2026"])("supports HTTP-date %s", (value) => {
    expect(parseRetryAfterMs(value, now)).toBe(12_000);
  });
  it("bounds oversized numeric values without losing the server delay", () => {
    expect(parseRetryAfterMs("9".repeat(400), now)).toBe(Number.MAX_SAFE_INTEGER);
    expect(parseRetryAfterMs("0", now)).toBe(0);
  });
  it("does not retry earlier than an oversized server delay", async () => {
    let attempts = 0;
    const transport = new AquariHttpTransport({
      baseUrl: "https://example.invalid/",
      maxRetries: 2,
      maxRetryDelayMs: 5_000,
      fetch: () => {
        attempts += 1;
        return Promise.resolve(new Response(JSON.stringify({ error: { code: "RateLimitExceeded", message: "Wait" } }), { status: 429, headers: { "retry-after": "9".repeat(400), "content-type": "application/json" } }));
      },
    });
    await expect(transport.request({ path: "/read" })).rejects.toMatchObject({ retryAfterMs: Number.MAX_SAFE_INTEGER });
    expect(attempts).toBe(1);
  });
  it("preserves HTTP-date metadata on classified errors", async () => {
    const future = new Date(Date.now() + 60_000).toUTCString();
    const transport = new AquariHttpTransport({ baseUrl: "https://example.invalid/", maxRetries: 0, fetch: () => Promise.resolve(new Response(JSON.stringify({ error: { code: "RateLimitExceeded", message: "Wait" } }), { status: 429, headers: { "retry-after": future, "content-type": "application/json" } })) });
    try {
      await transport.request({ path: "/read" });
      throw new Error("Expected rate limit");
    } catch (error) {
      expect(error).toBeInstanceOf(AquariRateLimitError);
      if (!(error instanceof AquariRateLimitError)) throw error;
      expect(error.retryAfterMs).toBeGreaterThan(30_000);
    }
  });
});
