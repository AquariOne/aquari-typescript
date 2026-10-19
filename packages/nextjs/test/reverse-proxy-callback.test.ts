import type {
  AquariAuthorizationTransaction,
  AquariCompleteAuthorizationResult,
} from "@aquari-one/sdk";
import { describe, expect, it, vi } from "vitest";

import {
  createAquari,
  InMemoryAquariSessionStore,
} from "../src/index.js";

describe("@aquari-one/nextjs reverse-proxy callback", () => {
  it("uses the configured public redirect URI while preserving the OAuth response query", async () => {
    const issuer = "https://issuer.example/";
    const redirectUri =
      "https://app.example.com/auth/callback?tenant=gemira";

    const transaction: AquariAuthorizationTransaction = {
      version: 1,
      issuer,
      clientId: "client-id",
      redirectUri,
      scopes: ["openid"],
      codeVerifier: "v".repeat(64),
      state: "s".repeat(43),
      nonce: "n".repeat(43),
      createdAt: Date.now(),
    };

    const completion: AquariCompleteAuthorizationResult = {
      tokens: {
        subject: "subject-1",
        tokenType: "Bearer",
        accessToken: "access-token",
        idToken: "id-token",
        refreshToken: "refresh-token",
        expiresIn: 3600,
        expiresAt: Date.now() + 3_600_000,
        scopes: ["openid"],
      },
      identity: {
        subject: "subject-1",
      },
    };

    const aquari = createAquari({
      issuer,
      clientId: "client-id",
      redirectUri,
      scopes: ["openid"],
      sessionStore: new InMemoryAquariSessionStore(),
      secureCookies: true,
    });

    vi.spyOn(aquari.client.auth, "begin").mockResolvedValue({
      url: "https://issuer.example/connect/authorize",
      transaction,
    });

    const complete = vi
      .spyOn(aquari.client.auth, "complete")
      .mockResolvedValue(completion);

    const signInResponse = await aquari.auth.signIn(
      new Request("https://app.example.com/auth/login"),
    );

    const setCookie = signInResponse.headers.get("set-cookie");
    expect(setCookie).not.toBeNull();

    const transactionCookie = setCookie?.split(";")[0];
    expect(transactionCookie).toBeTruthy();

    const callbackResponse = await aquari.auth.callback(
      new Request(
        "http://127.0.0.1:3201/auth/callback" +
          "?tenant=gemira" +
          "&code=code-1" +
          "&state=state-1" +
          "&iss=https%3A%2F%2Fissuer.example%2F",
        {
          headers: {
            cookie: transactionCookie ?? "",
          },
        },
      ),
    );

    expect(callbackResponse.status).toBe(302);
    expect(complete).toHaveBeenCalledTimes(1);

    const completeInput = complete.mock.calls[0]?.[0];
    expect(completeInput).toBeDefined();

    const callbackUrl = new URL(String(completeInput));

    expect(callbackUrl.origin).toBe("https://app.example.com");
    expect(callbackUrl.pathname).toBe("/auth/callback");
    expect(callbackUrl.searchParams.get("tenant")).toBe("gemira");
    expect(callbackUrl.searchParams.get("code")).toBe("code-1");
    expect(callbackUrl.searchParams.get("state")).toBe("state-1");
    expect(callbackUrl.searchParams.get("iss")).toBe(issuer);

    expect(callbackUrl.hostname).not.toBe("127.0.0.1");
    expect(callbackUrl.protocol).toBe("https:");
  });
});
