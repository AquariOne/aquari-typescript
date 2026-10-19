import {
  type AquariAuthorizationTransaction,
  type AquariCompleteAuthorizationResult,
} from "@aquari-one/sdk";
import {
  describe,
  expect,
  it,
  vi,
} from "vitest";

import {
  InMemoryAquariSessionStore,
  createAquari,
} from "../src/index.js";

const ISSUER = "https://api.aquari.one/";
const REDIRECT_URI = "https://dev.gemira.app/auth/callback";
const SESSION_COOKIE = "gemira_dev_aquari_session";
const TRANSACTION_COOKIE = "gemira_dev_aquari_tx";

function transaction(): AquariAuthorizationTransaction {
  return {
    version: 1,
    issuer: ISSUER,
    clientId: "gemira-web",
    redirectUri: REDIRECT_URI,
    scopes: ["openid", "profile", "offline_access"],
    codeVerifier: "v".repeat(64),
    state: "state-session-cookie-domain",
    nonce: "nonce-session-cookie-domain",
    createdAt: Date.now(),
  };
}

function completion(): AquariCompleteAuthorizationResult {
  return {
    tokens: {
      subject: "subject-1",
      tokenType: "Bearer",
      accessToken: "access-token",
      idToken: "id-token",
      refreshToken: "refresh-token",
      expiresIn: 3600,
      expiresAt: Date.now() + 60 * 60 * 1_000,
      scopes: ["openid", "profile", "offline_access"],
    },
    identity: {
      subject: "subject-1",
      handle: "@tester.aquari.one",
      name: "SDK Tester",
      email: "tester@example.com",
      emailVerified: true,
    },
  };
}

function createAdapter(
  sessionCookieDomain: string | null = ".gemira.app",
) {
  return createAquari({
    issuer: ISSUER,
    clientId: "gemira-web",
    redirectUri: REDIRECT_URI,
    scopes: ["openid", "profile", "offline_access"],
    sessionStore: new InMemoryAquariSessionStore(),
    sessionCookieName: SESSION_COOKIE,
    transactionCookieName: TRANSACTION_COOKIE,
    sessionTtlSeconds: 30 * 24 * 60 * 60,
    ...(sessionCookieDomain !== null ? { sessionCookieDomain } : {}),
  });
}

describe("Next.js application-session cookie domain", () => {
  it("keeps the transaction host-only and emits two callback cookies", async () => {
    const aquari = createAdapter();

    vi.spyOn(aquari.client.auth, "begin").mockResolvedValue({
      url: "https://auth.aquari.one/connect/authorize",
      transaction: transaction(),
    });

    vi.spyOn(aquari.client.auth, "complete").mockResolvedValue(completion());

    const signInResponse = await aquari.auth.signIn(
      new Request("https://dev.gemira.app/login"),
      { returnTo: "/auth/complete" },
    );

    const signInCookies = signInResponse.headers.getSetCookie();
    expect(signInCookies).toHaveLength(1);

    const transactionSetCookie = signInCookies[0];
    expect(transactionSetCookie).toBeDefined();

    if (transactionSetCookie === undefined) {
      throw new Error("Transaction cookie was not emitted.");
    }

    expect(transactionSetCookie).toContain(`${TRANSACTION_COOKIE}=`);
    expect(transactionSetCookie.toLowerCase()).not.toContain("domain=");

    const callbackResponse = await aquari.auth.callback(
      new Request(
        `${REDIRECT_URI}?code=code-1&state=state-session-cookie-domain`,
        {
          headers: {
            cookie: transactionSetCookie.split(";")[0] ?? "",
          },
        },
      ),
    );

    const callbackCookies = callbackResponse.headers.getSetCookie();
    expect(callbackCookies).toHaveLength(2);

    const sessionSetCookie = callbackCookies.find((value) =>
      value.startsWith(`${SESSION_COOKIE}=`),
    );
    const transactionDelete = callbackCookies.find((value) =>
      value.startsWith(`${TRANSACTION_COOKIE}=`),
    );

    expect(sessionSetCookie?.toLowerCase()).toContain("domain=gemira.app");
    expect(sessionSetCookie).toContain("Max-Age=2592000");
    expect(transactionDelete).toContain("Max-Age=0");
    expect(transactionDelete?.toLowerCase()).not.toContain("domain=");
  });

  it("uses the same domain for session deletion", async () => {
    const aquari = createAdapter();

    const response = await aquari.auth.signOut(
      new Request("https://dev.gemira.app/account", {
        headers: {
          cookie: `${SESSION_COOKIE}=opaque-session`,
        },
      }),
    );

    const cookie = response.headers.getSetCookie()[0];

    expect(cookie?.toLowerCase()).toContain("domain=gemira.app");
    expect(cookie).toContain("Max-Age=0");
  });

  it("preserves host-only sessions by default", async () => {
    const aquari = createAdapter(null);

    const response = await aquari.auth.signOut(
      new Request("https://dev.gemira.app/account"),
    );

    expect(
      response.headers.getSetCookie()[0]?.toLowerCase(),
    ).not.toContain("domain=");
  });

  it("rejects an unrelated domain", () => {
    expect(() => createAdapter("evil.example")).toThrow(
      "redirect host or one of its parent domains",
    );
  });
});
