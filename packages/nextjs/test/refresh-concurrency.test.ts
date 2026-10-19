import {
  AquariOAuthError,
  type AquariTokenSet,
} from "@aquari-one/sdk";
import {
  describe,
  expect,
  it,
  vi,
} from "vitest";

import {
  InMemoryAquariRefreshLock,
  InMemoryAquariSessionStore,
  createAquari,
} from "../src/index.js";

const ISSUER =
  "https://dev.api.aquari.one/";
const SESSION_ID =
  "refresh-concurrency-session";
const SESSION_KEY =
  `aquari:session:${SESSION_ID}`;

function nearExpiryTokens(): AquariTokenSet {
  return {
    subject: "subject-1",
    tokenType: "Bearer",
    accessToken: "access-old",
    idToken: "id-old",
    refreshToken: "refresh-old",
    expiresIn: 3600,
    expiresAt:
      Date.now() + 1_000,
    scopes: [
      "openid",
      "offline_access",
    ],
  };
}

function refreshedTokens(
  tokens: AquariTokenSet,
): AquariTokenSet {
  return {
    ...tokens,
    accessToken:
      "access-new",
    refreshToken:
      "refresh-new",
    expiresIn: 3600,
    expiresAt:
      Date.now() + 3_600_000,
  };
}

async function seedSession(
  store: InMemoryAquariSessionStore,
): Promise<void> {
  await store.set(
    SESSION_KEY,
    JSON.stringify({
      version: 1,
      tokens:
        nearExpiryTokens(),
      identity: {
        subject:
          "subject-1",
      },
    }),
    new Date(
      Date.now() + 3_600_000,
    ),
  );
}

function sessionRequest(): Request {
  return new Request(
    "https://app.example/session",
    {
      headers: {
        cookie:
          `aquari_session=${SESSION_ID}`,
      },
    },
  );
}

function createTestAquari(
  store: InMemoryAquariSessionStore,
  refreshLock =
    new InMemoryAquariRefreshLock(),
) {
  return createAquari({
    issuer:
      ISSUER,
    clientId:
      "public-client",
    redirectUri:
      "https://app.example/auth/callback",
    scopes: [
      "openid",
      "offline_access",
    ],
    sessionStore:
      store,
    refreshLock,
  });
}

describe(
  "@aquari-one/nextjs refresh serialization",
  () => {
    it(
      "single-flights concurrent refreshes for one session",
      async () => {
        const store =
          new InMemoryAquariSessionStore();

        await seedSession(store);

        const aquari =
          createTestAquari(store);

        let refreshCalls = 0;

        vi.spyOn(
          aquari.client.auth,
          "refresh",
        ).mockImplementation(
          async tokens => {
            refreshCalls += 1;

            await new Promise<void>(
              resolve => {
                setTimeout(
                  resolve,
                  20,
                );
              },
            );

            return refreshedTokens(
              tokens,
            );
          },
        );

        const request =
          sessionRequest();

        const tokens =
          await Promise.all(
            Array.from(
              { length: 8 },
              async () =>
                await aquari.auth
                  .getAccessToken(
                    request,
                  ),
            ),
          );

        expect(refreshCalls)
          .toBe(1);

        expect(
          new Set(tokens),
        ).toEqual(
          new Set([
            "access-new",
          ]),
        );
      },
    );

    it(
      "supports a shared refresh lock across adapter instances",
      async () => {
        const store =
          new InMemoryAquariSessionStore();
        const lock =
          new InMemoryAquariRefreshLock();

        await seedSession(store);

        const first =
          createTestAquari(
            store,
            lock,
          );
        const second =
          createTestAquari(
            store,
            lock,
          );

        let refreshCalls = 0;

        const refresh =
          async (
            tokens: AquariTokenSet,
          ): Promise<AquariTokenSet> => {
            refreshCalls += 1;

            await new Promise<void>(
              resolve => {
                setTimeout(
                  resolve,
                  20,
                );
              },
            );

            return refreshedTokens(
              tokens,
            );
          };

        vi.spyOn(
          first.client.auth,
          "refresh",
        ).mockImplementation(
          refresh,
        );

        vi.spyOn(
          second.client.auth,
          "refresh",
        ).mockImplementation(
          refresh,
        );

        const request =
          sessionRequest();

        const [a, b] =
          await Promise.all([
            first.auth
              .getAccessToken(
                request,
              ),
            second.auth
              .getAccessToken(
                request,
              ),
          ]);

        expect(refreshCalls)
          .toBe(1);
        expect(a)
          .toBe("access-new");
        expect(b)
          .toBe("access-new");
      },
    );

    it(
      "does not resurrect a session when sign-out races an in-flight refresh",
      async () => {
        const store =
          new InMemoryAquariSessionStore();

        await seedSession(store);

        const aquari =
          createTestAquari(store);

        let releaseRefresh!:
          () => void;

        const refreshGate =
          new Promise<void>(
            resolve => {
              releaseRefresh =
                resolve;
            },
          );

        let markStarted!:
          () => void;

        const started =
          new Promise<void>(
            resolve => {
              markStarted =
                resolve;
            },
          );

        vi.spyOn(
          aquari.client.auth,
          "refresh",
        ).mockImplementation(
          async tokens => {
            markStarted();
            await refreshGate;

            return refreshedTokens(
              tokens,
            );
          },
        );

        const request =
          sessionRequest();

        const accessToken =
          aquari.auth
            .getAccessToken(
              request,
            );

        await started;

        const signOut =
          aquari.auth.signOut(
            request,
          );

        releaseRefresh();

        await expect(accessToken)
          .resolves.toBe(
            "access-new",
          );

        await expect(signOut)
          .resolves.toMatchObject({
            status: 204,
          });

        await expect(
          store.get(
            SESSION_KEY,
          ),
        ).resolves.toBeNull();
      },
    );

    it(
      "fails closed and removes unchanged session state on invalid_grant",
      async () => {
        const store =
          new InMemoryAquariSessionStore();

        await seedSession(store);

        const aquari =
          createTestAquari(store);

        vi.spyOn(
          aquari.client.auth,
          "refresh",
        ).mockRejectedValue(
          new AquariOAuthError({
            code:
              "invalid_grant",
            message:
              "Refresh token is no longer valid.",
          }),
        );

        await expect(
          aquari.auth
            .getAccessToken(
              sessionRequest(),
            ),
        ).resolves.toBeNull();

        await expect(
          store.get(
            SESSION_KEY,
          ),
        ).resolves.toBeNull();
      },
    );
  },
);
