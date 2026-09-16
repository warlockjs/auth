/**
 * Two-sided identity-clearing control for the `request.user` →
 * `request.locals.user` move (core@c4e3374, auth@26be1a1).
 *
 * `auth.middleware.spec.ts` already pins that `authMiddleware` clears a
 * *previously-set* value on `request.locals.user` when the SAME request
 * object is reused across calls in a test. It does not prove the thing that
 * actually matters in production: that an authenticated user from ONE
 * request is invisible to the NEXT request. That guarantee is structural —
 * `Request#locals` is a fresh class-field object per instance
 * (`core/src/http/request.ts`) and `useCurrentUser()`/`currentUser()` read
 * through an `AsyncLocalStorage`-backed context scoped per request
 * (`core/src/http/context/request-context.ts`) — and nothing exercises it
 * across two distinct `Request` instances until now.
 *
 * `@warlock.js/core` is mocked the same way `auth.middleware.spec.ts` mocks
 * it (`config`/`t` stubbed identically) so `authMiddleware` behaves exactly
 * as it does in that suite — EXCEPT `Request`, `requestContext`, and
 * `useCurrentUser` are taken from core's REAL implementation rather than
 * stubbed, because this spec needs the REAL per-request `locals` field and
 * the REAL `AsyncLocalStorage`-backed store — a mock of either would prove
 * nothing about isolation.
 *
 * They are fetched via `@warlock.js/core`'s own PACKAGE-SPECIFIER deep
 * paths (`@warlock.js/core/src/http/request`, not a `../../../core/src/...`
 * relative crossing) so tsc resolves them the same way it resolves every
 * other `@warlock.js/core` import in this package: through `node_modules`,
 * which keeps them OUT of auth's own compiled program (a relative crossing
 * into a sibling package's `src` makes tsc treat those files as auth's own
 * source and charge their `rootDir` violations to auth — see
 * `builder/scripts/strictness-gate.ts`'s `PROGRAM_CONTAINMENT_CODES`).
 *
 * This also deliberately avoids `importOriginal()` on the bare
 * `@warlock.js/core` specifier: that forces evaluation of the FULL real
 * barrel, including `core/src/database/utils.ts`, which imports
 * `@warlock.js/auth` back — a genuine core→auth cycle. Loading it mid-mock
 * caches `auth.middleware.ts` (transitively re-exported from
 * `@warlock.js/auth`'s own index) with whatever `@warlock.js/core` binding
 * was live at that moment, which is NOT this file's mock — the exact
 * "two `config`s in play" bug this spec exists to prevent, just relocated
 * to the test's own plumbing. The deep-path imports below only ever pull in
 * `request.ts` and `request-context.ts` and their own dependencies, never
 * `./database`, so the cycle is never entered. Both `auth.middleware.ts`
 * and this spec still resolve "@warlock.js/core" to this one mocked
 * module, so there is exactly one `config`/`useCurrentUser` in play.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const configKey = vi.fn();
const jwtVerify = vi.fn();
const accessTokenFindByToken = vi.fn();

vi.mock("@warlock.js/core", async () => {
  const { Request } = await import("@warlock.js/core/src/http/request");
  const { requestContext, useCurrentUser, useRequest } = await import(
    "@warlock.js/core/src/http/context/request-context"
  );

  return {
    Request,
    requestContext,
    useCurrentUser,
    useRequest,
    config: { key: (...args: unknown[]) => configKey(...args) },
    t: (key: string) => key,
  };
});

vi.mock("@warlock.js/logger", async importOriginal => {
  const actual = await importOriginal<typeof import("@warlock.js/logger")>();

  return {
    ...actual,
    log: { ...actual.log, error: vi.fn() },
  };
});

vi.mock("../services/jwt", async importOriginal => {
  const actual = await importOriginal<typeof import("../services/jwt")>();

  return {
    ...actual,
    jwt: {
      ...actual.jwt,
      verify: (...args: unknown[]) => jwtVerify(...args),
    },
  };
});

vi.mock("../models/access-token", () => ({
  AccessToken: { findByToken: (...args: unknown[]) => accessTokenFindByToken(...args) },
}));

import { Request, requestContext, useCurrentUser } from "@warlock.js/core";
import { authMiddleware } from "./auth.middleware";
import { currentUser } from "../services/current-user";
import { makeCtx } from "./test-support/make-ctx";

/** A token row the database considers live (same shape as auth.middleware.spec.ts). */
function liveRow(fields: Record<string, unknown>) {
  return { isExpired: false, destroy: vi.fn(), ...fields };
}

/** `auth.userType.<type>` resolves to the supplied user model; everything else falls back. */
function stubConfig(userModel: unknown) {
  configKey.mockImplementation((key: string, fallback?: unknown) => {
    if (key.startsWith("auth.userType.")) return userModel;

    return fallback;
  });
}

/**
 * Build a real per-request pair, distinct object identity from every other
 * call. `baseRequest` is stubbed only far enough for
 * `request.authorizationValue` (a real `Request#header()` read) to work —
 * everything else stays the real `Request` implementation, including its
 * class-field `locals` initializer.
 */
function buildRequestResponse() {
  const request = new Request();

  request.baseRequest = { headers: { authorization: "Bearer valid-token" } } as any;

  return { request, response: { unauthorized: vi.fn() } };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("request.locals.user cross-request isolation (5.12.0 move)", () => {
  it("authenticates request A, then B — handled afterwards — sees no user at all", async () => {
    const decoded = { id: 1, userType: "user" };
    jwtVerify.mockResolvedValue(decoded);
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);
    const { request: requestA, response: responseA } = buildRequestResponse();

    // Request A: authenticated.
    await requestContext.run({ request: requestA as any, response: responseA as any }, async () => {
      await middleware(makeCtx({ request: requestA, response: responseA }));

      expect(requestA.locals.user).toEqual({ id: 1, userType: "user" });
      expect(useCurrentUser()).toEqual({ id: 1, userType: "user" });
      expect(currentUser()).toEqual({ id: 1, userType: "user" });
      // 3. decodedAccessToken behaviour still works for A.
      expect(requestA.decodedAccessToken).toEqual(decoded);
    });

    // Request B: a brand new, unrelated request handled AFTER A finished.
    // It never touches authMiddleware — an unauthenticated request must see
    // nothing of A's identity.
    const { request: requestB, response: responseB } = buildRequestResponse();

    await requestContext.run({ request: requestB as any, response: responseB as any }, async () => {
      expect(requestB.locals.user).toBeUndefined();
      expect(useCurrentUser()).toBeUndefined();
      expect(currentUser()).toBeUndefined();
    });
  });

  it("keeps two requests isolated when handled CONCURRENTLY through the async context", async () => {
    const decoded = { id: 42, userType: "user" };
    jwtVerify.mockResolvedValue(decoded);
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 42, userType: "user" }) });

    const middleware = authMiddleware([]);
    const { request: requestA, response: responseA } = buildRequestResponse();
    const { request: requestB, response: responseB } = buildRequestResponse();

    // A authenticates; B never does. Both run in overlapping async chains —
    // each yields mid-flight (a macrotask tick) so the other's turn can run
    // before either reads back its own context, which is what actually
    // exercises AsyncLocalStorage isolation rather than plain sequencing.
    const runA = requestContext.run(
      { request: requestA as any, response: responseA as any },
      async () => {
        await middleware(makeCtx({ request: requestA, response: responseA }));

        await new Promise(resolve => setTimeout(resolve, 0));

        return {
          localsUser: requestA.locals.user,
          currentUser: useCurrentUser(),
          decodedAccessToken: requestA.decodedAccessToken,
        };
      },
    );

    const runB = requestContext.run(
      { request: requestB as any, response: responseB as any },
      async () => {
        await new Promise(resolve => setTimeout(resolve, 0));

        return {
          localsUser: requestB.locals.user,
          currentUser: useCurrentUser(),
        };
      },
    );

    const [resultA, resultB] = await Promise.all([runA, runB]);

    expect(resultA.localsUser).toEqual(decoded);
    expect(resultA.currentUser).toEqual(decoded);
    // 3. decodedAccessToken behaviour still works for A, even interleaved with B.
    expect(resultA.decodedAccessToken).toEqual(decoded);

    // 2. B — run concurrently with A's authentication — sees nothing of it.
    expect(resultB.localsUser).toBeUndefined();
    expect(resultB.currentUser).toBeUndefined();
  });
});
