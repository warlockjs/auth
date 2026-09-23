import { beforeEach, describe, expect, it, vi } from "vitest";

const configKey = vi.fn();
const jwtVerify = vi.fn();
const accessTokenFindByToken = vi.fn();
const renewAutomaticSession = vi.fn();
const setAuthCookie = vi.fn();
const canAuthenticate = vi.fn();

/**
 * Mirrors `core/src/http/csrf-origin-policy.ts`'s `resolveCsrfOriginVerdict`
 * against this file's plain fake-request objects (`origin`/`header`/
 * `protocol`/`hostname`) — `csrf-origin-check.ts` now delegates to the real
 * one, so this test double stands in for `@warlock.js/core` exactly as it
 * did before that extraction.
 */
function fakeResolveCsrfOriginVerdict(request: {
  origin?: string;
  header: (name: string) => unknown;
  protocol: string;
  hostname: string;
}) {
  const normalize = (origin: string) => {
    try {
      const url = new URL(origin);
      const isDefaultPort =
        (url.protocol === "http:" && (url.port === "" || url.port === "80")) ||
        (url.protocol === "https:" && (url.port === "" || url.port === "443"));
      return `${url.protocol}//${isDefaultPort ? url.hostname : url.host}`;
    } catch {
      return origin;
    }
  };
  const ownOrigin = () => {
    const hostHeader = request.header("host");
    const host = typeof hostHeader === "string" && hostHeader ? hostHeader : request.hostname;
    return `${request.protocol}://${host}`;
  };
  const isAllowed = (origin: string) => {
    if (normalize(origin) === normalize(ownOrigin())) return true;
    const allowedOrigins: string[] = configKey("auth.csrf.allowedOrigins", []) ?? [];
    return allowedOrigins.includes(origin);
  };
  const originOf = (rawUrl: string) => {
    try {
      const url = new URL(rawUrl);
      return `${url.protocol}//${url.host}`;
    } catch {
      return undefined;
    }
  };

  if (request.origin) {
    return isAllowed(request.origin)
      ? { allowed: true as const }
      : { allowed: false as const, reason: "origin-mismatch" as const };
  }

  const referer = request.header("referer");
  const refererOrigin = typeof referer === "string" ? originOf(referer) : undefined;

  if (refererOrigin) {
    return isAllowed(refererOrigin)
      ? { allowed: true as const }
      : { allowed: false as const, reason: "referer-mismatch" as const };
  }

  return { allowed: false as const, reason: "missing-origin-and-referer" as const };
}

vi.mock("@warlock.js/core", () => ({
  config: { key: (...args: unknown[]) => configKey(...args) },
  t: (key: string) => key,
  resolveCsrfOriginVerdict: (request: unknown) =>
    fakeResolveCsrfOriginVerdict(request as Parameters<typeof fakeResolveCsrfOriginVerdict>[0]),
}));

vi.mock("@warlock.js/logger", () => ({
  log: { error: vi.fn() },
}));

vi.mock("../services/jwt", async (importOriginal) => {
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

vi.mock("../services/auth.service", () => ({
  authService: {
    canAuthenticate: (...args: unknown[]) => canAuthenticate(...args),
    renewAutomaticSession: (...args: unknown[]) => renewAutomaticSession(...args),
    setAuthCookie: (...args: unknown[]) => setAuthCookie(...args),
  },
}));

import { authMiddleware } from "./auth.middleware";
import { AuthErrorCodes } from "../utils/auth-error-codes";
import { makeCtx } from "./test-support/make-ctx";

function buildRequest(authorizationValue?: string) {
  return {
    authorizationValue,
    locals: { user: undefined as unknown },
    decodedAccessToken: undefined as unknown,
  };
}

function buildResponse() {
  return { unauthorized: vi.fn(), forbidden: vi.fn() };
}

/**
 * A token row the database considers live.
 *
 * `isExpired` is stated explicitly on every row because the middleware now asks
 * for it, and a row that cannot answer is treated as expired — a mock that
 * stayed silent would be asserting the opposite of what the test means.
 */
function liveRow(fields: Record<string, unknown>) {
  return { isExpired: false, destroy: vi.fn(), ...fields };
}

/**
 * Route `config.key`: model resolution falls back to the (mocked) AccessToken,
 * and `auth.userType.<type>` resolves to the supplied user model.
 */
function stubConfig(userModel: unknown) {
  configKey.mockImplementation((key: string, fallback?: unknown) => {
    if (key.startsWith("auth.userType.")) return userModel;

    return fallback; // model resolution → mocked AccessToken
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  canAuthenticate.mockResolvedValue(true);
  renewAutomaticSession.mockResolvedValue(null);
});

describe("authMiddleware", () => {
  it("renews a missing cookie access token before the handler and writes the rotated pair", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });
    renewAutomaticSession.mockResolvedValue({
      accessToken: { token: "next-access", expiresAt: "2030-01-01T00:00:00.000Z" },
      refreshToken: { token: "next-refresh", expiresAt: "2030-01-02T00:00:00.000Z" },
    });
    const request = {
      authorizationValue: undefined,
      cookie: vi.fn((name: string) => (name === "refresh" ? "old-refresh" : undefined)),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      method: "GET",
    };
    const response = buildResponse();
    const middleware = authMiddleware("user", {
      source: "cookie",
      key: "access",
      refresh: { source: "cookie", key: "refresh", overlapMs: 4_000 },
    });

    await middleware(makeCtx({ request, response }));

    expect(renewAutomaticSession).toHaveBeenCalledWith("old-refresh", "user", { overlapMs: 4_000 });
    expect(setAuthCookie).toHaveBeenNthCalledWith(
      1,
      response,
      expect.objectContaining({ token: "next-access" }),
      { name: "access" },
    );
    expect(setAuthCookie).toHaveBeenNthCalledWith(
      2,
      response,
      expect.objectContaining({ token: "next-refresh" }),
      { name: "refresh" },
    );
    expect(accessTokenFindByToken).toHaveBeenCalledWith("next-access");
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("keeps the local page redirect when automatic renewal has no valid refresh credential", async () => {
    const request = {
      authorizationValue: undefined,
      cookie: vi.fn(() => undefined),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      method: "GET",
      route: { isPage: true },
      url: "/account",
    };
    const response = { ...buildResponse(), redirect: vi.fn() };
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.pageAuth.loginPath" ? "/login" : fallback,
    );
    const middleware = authMiddleware("user", {
      source: "cookie",
      key: "access",
      refresh: { source: "cookie", key: "refresh" },
      redirect: { to: "/sign-in", returnUrlParam: "next" },
    });

    await middleware(makeCtx({ request, response }));

    expect(renewAutomaticSession).not.toHaveBeenCalled();
    expect(response.redirect).toHaveBeenCalledWith("/sign-in?next=%2Faccount");
    expect(response.unauthorized).not.toHaveBeenCalled();
  });

  it("keeps optional middleware anonymous when automatic renewal fails", async () => {
    renewAutomaticSession.mockResolvedValue(null);
    const middleware = authMiddleware("user", {
      source: "cookie",
      key: "access",
      optional: true,
      refresh: { source: "cookie", key: "refresh" },
    });
    const request = {
      authorizationValue: undefined,
      cookie: vi.fn((name: string) => (name === "refresh" ? "expired-refresh" : undefined)),
      locals: { user: { id: 99 } as unknown },
      decodedAccessToken: undefined as unknown,
      method: "GET",
    };
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(renewAutomaticSession).toHaveBeenCalledOnce();
    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.locals.user).toBeUndefined();
    expect(setAuthCookie).not.toHaveBeenCalled();
  });

  it("attempts renewal once for an invalid access token and never renews a forbidden user type", async () => {
    jwtVerify
      .mockRejectedValueOnce(Object.assign(new Error("expired"), { code: "FAST_JWT_EXPIRED" }))
      .mockResolvedValueOnce({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });
    renewAutomaticSession.mockResolvedValue({
      accessToken: { token: "next-access", expiresAt: "2030-01-01T00:00:00.000Z" },
      refreshToken: { token: "next-refresh", expiresAt: "2030-01-02T00:00:00.000Z" },
    });
    const middleware = authMiddleware("user", {
      source: "cookie",
      key: "access",
      refresh: { source: "cookie", key: "refresh" },
    });
    const request = {
      authorizationValue: undefined,
      cookie: vi.fn((name: string) => (name === "access" ? "expired-access" : "refresh")),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      method: "GET",
    };

    await middleware(makeCtx({ request, response: buildResponse() }));

    expect(renewAutomaticSession).toHaveBeenCalledTimes(1);
    expect(jwtVerify).toHaveBeenCalledTimes(2);
  });

  it("returns 403 for a valid forbidden type without attempting renewal", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "admin" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "admin" }));
    const response = buildResponse();
    const middleware = authMiddleware("user", {
      source: "cookie",
      key: "access",
      refresh: { source: "cookie", key: "refresh" },
    });
    const request = {
      authorizationValue: undefined,
      cookie: vi.fn((name: string) => (name === "access" ? "valid-access" : "refresh")),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      method: "GET",
    };

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.Unauthorized }),
    );
    expect(renewAutomaticSession).not.toHaveBeenCalled();
  });

  it("rejects automatic renewal configurations that cannot safely persist a typed cookie session", () => {
    expect(() =>
      authMiddleware("user", {
        source: "header",
        refresh: { source: "cookie", key: "refresh" },
      }),
    ).toThrow(/cookie access and refresh credentials/);
    expect(() =>
      authMiddleware([], {
        source: "cookie",
        key: "access",
        refresh: { source: "cookie", key: "refresh" },
      }),
    ).toThrow(/one allowed user type/);
  });

  it("rejects an unauthenticated request even with an empty allow-list", async () => {
    const middleware = authMiddleware([]);
    const request = buildRequest(undefined);
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.MissingAccessToken }),
    );
    expect(request.locals.user).toBeUndefined();
  });

  it("allows any authenticated user when called with an empty array", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("rejects an authenticated user whose type is not in the allow-list", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn() });

    const middleware = authMiddleware(["admin"]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.Unauthorized }),
    );
    expect(request.locals.user).toBeUndefined();
  });

  it("uses the configured default user type for the options-only cookie overload", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    configKey.mockImplementation((key: string, fallback?: unknown) => {
      if (key === "auth.defaultUserType") return "user";
      if (key === "auth.userType.user") return { find: vi.fn().mockResolvedValue({ id: 1 }) };
      return fallback;
    });

    const middleware = authMiddleware({ source: "cookie", key: "session" });
    const request = { ...buildRequest(), method: "GET", cookie: vi.fn(() => "valid-token") };
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(request.cookie).toHaveBeenCalledWith("session");
    expect(request.locals.user).toEqual({ id: 1 });
  });

  it("continues anonymously only for the explicit optional overload", async () => {
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.defaultUserType" ? "user" : fallback,
    );

    const middleware = authMiddleware({ optional: true });
    const request = buildRequest(undefined);
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.locals.user).toBeUndefined();
  });

  it("allows an authenticated user whose type matches the allow-list", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware(["user"]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("rejects when the token verifies but no access-token row exists", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(null);

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
    expect(request.locals.user).toBeUndefined();
  });

  // #27 (b). Independent of the `exp`-claim guard in `jwt.verify`: here the
  // token's own claims are impeccable (`jwt.verify` resolves) and it is only the
  // persisted row that says the session is over. Before 4.12.0 the middleware
  // asked whether the row existed and never what it said, so this request was
  // authenticated by a token the database knew was dead.
  it("rejects a token whose persisted expires_at has passed, even though the JWT verifies", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user", exp: 4_102_444_800 });
    const destroy = vi.fn();
    accessTokenFindByToken.mockResolvedValue({ userType: "user", isExpired: true, destroy });
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
    expect(request.locals.user).toBeUndefined();
  });

  it("deletes the dead row on the way out rather than leaving it for cleanup", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user", exp: 4_102_444_800 });
    const destroy = vi.fn();
    accessTokenFindByToken.mockResolvedValue({ userType: "user", isExpired: true, destroy });
    // The user resolves, so the expiry gate is the only path that can destroy
    // the row — otherwise the pre-existing user-not-found branch would.
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);

    await middleware(makeCtx({ request: buildRequest("valid-token"), response: buildResponse() }));

    expect(destroy).toHaveBeenCalledOnce();
  });

  // Fail-closed: a row that cannot answer "am I expired" is not trusted. The
  // defect being fixed was a check that answered "fine" when it had nothing to
  // check, so the absent-getter case is pinned rather than left to chance.
  it("rejects when the token row cannot say whether it is expired", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user", exp: 4_102_444_800 });
    accessTokenFindByToken.mockResolvedValue({ userType: "user", destroy: vi.fn() });
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
    expect(request.locals.user).toBeUndefined();
  });

  // #27 (c). The guard must not cost the normal path: a live row, an unexpired
  // token, a request that goes through.
  it("still admits a valid, unexpired token", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user", exp: 4_102_444_800 });
    accessTokenFindByToken.mockResolvedValue({
      userType: "user",
      isExpired: false,
      destroy: vi.fn(),
    });
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("destroys the access-token row and rejects when the user no longer exists", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    const destroy = vi.fn();
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user", destroy }));
    stubConfig({ find: vi.fn().mockResolvedValue(null) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(destroy).toHaveBeenCalledOnce();
    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
  });

  // D5. Only a `fast-jwt` `TokenError` (or this package's own `TokenTypeError`,
  // D6) carries a `code` an allowlist can recognise — so a forged/malformed/
  // expired JWT is simulated the way `fast-jwt` actually throws it: an error
  // object with `.code`, not a bare `Error("message")`.
  // Two-sided control (pins the defect returning if the clear is ever
  // removed): seed a PREVIOUSLY-set identity on `request.locals.user`, then
  // assert the outcome — the identity does not survive a forged/malformed/
  // expired token — rather than asserting a `clearCurrentUser()` call that
  // no longer exists.
  it("rejects and clears a previously-set identity when the JWT itself is invalid (forged/malformed/expired)", async () => {
    jwtVerify.mockRejectedValue(
      Object.assign(new Error("malformed token"), {
        code: "FAST_JWT_MALFORMED",
      }),
    );

    const middleware = authMiddleware([]);
    const request = buildRequest("garbage-token");
    request.locals.user = { id: 99, userType: "user" };
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(request.locals.user).toBeUndefined();
    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
  });

  it("rejects an expired JWT (FAST_JWT_EXPIRED) with 401, not a thrown error", async () => {
    jwtVerify.mockRejectedValue(
      Object.assign(new Error("token expired"), {
        code: "FAST_JWT_EXPIRED",
      }),
    );

    const middleware = authMiddleware([]);
    const request = buildRequest("expired-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
  });

  // D6. `assertTokenType` (services/jwt.ts) throws a `TokenTypeError` carrying
  // `AuthErrorCodes.InvalidTokenType` for a refresh-token-where-access-token
  // -required mismatch — a genuine credential error, and now classifiable.
  it("rejects a tokenType mismatch (D6) with 401, same as a bad JWT, and clears a previously-set identity", async () => {
    jwtVerify.mockRejectedValue(
      Object.assign(new Error('Invalid token type: expected "access", received "refresh".'), {
        code: AuthErrorCodes.InvalidTokenType,
      }),
    );

    const middleware = authMiddleware([]);
    const request = buildRequest("refresh-token-used-as-access");
    request.locals.user = { id: 99, userType: "user" };
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(request.locals.user).toBeUndefined();
    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
  });

  // D5. The defect: `authConfig.accessToken.secret()` throws a plain `Error`
  // (no `code`) from *inside* `jwt.verify` when `JWT_SECRET` is missing/empty.
  // A broad catch answered 401 for this — mass "invalid token" on every
  // request during a config fault. It must now propagate untouched: a
  // previously-set identity survives (nothing clears it), no `unauthorized`
  // response, the caller sees the throw.
  it("propagates (does not answer 401) when jwt.verify fails for a reason with no error code — e.g. a missing JWT secret", async () => {
    jwtVerify.mockRejectedValue(
      new Error("auth: no JWT secret configured — set `auth.accessToken.secret`."),
    );

    const middleware = authMiddleware([]);
    const request = buildRequest("some-token");
    request.locals.user = { id: 99, userType: "user" };
    const response = buildResponse();

    await expect(middleware(makeCtx({ request, response }))).rejects.toThrow(
      /no JWT secret configured/,
    );

    expect(request.locals.user).toEqual({ id: 99, userType: "user" });
    expect(response.unauthorized).not.toHaveBeenCalled();
  });

  // D5. A DB/cache outage in the storage lookup is a server fault, not a
  // verdict on the caller's credential — it must not read as "invalid access
  // token" and must not clear the caller's session.
  it("propagates (does not answer 401) when the access-token storage lookup throws", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockRejectedValue(new Error("connection to database lost"));

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    request.locals.user = { id: 99, userType: "user" };
    const response = buildResponse();

    await expect(middleware(makeCtx({ request, response }))).rejects.toThrow(
      /connection to database lost/,
    );

    expect(request.locals.user).toEqual({ id: 99, userType: "user" });
    expect(response.unauthorized).not.toHaveBeenCalled();
  });

  // D5. An unknown/mis-registered user type is a deployment fault (the app
  // never registered a model for this token's principal), not a bad
  // credential — it must propagate rather than read as "invalid access token".
  it("propagates (does not answer 401) when the resolved user type maps to no registered model", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "ghost" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "ghost" }));
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key.startsWith("auth.userType.") ? undefined : fallback,
    );

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await expect(middleware(makeCtx({ request, response }))).rejects.toThrow(
      /ghost is unknown type/,
    );

    expect(response.unauthorized).not.toHaveBeenCalled();
  });

  it("falls back to the access-token row's userType when the decoded token has none", async () => {
    jwtVerify.mockResolvedValue({ id: 1 }); // no userType in the payload
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "admin" }));
    const find = vi.fn().mockResolvedValue({ id: 1, userType: "admin" });
    stubConfig({ find });

    const middleware = authMiddleware(["admin"]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(configKey).toHaveBeenCalledWith("auth.userType.admin");
    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "admin" });
  });

  it("stores the decoded access token on the request before resolving the user", async () => {
    const decoded = { id: 9, userType: "user" };
    jwtVerify.mockResolvedValue(decoded);
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 9, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(request.decodedAccessToken).toEqual(decoded);
  });

  it("looks up the access-token row by the raw authorization value", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("the-raw-token");
    const response = buildResponse();

    await middleware(makeCtx({ request, response }));

    expect(accessTokenFindByToken).toHaveBeenCalledWith("the-raw-token");
  });
});

/**
 * A logged-out human navigating to a guarded PAGE route should be redirected to
 * the login screen, not handed the API's raw JSON 401 (finding b9ab9804). This
 * is OPT-IN via `auth.pageAuth.loginPath` and backward-compatible: an API route,
 * or a page route with no `loginPath` configured, keeps the JSON 401 contract
 * unchanged. The page-vs-API signal is `request.route.isPage`.
 */
describe("authMiddleware — page-route login redirect (b9ab9804)", () => {
  /** A response that can BOTH send JSON 401 and redirect, so we see which it did. */
  function buildPageResponse() {
    return { unauthorized: vi.fn(), redirect: vi.fn() };
  }

  /** A request on a route of the given kind, at a given URL, with no credential. */
  function buildRouteRequest(isPage: boolean, url: string, locale = "en") {
    return {
      authorizationValue: undefined,
      // `cookie:token` reads the credential via request.cookie(); no cookie set
      // ⇒ empty ⇒ the missing-token rejection, which is the path under test.
      cookie: vi.fn(() => undefined),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      route: { isPage },
      url,
      locale,
    };
  }

  /** Route `config.key` so `auth.pageAuth.loginPath` resolves to `loginPath`. */
  function stubPageAuth(loginPath: string | undefined) {
    configKey.mockImplementation((key: string, fallback?: unknown) => {
      if (key === "auth.pageAuth.loginPath") return loginPath;

      return fallback; // returnUrlParam → "returnUrl"; everything else → default
    });
  }

  it("redirects a guarded PAGE request to loginPath with the original path as returnUrl", async () => {
    stubPageAuth("/login");

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(true, "/admin/posts");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.redirect).toHaveBeenCalledWith("/login?returnUrl=%2Fadmin%2Fposts");
    // Never the raw JSON blob for a browser navigating to a page.
    expect(response.unauthorized).not.toHaveBeenCalled();
  });

  it("still returns JSON 401 for an API route under the same guard (contract unchanged)", async () => {
    stubPageAuth("/login");

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(false, "/api/posts");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.MissingAccessToken }),
    );
    expect(response.redirect).not.toHaveBeenCalled();
  });

  it("leaves a PAGE route on JSON 401 when no loginPath is configured (opt-in, backward-compatible)", async () => {
    stubPageAuth(undefined);

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(true, "/admin/posts");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.MissingAccessToken }),
    );
    expect(response.redirect).not.toHaveBeenCalled();
  });

  it("appends returnUrl with & when the configured loginPath already carries a query", async () => {
    stubPageAuth("/login?flow=admin");

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(true, "/admin/posts");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.redirect).toHaveBeenCalledWith("/login?flow=admin&returnUrl=%2Fadmin%2Fposts");
  });
});

/**
 * The login redirect target must carry the request's locale prefix under an
 * active `web.localeRouting` strategy, same as `returnUrl` already does —
 * otherwise an anonymous `/ar/admin` bounces to the default locale's
 * `/login` instead of `/ar/login`. `auth` reads `web.localeRouting.strategy`
 * / `app.localeCodes` / `app.localeCode` by convention (see
 * `./localized-login-path.ts`); it never imports `web`.
 */
describe("authMiddleware — locale-prefixed login redirect", () => {
  function buildPageResponse() {
    return { unauthorized: vi.fn(), redirect: vi.fn() };
  }

  function buildRouteRequest(isPage: boolean, url: string, locale: string) {
    return {
      authorizationValue: undefined,
      cookie: vi.fn(() => undefined),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      route: { isPage },
      url,
      locale,
    };
  }

  /** Routes `config.key` for `auth.pageAuth.loginPath` plus `web`/`app` locale-routing keys. */
  function stubLocaleRouting(options: {
    loginPath: string;
    strategy?: string;
    localeCodes?: string[];
    defaultLocale?: string;
  }) {
    configKey.mockImplementation((key: string, fallback?: unknown) => {
      if (key === "auth.pageAuth.loginPath") return options.loginPath;
      if (key === "web.localeRouting.strategy") return options.strategy ?? "none";
      if (key === "app.localeCodes") return options.localeCodes ?? [];
      if (key === "app.localeCode") return options.defaultLocale ?? "";

      return fallback; // returnUrlParam → "returnUrl"; everything else → default
    });
  }

  it("redirects an ar request to the locale-prefixed login path under strategy prefix", async () => {
    stubLocaleRouting({
      loginPath: "/login",
      strategy: "prefix",
      localeCodes: ["en", "ar"],
      defaultLocale: "en",
    });

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(true, "/ar/admin", "ar");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.redirect).toHaveBeenCalledWith("/ar/login?returnUrl=%2Far%2Fadmin");
  });

  it("redirects an en request to the bare login path under strategy prefix-except-default", async () => {
    stubLocaleRouting({
      loginPath: "/login",
      strategy: "prefix-except-default",
      localeCodes: ["en", "ar"],
      defaultLocale: "en",
    });

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(true, "/admin", "en");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.redirect).toHaveBeenCalledWith("/login?returnUrl=%2Fadmin");
  });

  it("redirects an ar request to the ar-prefixed login path under strategy prefix-except-default", async () => {
    stubLocaleRouting({
      loginPath: "/login",
      strategy: "prefix-except-default",
      localeCodes: ["en", "ar"],
      defaultLocale: "en",
    });

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(true, "/ar/admin", "ar");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.redirect).toHaveBeenCalledWith("/ar/login?returnUrl=%2Far%2Fadmin");
  });

  it("leaves loginPath unchanged when strategy is none", async () => {
    stubLocaleRouting({
      loginPath: "/login",
      strategy: "none",
      localeCodes: ["en", "ar"],
      defaultLocale: "en",
    });

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(true, "/admin", "ar");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.redirect).toHaveBeenCalledWith("/login?returnUrl=%2Fadmin");
  });

  it("leaves an already-prefixed loginPath unchanged", async () => {
    stubLocaleRouting({
      loginPath: "/ar/login",
      strategy: "prefix",
      localeCodes: ["en", "ar"],
      defaultLocale: "en",
    });

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(true, "/ar/admin", "ar");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.redirect).toHaveBeenCalledWith("/ar/login?returnUrl=%2Far%2Fadmin");
  });

  it("leaves an absolute loginPath unchanged", async () => {
    stubLocaleRouting({
      loginPath: "https://accounts.example.com/login",
      strategy: "prefix",
      localeCodes: ["en", "ar"],
      defaultLocale: "en",
    });

    const middleware = authMiddleware([], "cookie:token");
    const request = buildRouteRequest(true, "/ar/admin", "ar");
    const response = buildPageResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.redirect).toHaveBeenCalledWith(
      "https://accounts.example.com/login?returnUrl=%2Far%2Fadmin",
    );
  });
});

/**
 * CSRF Origin check:
 * a cookie-sourced credential on an unsafe method (POST/PUT/PATCH/DELETE) must
 * carry an `Origin` — or, absent that, `Referer` — naming the request's own
 * origin or an entry in `auth.csrf.allowedOrigins`. Header-token auth and safe
 * methods (GET/HEAD/OPTIONS) are completely unaffected.
 */
describe("authMiddleware — CSRF Origin check (cookie source, unsafe method)", () => {
  const OWN_ORIGIN = "https://app.example.com";

  /** A response that can answer 403 (forbidden), 401 (unauthorized), or neither (success). */
  function buildCsrfResponse() {
    return { unauthorized: vi.fn(), forbidden: vi.fn() };
  }

  /**
   * A request on `https://app.example.com`, with the given method and
   * Origin/Referer, presenting a credential via cookie or header depending on
   * `source`.
   */
  function buildCsrfRequest(options: {
    method: string;
    source: "cookie" | "header";
    origin?: string;
    referer?: string;
    protocol?: string;
    hostname?: string;
    /** Raw `Host` header value (may include a port), e.g. `"localhost:41910"`. */
    host?: string;
  }) {
    const { method, source, origin, referer } = options;
    const protocol = options.protocol ?? "https";
    const hostname = options.hostname ?? "app.example.com";
    const host = options.host ?? hostname;

    return {
      authorizationValue: source === "header" ? "the-token" : undefined,
      cookie: vi.fn((name: string) =>
        source === "cookie" && name === "token" ? "the-token" : undefined,
      ),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      method,
      origin,
      protocol,
      hostname,
      header: vi.fn((name: string) => {
        if (name === "referer") return referer;
        if (name === "host") return host;

        return null;
      }),
    };
  }

  /** Full success chain, so an allowed request reaches `request.locals.user`. */
  function stubSuccessfulAuth() {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });
  }

  it("allows a cookie-authenticated POST when Origin matches the request's own origin", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({ method: "POST", source: "cookie", origin: OWN_ORIGIN });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).not.toHaveBeenCalled();
    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("allows a cookie-authenticated POST when Origin is in auth.csrf.allowedOrigins", async () => {
    stubSuccessfulAuth();
    configKey.mockImplementation((key: string, fallback?: unknown) => {
      if (key === "auth.csrf.allowedOrigins") return ["https://allowed.example.com"];
      if (key.startsWith("auth.userType."))
        return { find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) };

      return fallback;
    });

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({
      method: "POST",
      source: "cookie",
      origin: "https://allowed.example.com",
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("rejects a cookie-authenticated POST from a foreign Origin with 403 CsrfOriginMismatch", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({
      method: "POST",
      source: "cookie",
      origin: "https://evil.example.com",
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.CsrfOriginMismatch }),
    );
    expect(request.locals.user).toBeUndefined();
  });

  it("allows a cookie-authenticated POST with no Origin but a same-origin Referer", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({
      method: "POST",
      source: "cookie",
      referer: `${OWN_ORIGIN}/some/page`,
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("rejects a cookie-authenticated POST with neither Origin nor Referer", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({ method: "POST", source: "cookie" });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.CsrfOriginMismatch }),
    );
    expect(request.locals.user).toBeUndefined();
  });

  it("leaves header-token auth unaffected: a foreign-Origin POST is allowed", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([]); // default tokenFrom: "header"
    const request = buildCsrfRequest({
      method: "POST",
      source: "header",
      origin: "https://evil.example.com",
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("leaves safe methods unaffected: a cookie-authenticated GET from a foreign Origin is allowed", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({
      method: "GET",
      source: "cookie",
      origin: "https://evil.example.com",
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  /**
   * `request.hostname` (Express/Fastify's hostname) never carries a port, but
   * a browser's `Origin`/Host pair on a non-default port (any `warlock dev`
   * session) always does. The own-origin comparison must include the port
   * from the `Host` header, not just the bare hostname.
   */
  it("allows a cookie-authenticated POST when Origin is same-origin on a non-default port", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({
      method: "POST",
      source: "cookie",
      origin: "http://localhost:41910",
      protocol: "http",
      hostname: "localhost",
      host: "localhost:41910",
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("rejects a cookie-authenticated POST when Origin's port differs from the Host header's port", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({
      method: "POST",
      source: "cookie",
      origin: "http://localhost:3000",
      protocol: "http",
      hostname: "localhost",
      host: "localhost:41910",
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.CsrfOriginMismatch }),
    );
    expect(request.locals.user).toBeUndefined();
  });

  it("allows a cookie-authenticated POST when Origin omits the default port and Host carries it", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({
      method: "POST",
      source: "cookie",
      origin: OWN_ORIGIN,
      protocol: "https",
      hostname: "app.example.com",
      host: "app.example.com:443",
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });

  it("still rejects a cross-site Origin with a port with 403 CsrfOriginMismatch", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({
      method: "POST",
      source: "cookie",
      origin: "https://evil.example.com:41910",
      protocol: "http",
      hostname: "localhost",
      host: "localhost:41910",
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.CsrfOriginMismatch }),
    );
    expect(request.locals.user).toBeUndefined();
  });

  it("allows a cookie-authenticated POST with no Origin but a same-origin Referer carrying a port", async () => {
    stubSuccessfulAuth();

    const middleware = authMiddleware([], "cookie:token");
    const request = buildCsrfRequest({
      method: "POST",
      source: "cookie",
      referer: "http://localhost:41910/some/page",
      protocol: "http",
      hostname: "localhost",
      host: "localhost:41910",
    });
    const response = buildCsrfResponse();

    await middleware(makeCtx({ request, response }));

    expect(response.forbidden).not.toHaveBeenCalled();
    expect(request.locals.user).toEqual({ id: 1, userType: "user" });
  });
});

/**
 * Regression spec for design-note section 4 (already-correct behavior, pinned
 * here so it cannot silently regress): a cookie-sourced credential sets
 * `request.decodedAccessToken` exactly like a header-sourced one, which is
 * what makes `Request`'s `decodedAccessToken` setter mark
 * `request.locals.authDerived = true` and therefore the page cache floor
 * (`private, no-store`, `web/src/server/response-cache-floor.ts`) apply. The
 * web-side assertion (`private, no-store` on an actual response) is NOT run
 * here — see `auth-derived-cache-headers.spec.ts` in `web/` for that half;
 * this spec only pins the auth-side precondition the web behavior depends on.
 */
describe("authMiddleware — cookie auth sets decodedAccessToken (cache-floor precondition)", () => {
  it("sets request.decodedAccessToken for a cookie-sourced credential, same as header auth", async () => {
    const decoded = { id: 1, userType: "user" };
    jwtVerify.mockResolvedValue(decoded);
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([], "cookie:token");
    const request = {
      authorizationValue: undefined,
      cookie: vi.fn((name: string) => (name === "token" ? "the-token" : undefined)),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      method: "GET",
    };
    const response = { unauthorized: vi.fn(), forbidden: vi.fn() };

    await middleware(makeCtx({ request, response }));

    expect(request.decodedAccessToken).toEqual(decoded);
  });
});
