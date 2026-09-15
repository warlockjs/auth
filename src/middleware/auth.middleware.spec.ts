import { beforeEach, describe, expect, it, vi } from "vitest";

const configKey = vi.fn();
const jwtVerify = vi.fn();
const accessTokenFindByToken = vi.fn();

vi.mock("@warlock.js/core", () => ({
  config: { key: (...args: unknown[]) => configKey(...args) },
  t: (key: string) => key,
}));

vi.mock("@warlock.js/logger", () => ({
  log: { error: vi.fn() },
}));

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
  return { unauthorized: vi.fn() };
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
});

describe("authMiddleware", () => {
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

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.Unauthorized }),
    );
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
    jwtVerify.mockRejectedValue(Object.assign(new Error("malformed token"), {
      code: "FAST_JWT_MALFORMED",
    }));

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
    jwtVerify.mockRejectedValue(Object.assign(new Error("token expired"), {
      code: "FAST_JWT_EXPIRED",
    }));

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
  function buildRouteRequest(isPage: boolean, url: string) {
    return {
      authorizationValue: undefined,
      // `cookie:token` reads the credential via request.cookie(); no cookie set
      // ⇒ empty ⇒ the missing-token rejection, which is the path under test.
      cookie: vi.fn(() => undefined),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      route: { isPage },
      url,
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
 * CSRF Origin check (lead decision 3, `releases/v5.12-cookie-auth-design-note.md`):
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
  }) {
    const { method, source, origin, referer } = options;

    return {
      authorizationValue: source === "header" ? "the-token" : undefined,
      cookie: vi.fn((name: string) => (source === "cookie" && name === "token" ? "the-token" : undefined)),
      locals: { user: undefined as unknown },
      decodedAccessToken: undefined as unknown,
      method,
      origin,
      protocol: "https",
      hostname: "app.example.com",
      header: vi.fn((name: string) => (name === "referer" ? referer : null)),
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
      if (key.startsWith("auth.userType.")) return { find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) };

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
describe("authMiddleware — cookie auth sets decodedAccessToken (cache-floor precondition, design note §4)", () => {
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
