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

vi.mock("../services/jwt", () => ({
  jwt: { verify: (...args: unknown[]) => jwtVerify(...args) },
}));

vi.mock("../models/access-token", () => ({
  AccessToken: { findByToken: (...args: unknown[]) => accessTokenFindByToken(...args) },
}));

import { authMiddleware } from "./auth.middleware";
import { AuthErrorCodes } from "../utils/auth-error-codes";

function buildRequest(authorizationValue?: string) {
  return {
    authorizationValue,
    user: undefined as unknown,
    decodedAccessToken: undefined as unknown,
    clearCurrentUser: vi.fn(),
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

    await middleware(request as never, response as never);

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.MissingAccessToken }),
    );
    expect(request.user).toBeUndefined();
  });

  it("allows any authenticated user when called with an empty array", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.user).toEqual({ id: 1, userType: "user" });
  });

  it("rejects an authenticated user whose type is not in the allow-list", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn() });

    const middleware = authMiddleware(["admin"]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.Unauthorized }),
    );
    expect(request.user).toBeUndefined();
  });

  it("allows an authenticated user whose type matches the allow-list", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware(["user"]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.user).toEqual({ id: 1, userType: "user" });
  });

  it("rejects when the token verifies but no access-token row exists", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(null);

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
    expect(request.user).toBeUndefined();
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

    await middleware(request as never, response as never);

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
    expect(request.user).toBeUndefined();
  });

  it("deletes the dead row on the way out rather than leaving it for cleanup", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user", exp: 4_102_444_800 });
    const destroy = vi.fn();
    accessTokenFindByToken.mockResolvedValue({ userType: "user", isExpired: true, destroy });
    // The user resolves, so the expiry gate is the only path that can destroy
    // the row — otherwise the pre-existing user-not-found branch would.
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);

    await middleware(buildRequest("valid-token") as never, buildResponse() as never);

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

    await middleware(request as never, response as never);

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
    expect(request.user).toBeUndefined();
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

    await middleware(request as never, response as never);

    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.user).toEqual({ id: 1, userType: "user" });
  });

  it("destroys the access-token row and rejects when the user no longer exists", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    const destroy = vi.fn();
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user", destroy }));
    stubConfig({ find: vi.fn().mockResolvedValue(null) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(destroy).toHaveBeenCalledOnce();
    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
  });

  it("rejects and clears the current user when token verification throws", async () => {
    jwtVerify.mockRejectedValue(new Error("malformed token"));

    const middleware = authMiddleware([]);
    const request = buildRequest("garbage-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(request.clearCurrentUser).toHaveBeenCalledOnce();
    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
  });

  it("rejects when the resolved user type maps to no registered model", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "ghost" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "ghost" }));
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key.startsWith("auth.userType.") ? undefined : fallback,
    );

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
  });

  it("falls back to the access-token row's userType when the decoded token has none", async () => {
    jwtVerify.mockResolvedValue({ id: 1 }); // no userType in the payload
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "admin" }));
    const find = vi.fn().mockResolvedValue({ id: 1, userType: "admin" });
    stubConfig({ find });

    const middleware = authMiddleware(["admin"]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(configKey).toHaveBeenCalledWith("auth.userType.admin");
    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.user).toEqual({ id: 1, userType: "admin" });
  });

  it("stores the decoded access token on the request before resolving the user", async () => {
    const decoded = { id: 9, userType: "user" };
    jwtVerify.mockResolvedValue(decoded);
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 9, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(request.decodedAccessToken).toEqual(decoded);
  });

  it("looks up the access-token row by the raw authorization value", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow({ userType: "user" }));
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("the-raw-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(accessTokenFindByToken).toHaveBeenCalledWith("the-raw-token");
  });
});
