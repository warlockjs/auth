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
    accessTokenFindByToken.mockResolvedValue({ userType: "user" });
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
    accessTokenFindByToken.mockResolvedValue({ userType: "user" });
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
    accessTokenFindByToken.mockResolvedValue({ userType: "user" });
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

  it("destroys the access-token row and rejects when the user no longer exists", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    const destroy = vi.fn();
    accessTokenFindByToken.mockResolvedValue({ userType: "user", destroy });
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
    accessTokenFindByToken.mockResolvedValue({ userType: "ghost" });
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
    accessTokenFindByToken.mockResolvedValue({ userType: "admin" });
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
    accessTokenFindByToken.mockResolvedValue({ userType: "user" });
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 9, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(request.decodedAccessToken).toEqual(decoded);
  });

  it("looks up the access-token row by the raw authorization value", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue({ userType: "user" });
    stubConfig({ find: vi.fn().mockResolvedValue({ id: 1, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("the-raw-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(accessTokenFindByToken).toHaveBeenCalledWith("the-raw-token");
  });
});
