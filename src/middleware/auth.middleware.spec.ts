import { beforeEach, describe, expect, it, vi } from "vitest";

const configKey = vi.fn();
const jwtVerify = vi.fn();
const accessTokenFirst = vi.fn();

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
  AccessToken: { first: (...args: unknown[]) => accessTokenFirst(...args) },
}));

import { authMiddleware } from "./auth.middleware";
import { AuthErrorCodes } from "../utils/auth-error-codes";

type FakeResponse = {
  unauthorized: ReturnType<typeof vi.fn>;
};

function buildRequest(authorizationValue?: string) {
  return {
    authorizationValue,
    user: undefined as unknown,
    decodedAccessToken: undefined as unknown,
    clearCurrentUser: vi.fn(),
  };
}

function buildResponse(): FakeResponse {
  return { unauthorized: vi.fn() };
}

function stubAuthenticatedUser(userType: string) {
  jwtVerify.mockResolvedValue({ id: 1, userType });

  accessTokenFirst.mockResolvedValue({
    get: (key: string) => (key === "user_type" ? userType : undefined),
  });

  configKey.mockReturnValue({ find: vi.fn().mockResolvedValue({ id: 1, userType }) });
}

describe("authMiddleware", () => {
  beforeEach(() => {
    configKey.mockReset();
    jwtVerify.mockReset();
    accessTokenFirst.mockReset();
  });

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
    stubAuthenticatedUser("user");

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.user).toEqual({ id: 1, userType: "user" });
  });

  it("rejects an authenticated user whose type is not in the allow-list", async () => {
    stubAuthenticatedUser("user");

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
    stubAuthenticatedUser("user");

    const middleware = authMiddleware(["user"]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.user).toEqual({ id: 1, userType: "user" });
  });

  it("rejects when the token verifies but no access-token row exists", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFirst.mockResolvedValue(null);

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

    accessTokenFirst.mockResolvedValue({
      get: (key: string) => (key === "user_type" ? "user" : undefined),
      destroy,
    });

    configKey.mockReturnValue({ find: vi.fn().mockResolvedValue(null) });

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

    accessTokenFirst.mockResolvedValue({
      get: (key: string) => (key === "user_type" ? "ghost" : undefined),
    });

    configKey.mockReturnValue(undefined);

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(response.unauthorized).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: AuthErrorCodes.InvalidAccessToken }),
    );
  });

  it("falls back to the access-token row's userType when the decoded token has none", async () => {
    // decoded payload carries no userType; the stored row supplies "admin"
    jwtVerify.mockResolvedValue({ id: 1 });

    accessTokenFirst.mockResolvedValue({
      get: (key: string) => (key === "user_type" ? "admin" : undefined),
    });

    const find = vi.fn().mockResolvedValue({ id: 1, userType: "admin" });
    configKey.mockReturnValue({ find });

    const middleware = authMiddleware(["admin"]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    // the model was looked up under the row-supplied "admin" type
    expect(configKey).toHaveBeenCalledWith("auth.userType.admin");
    expect(response.unauthorized).not.toHaveBeenCalled();
    expect(request.user).toEqual({ id: 1, userType: "admin" });
  });

  it("stores the decoded access token on the request before resolving the user", async () => {
    const decoded = { id: 9, userType: "user" };
    jwtVerify.mockResolvedValue(decoded);
    accessTokenFirst.mockResolvedValue({
      get: (key: string) => (key === "user_type" ? "user" : undefined),
    });
    configKey.mockReturnValue({ find: vi.fn().mockResolvedValue({ id: 9, userType: "user" }) });

    const middleware = authMiddleware([]);
    const request = buildRequest("valid-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(request.decodedAccessToken).toEqual(decoded);
  });

  it("looks up the access-token row by the raw authorization value", async () => {
    stubAuthenticatedUser("user");

    const middleware = authMiddleware([]);
    const request = buildRequest("the-raw-token");
    const response = buildResponse();

    await middleware(request as never, response as never);

    expect(accessTokenFirst).toHaveBeenCalledWith({ token: "the-raw-token" });
  });
});
