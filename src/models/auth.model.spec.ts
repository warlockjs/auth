import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@warlock.js/cascade", () => ({
  Model: class {},
}));

vi.mock("../services", () => ({
  authService: {
    verifyPassword: vi.fn().mockResolvedValue(true),
    buildAccessTokenPayload: vi.fn(),
    createTokenPair: vi.fn(),
    generateAccessToken: vi.fn(),
    createRefreshToken: vi.fn(),
    removeAccessToken: vi.fn(),
    removeRefreshToken: vi.fn(),
    removeAllAccessTokens: vi.fn(),
    revokeAllTokens: vi.fn(),
    getActiveSessions: vi.fn(),
    attemptLogin: vi.fn(),
  },
}));

import { authService } from "../services";
import { Auth } from "./auth.model";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Auth.confirmPassword", () => {
  it("forwards (plaintext, storedHash) to verifyPassword in that order", async () => {
    const storedHash = "$2a$12$storedHashValue";
    const user = {
      string: (key: string) => (key === "password" ? storedHash : undefined),
    };

    await Auth.prototype.confirmPassword.call(user as unknown as Auth, "plain-input");

    expect(authService.verifyPassword).toHaveBeenCalledWith("plain-input", storedHash);
  });
});

describe("Auth delegation to authService", () => {
  it("accessTokenPayload delegates to buildAccessTokenPayload(this)", () => {
    const user = { id: 1 } as unknown as Auth;

    Auth.prototype.accessTokenPayload.call(user);

    expect(authService.buildAccessTokenPayload).toHaveBeenCalledWith(user);
  });

  it("createTokenPair forwards (this, deviceInfo)", async () => {
    const user = { id: 1 } as unknown as Auth;
    const deviceInfo = { ip: "1.2.3.4" };

    await Auth.prototype.createTokenPair.call(user, deviceInfo);

    expect(authService.createTokenPair).toHaveBeenCalledWith(user, deviceInfo);
  });

  it("generateAccessToken forwards (this, data)", async () => {
    const user = { id: 1 } as unknown as Auth;
    const data = { custom: "claim" };

    await Auth.prototype.generateAccessToken.call(user, data);

    expect(authService.generateAccessToken).toHaveBeenCalledWith(user, data);
  });

  it("generateRefreshToken maps to authService.createRefreshToken(this, deviceInfo)", async () => {
    const user = { id: 1 } as unknown as Auth;
    const deviceInfo = { deviceId: "d-1" };

    await Auth.prototype.generateRefreshToken.call(user, deviceInfo);

    expect(authService.createRefreshToken).toHaveBeenCalledWith(user, deviceInfo);
  });

  it("removeAccessToken forwards (this, token)", async () => {
    const user = { id: 1 } as unknown as Auth;

    await Auth.prototype.removeAccessToken.call(user, "tok");

    expect(authService.removeAccessToken).toHaveBeenCalledWith(user, "tok");
  });

  it("removeRefreshToken forwards (this, token)", async () => {
    const user = { id: 1 } as unknown as Auth;

    await Auth.prototype.removeRefreshToken.call(user, "rtok");

    expect(authService.removeRefreshToken).toHaveBeenCalledWith(user, "rtok");
  });

  it("removeAllAccessTokens forwards (this)", async () => {
    const user = { id: 1 } as unknown as Auth;

    await Auth.prototype.removeAllAccessTokens.call(user);

    expect(authService.removeAllAccessTokens).toHaveBeenCalledWith(user);
  });

  it("revokeAllTokens forwards (this)", async () => {
    const user = { id: 1 } as unknown as Auth;

    await Auth.prototype.revokeAllTokens.call(user);

    expect(authService.revokeAllTokens).toHaveBeenCalledWith(user);
  });

  it("activeSessions maps to authService.getActiveSessions(this)", async () => {
    const user = { id: 1 } as unknown as Auth;

    await Auth.prototype.activeSessions.call(user);

    expect(authService.getActiveSessions).toHaveBeenCalledWith(user);
  });

  it("static attempt maps to authService.attemptLogin(this, data)", async () => {
    const Model = function () {} as never;
    const data = { email: "a@b.c", password: "x" };

    await Auth.attempt.call(Model, data);

    expect(authService.attemptLogin).toHaveBeenCalledWith(Model, data);
  });
});
