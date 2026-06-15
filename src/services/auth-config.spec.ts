import { beforeEach, describe, expect, it, vi } from "vitest";

const configKey = vi.fn();
const logWarn = vi.fn();

vi.mock("@warlock.js/core", () => ({
  config: { key: (...args: unknown[]) => configKey(...args) },
}));

vi.mock("@warlock.js/logger", () => ({
  log: { warn: (...args: unknown[]) => logWarn(...args) },
}));

import { authConfig } from "./auth-config";

beforeEach(() => {
  vi.clearAllMocks();
  configKey.mockReturnValue(undefined);
});

describe("authConfig resolver", () => {
  it("prefers the new accessToken.* / refreshToken.* key", () => {
    configKey.mockImplementation((key: string) =>
      key === "auth.accessToken.secret" ? "new-secret" : undefined,
    );

    expect(authConfig.accessToken.secret()).toBe("new-secret");
    expect(logWarn).not.toHaveBeenCalled();
  });

  it("falls back to the deprecated jwt.* key and warns", () => {
    configKey.mockImplementation((key: string) =>
      key === "auth.jwt.secret" ? "legacy-secret" : undefined,
    );

    expect(authConfig.accessToken.secret()).toBe("legacy-secret");
    expect(logWarn).toHaveBeenCalledOnce();
  });

  it("returns the documented defaults when nothing is configured", () => {
    expect(authConfig.accessToken.algorithm()).toBe("HS256");
    expect(authConfig.accessToken.expiresIn()).toBeUndefined();
    expect(authConfig.refreshToken.enabled()).toBe(true);
    expect(authConfig.refreshToken.expiresIn()).toBe("7d");
    expect(authConfig.refreshToken.rotation()).toBe(true);
    expect(authConfig.refreshToken.maxPerUser()).toBe(5);
    expect(authConfig.refreshToken.logoutWithoutToken()).toBe("revoke-all");
  });

  it("honours a falsy-but-set value rather than the default", () => {
    configKey.mockImplementation((key: string) =>
      key === "auth.refreshToken.enabled" ? false : undefined,
    );

    expect(authConfig.refreshToken.enabled()).toBe(false);
  });

  it("warns at most once for the same legacy key", () => {
    configKey.mockImplementation((key: string) =>
      key === "auth.jwt.refresh.rotation" ? false : undefined,
    );

    authConfig.refreshToken.rotation();
    authConfig.refreshToken.rotation();

    expect(logWarn).toHaveBeenCalledOnce();
  });
});
