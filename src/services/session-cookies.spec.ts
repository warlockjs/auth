import { beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import type { Response } from "@warlock.js/core";
import type { CookieWriter } from "../contracts/types";

vi.mock("../models/access-token", () => ({ AccessToken: {} }));
vi.mock("../models/refresh-token", () => ({ RefreshToken: {} }));
vi.mock("../models/auth-token-family", () => ({ AuthTokenFamily: {} }));
vi.mock("../models/one-time-token", () => ({ OneTimeToken: {} }));

const configKey = vi.fn();

vi.mock("@warlock.js/core", () => ({
  config: { key: (...args: unknown[]) => configKey(...args) },
  hashPassword: vi.fn(),
  verifyPassword: vi.fn(),
  ForbiddenError: class ForbiddenError extends Error {},
}));

vi.mock("@warlock.js/logger", () => ({
  log: { warn: vi.fn(), error: vi.fn() },
}));

vi.mock("@mongez/reinforcements", () => ({
  Random: { string: vi.fn() },
}));

import { authService } from "./auth.service";

function buildResponse() {
  return { cookie: vi.fn(), clearCookie: vi.fn() };
}

function stubCookieConfig(overrides: Record<string, unknown> = {}) {
  configKey.mockImplementation((key: string, fallback?: unknown) => {
    if (key in overrides) return overrides[key];

    return fallback;
  });
}

const NOW = new Date("2026-01-01T00:00:00.000Z");

const tokens = {
  accessToken: { token: "the-access", expiresAt: new Date(NOW.getTime() + 3_600_000).toISOString() },
  refreshToken: {
    token: "the-refresh",
    expiresAt: new Date(NOW.getTime() + 7 * 86_400_000).toISOString(),
  },
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  stubCookieConfig();
});

describe("authService.setSessionCookies", () => {
  it("sets both cookies HttpOnly, Lax, Path=/ with each token's own lifetime", () => {
    const response = buildResponse();

    authService.setSessionCookies(response, tokens);

    expect(response.cookie).toHaveBeenCalledTimes(2);
    expect(response.cookie).toHaveBeenCalledWith("access_token", "the-access", {
      raw: true,
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 3600,
    });
    expect(response.cookie).toHaveBeenCalledWith("refresh_token", "the-refresh", {
      raw: true,
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 86_400,
    });
  });

  it("honours custom names and stays on Path=/ whatever auth.cookie.path says", () => {
    stubCookieConfig({
      "auth.cookie.name": "sid",
      "auth.cookie.refreshName": "rid",
      "auth.cookie.path": "/app",
    });
    const response = buildResponse();

    authService.setSessionCookies(response, tokens);

    expect(response.cookie).toHaveBeenCalledWith(
      "sid",
      "the-access",
      expect.objectContaining({ path: "/" }),
    );
    expect(response.cookie).toHaveBeenCalledWith(
      "rid",
      "the-refresh",
      expect.objectContaining({ path: "/" }),
    );
  });
});

describe("authService.clearSessionCookies", () => {
  it("clears both default-named cookies on Path=/", () => {
    const response = buildResponse();

    authService.clearSessionCookies(response);

    expect(response.clearCookie).toHaveBeenCalledWith("access_token", { path: "/" });
    expect(response.clearCookie).toHaveBeenCalledWith("refresh_token", { path: "/" });
  });

  it("honours custom names", () => {
    stubCookieConfig({ "auth.cookie.name": "sid", "auth.cookie.refreshName": "rid" });
    const response = buildResponse();

    authService.clearSessionCookies(response);

    expect(response.clearCookie).toHaveBeenCalledWith("sid", { path: "/" });
    expect(response.clearCookie).toHaveBeenCalledWith("rid", { path: "/" });
  });
});

describe("CookieWriter", () => {
  it("accepts core's Response and any object with cookie/clearCookie", () => {
    expectTypeOf<Response>().toMatchTypeOf<CookieWriter>();
    expectTypeOf(buildResponse()).toMatchTypeOf<CookieWriter>();
  });
});
