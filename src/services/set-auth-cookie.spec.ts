import { beforeEach, describe, expect, it, vi } from "vitest";

// ── models (auth.service.ts imports these at module scope) ─────────────────
vi.mock("../models/access-token", () => ({ AccessToken: {} }));
vi.mock("../models/refresh-token", () => ({ RefreshToken: {} }));
vi.mock("../models/auth-token-family", () => ({ AuthTokenFamily: {} }));
vi.mock("../models/one-time-token", () => ({ OneTimeToken: {} }));

// ── core ────────────────────────────────────────────────────────────────────
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

/** A mocked `Response` exposing only the two methods under test. */
function buildResponse() {
  return { cookie: vi.fn(), clearCookie: vi.fn() };
}

/** Route `config.key` so `auth.cookie.*` resolves to the package defaults unless overridden. */
function stubCookieConfig(overrides: Record<string, unknown> = {}) {
  configKey.mockImplementation((key: string, fallback?: unknown) => {
    if (key in overrides) return overrides[key];

    return fallback;
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  stubCookieConfig();
});

describe("authService.setAuthCookie", () => {
  it("writes the token raw, under the default name and path, with no maxAge for a bare string", () => {
    const response = buildResponse();

    authService.setAuthCookie(response as never, "the-jwt");

    expect(response.cookie).toHaveBeenCalledWith("access_token", "the-jwt", {
      raw: true,
      path: "/",
    });
  });

  it("derives maxAge (seconds) from an AccessTokenOutput's expiresAt", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

    const response = buildResponse();
    const expiresAt = new Date("2026-01-01T01:00:00.000Z").toISOString(); // +1h

    authService.setAuthCookie(response as never, { token: "the-jwt", expiresAt });

    expect(response.cookie).toHaveBeenCalledWith("access_token", "the-jwt", {
      raw: true,
      path: "/",
      maxAge: 3600,
    });

    vi.useRealTimers();
  });

  it("lets an explicit options.maxAge override the derived expiry", () => {
    const response = buildResponse();

    authService.setAuthCookie(
      response as never,
      { token: "the-jwt", expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
      { maxAge: 60 },
    );

    expect(response.cookie).toHaveBeenCalledWith(
      "access_token",
      "the-jwt",
      expect.objectContaining({ maxAge: 60 }),
    );
  });

  it("honors auth.cookie.name / auth.cookie.path config", () => {
    stubCookieConfig({ "auth.cookie.name": "session", "auth.cookie.path": "/app" });
    const response = buildResponse();

    authService.setAuthCookie(response as never, "the-jwt");

    expect(response.cookie).toHaveBeenCalledWith("session", "the-jwt", {
      raw: true,
      path: "/app",
    });
  });

  it("lets per-call name/path override config", () => {
    const response = buildResponse();

    authService.setAuthCookie(response as never, "the-jwt", { name: "custom", path: "/x" });

    expect(response.cookie).toHaveBeenCalledWith(
      "custom",
      "the-jwt",
      expect.objectContaining({ path: "/x" }),
    );
  });
});

describe("authService.clearAuthCookie", () => {
  it("clears the default-named cookie at the default path", () => {
    const response = buildResponse();

    authService.clearAuthCookie(response as never);

    expect(response.clearCookie).toHaveBeenCalledWith("access_token", { path: "/" });
  });

  it("honors auth.cookie.name / auth.cookie.path config", () => {
    stubCookieConfig({ "auth.cookie.name": "session", "auth.cookie.path": "/app" });
    const response = buildResponse();

    authService.clearAuthCookie(response as never);

    expect(response.clearCookie).toHaveBeenCalledWith("session", { path: "/app" });
  });

  it("lets per-call name/path override config", () => {
    const response = buildResponse();

    authService.clearAuthCookie(response as never, { name: "custom", path: "/x" });

    expect(response.clearCookie).toHaveBeenCalledWith("custom", { path: "/x" });
  });
});
