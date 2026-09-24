import { beforeEach, describe, expect, it, vi } from "vitest";

const configKey = vi.fn();
const verdict = vi.fn();
const findFamily = vi.fn();
const findByToken = vi.fn();

vi.mock("../models/access-token", () => ({ AccessToken: {} }));
vi.mock("../models/auth-token-family", () => ({
  AuthTokenFamily: {
    ensure: vi.fn(),
    findByFamilyId: (...a: unknown[]) => findFamily(...a),
  },
}));
vi.mock("../models/one-time-token", () => ({ OneTimeToken: {} }));
vi.mock("../models/refresh-token", () => ({
  RefreshToken: { findByToken: (...a: unknown[]) => findByToken(...a) },
}));
vi.mock("./token-family-operation", () => ({
  runTokenFamilyOperation: (_id: string, fn: () => unknown) => Promise.resolve().then(fn),
  afterTokenFamilyOperation: (fn: () => void) => fn(),
  TokenFamilyUnavailableError: class extends Error {},
}));
vi.mock("./jwt", () => ({
  isInvalidCredentialError: () => false,
  jwt: {
    verifyRefreshToken: async () => ({ userId: 1, userType: "user", familyId: "fam" }),
  },
}));
vi.mock("@warlock.js/core", () => ({
  config: { key: (...a: unknown[]) => configKey(...a) },
  hashPassword: vi.fn(),
  verifyPassword: vi.fn(),
  resolveCsrfOriginVerdict: (...a: unknown[]) => verdict(...a),
  ForbiddenError: class ForbiddenError extends Error {},
}));
vi.mock("@warlock.js/logger", () => ({ log: { warn: vi.fn(), error: vi.fn() } }));
vi.mock("@mongez/reinforcements", () => ({ Random: { string: vi.fn() } }));

import { authService } from "./auth.service";

const DAY = 86_400_000;

beforeEach(() => {
  vi.clearAllMocks();
  configKey.mockImplementation((_key: string, fallback?: unknown) => fallback);
});

describe("renewAutomaticSession maxAge", () => {
  function primeToken() {
    const oldToken = {
      familyId: "fam",
      userId: 1,
      userType: "user",
      isValid: true,
      revokeIfActive: vi.fn(),
    };

    findByToken.mockResolvedValue(oldToken);
    (authService as any).refreshIdentityMatches = () => true;
    const revoke = vi.spyOn(authService, "revokeTokenFamily").mockResolvedValue();

    return { oldToken, revoke };
  }

  it("refuses to rotate a family older than maxAge and revokes it", async () => {
    const { oldToken, revoke } = primeToken();
    findFamily.mockResolvedValue({ get: () => new Date(Date.now() - 31 * DAY) });

    const pair = await authService.renewAutomaticSession("r", "user", { maxAgeMs: 30 * DAY });

    expect(pair).toBeNull();
    expect(revoke).toHaveBeenCalledWith("fam");
    expect(oldToken.revokeIfActive).not.toHaveBeenCalled();
  });

  it("does not look at the family when no maxAge is given", async () => {
    const { revoke } = primeToken();
    findFamily.mockResolvedValue({ get: () => new Date(Date.now() - 400 * DAY) });

    await authService.renewAutomaticSession("r", "user").catch(() => undefined);

    expect(findFamily).not.toHaveBeenCalled();
    expect(revoke).not.toHaveBeenCalled();
  });
});

describe("loginWithSessionCookies", () => {
  it("rejects a cookie-less login without Origin/Referer before checking credentials", async () => {
    verdict.mockReturnValue({ allowed: false, reason: "missing-origin-and-referer" });
    const login = vi.spyOn(authService, "login");

    await expect(
      authService.loginWithSessionCookies({} as never, {} as never, {} as never, {} as never),
    ).rejects.toMatchObject({
      name: "CsrfOriginMismatchError",
      reason: "missing-origin-and-referer",
    });
    expect(login).not.toHaveBeenCalled();
  });

  it("logs in and sets both session cookies for a same-origin request", async () => {
    verdict.mockReturnValue({ allowed: true });
    const tokens = {
      accessToken: { token: "a", expiresAt: new Date(Date.now() + 1000).toISOString() },
      refreshToken: { token: "r", expiresAt: new Date(Date.now() + 5000).toISOString() },
    };
    vi.spyOn(authService, "login").mockResolvedValue({ user: {}, tokens } as never);
    const setCookies = vi
      .spyOn(authService, "setSessionCookies")
      .mockImplementation(() => undefined);

    const result = await authService.loginWithSessionCookies(
      {} as never,
      {} as never,
      {} as never,
      {} as never,
    );

    expect(result?.tokens).toBe(tokens);
    expect(setCookies).toHaveBeenCalledTimes(1);
  });
});
