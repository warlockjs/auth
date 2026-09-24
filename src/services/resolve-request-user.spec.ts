import { beforeEach, describe, expect, it, vi } from "vitest";

const configKey = vi.fn();
const jwtVerify = vi.fn();
const accessTokenFindByToken = vi.fn();
const renewAutomaticSession = vi.fn();
const setAuthCookie = vi.fn();
const canAuthenticate = vi.fn();

vi.mock("@warlock.js/core", () => ({
  config: { key: (...args: unknown[]) => configKey(...args) },
}));

vi.mock("@warlock.js/logger", () => ({
  log: { error: vi.fn() },
}));

vi.mock("./jwt", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./jwt")>();

  return {
    ...actual,
    jwt: { ...actual.jwt, verify: (...args: unknown[]) => jwtVerify(...args) },
  };
});

vi.mock("../models/access-token", () => ({
  AccessToken: { findByToken: (...args: unknown[]) => accessTokenFindByToken(...args) },
}));

vi.mock("./auth.service", () => ({
  authService: {
    canAuthenticate: (...args: unknown[]) => canAuthenticate(...args),
    renewAutomaticSession: (...args: unknown[]) => renewAutomaticSession(...args),
    setAuthCookie: (...args: unknown[]) => setAuthCookie(...args),
  },
}));

import { resolveRequestUser, resolveRequestUserOutcome } from "./resolve-request-user";

const user = { id: 1, userType: "user" };

function buildRequest(authorizationValue?: string, cookies: Record<string, string> = {}) {
  return {
    authorizationValue,
    cookie: vi.fn((name: string) => cookies[name]),
    locals: { user: "stale" as unknown },
    decodedAccessToken: undefined as unknown,
  };
}

function liveRow(fields: Record<string, unknown> = {}) {
  return { isExpired: false, userType: "user", destroy: vi.fn(), ...fields };
}

function stubConfig(userModel: unknown) {
  configKey.mockImplementation((key: string, fallback?: unknown) =>
    key.startsWith("auth.userType.") ? userModel : fallback,
  );
}

const run = (request: unknown, options?: Parameters<typeof resolveRequestUser>[2]) =>
  resolveRequestUser(request as never, {} as never, options);

beforeEach(() => {
  vi.clearAllMocks();
  canAuthenticate.mockResolvedValue(true);
  renewAutomaticSession.mockResolvedValue(null);
});

describe("resolveRequestUser", () => {
  it("returns the user for a live token and records the decoded claims", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow());
    stubConfig({ find: vi.fn().mockResolvedValue(user) });
    const request = buildRequest("token");

    expect(await run(request)).toBe(user);
    expect(request.decodedAccessToken).toEqual({ id: 1, userType: "user" });
  });

  it("returns null and clears locals.user when there is no credential", async () => {
    const request = buildRequest(undefined);

    expect(await run(request)).toBeNull();
    expect(request.locals.user).toBeUndefined();
    expect(jwtVerify).not.toHaveBeenCalled();
  });

  it("returns null for a token row the model reports expired, and destroys it", async () => {
    const row = liveRow({ isExpired: true });
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(row);

    expect(await run(buildRequest("token"))).toBeNull();
    expect(row.destroy).toHaveBeenCalled();
  });

  it("reports a disallowed user type as forbidden", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow());

    const outcome = await resolveRequestUserOutcome(
      buildRequest("token") as never,
      {} as never,
      { allowedTypes: ["admin"] },
    );

    expect(outcome).toEqual({ user: null, failure: "forbidden" });
  });

  it("reports a user that cannot authenticate as unauthorized", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow());
    stubConfig({ find: vi.fn().mockResolvedValue(user) });
    canAuthenticate.mockResolvedValue(false);

    const outcome = await resolveRequestUserOutcome(buildRequest("token") as never, {} as never);

    expect(outcome).toEqual({ user: null, failure: "unauthorized" });
  });

  it("renews once from the refresh cookie and writes the rotated pair", async () => {
    jwtVerify.mockResolvedValue({ id: 1, userType: "user" });
    accessTokenFindByToken.mockResolvedValue(liveRow());
    stubConfig({ find: vi.fn().mockResolvedValue(user) });
    renewAutomaticSession.mockResolvedValue({
      accessToken: { token: "next-access" },
      refreshToken: { token: "next-refresh" },
    });
    const request = buildRequest(undefined, { refresh: "old-refresh" });
    const response = {};

    const resolved = await resolveRequestUser(request as never, response as never, {
      tokenFrom: "cookie:access",
      refreshCredential: "cookie:refresh",
      overlapMs: 4_000,
      allowedTypes: ["user"],
      renewalUserType: "user",
    });

    expect(resolved).toBe(user);
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
  });
});
