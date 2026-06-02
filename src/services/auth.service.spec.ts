import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@mongez/reinforcements", () => ({
  Random: { string: vi.fn(() => "random-family-id") },
}));

const configKey = vi.fn();
const configGet = vi.fn();

vi.mock("@warlock.js/core", () => ({
  config: {
    key: (...args: unknown[]) => configKey(...args),
    get: (...args: unknown[]) => configGet(...args),
  },
  hashPassword: vi.fn(),
  verifyPassword: vi.fn(),
}));

const accessTokenCreate = vi.fn();
const accessTokenDelete = vi.fn();

vi.mock("../models/access-token", () => ({
  AccessToken: {
    create: (...args: unknown[]) => accessTokenCreate(...args),
    delete: (...args: unknown[]) => accessTokenDelete(...args),
  },
}));

const refreshTokenCreate = vi.fn();
const refreshTokenFirst = vi.fn();
const refreshTokenDelete = vi.fn();
const refreshTokenQuery = vi.fn();

vi.mock("../models/refresh-token", () => ({
  RefreshToken: {
    create: (...args: unknown[]) => refreshTokenCreate(...args),
    first: (...args: unknown[]) => refreshTokenFirst(...args),
    delete: (...args: unknown[]) => refreshTokenDelete(...args),
    query: (...args: unknown[]) => refreshTokenQuery(...args),
  },
}));

const jwtGenerate = vi.fn();
const jwtVerify = vi.fn();
const jwtGenerateRefreshToken = vi.fn();
const jwtVerifyRefreshToken = vi.fn();

vi.mock("./jwt", () => ({
  jwt: {
    generate: (...args: unknown[]) => jwtGenerate(...args),
    verify: (...args: unknown[]) => jwtVerify(...args),
    generateRefreshToken: (...args: unknown[]) => jwtGenerateRefreshToken(...args),
    verifyRefreshToken: (...args: unknown[]) => jwtVerifyRefreshToken(...args),
  },
}));

const emit = vi.fn();

vi.mock("./auth-events", () => ({
  authEvents: {
    emit: (...args: unknown[]) => emit(...args),
  },
}));

import { Random } from "@mongez/reinforcements";
import { hashPassword, verifyPassword } from "@warlock.js/core";
import { authService } from "./auth.service";

/**
 * Build a fake `Auth` user model good enough for the service, which only
 * ever reads `.id`, `.userType`, and `.string("password")`.
 */
function buildUser(overrides: Record<string, unknown> = {}) {
  return {
    id: 1,
    userType: "user",
    string: (key: string) => (key === "password" ? "stored-hash" : undefined),
    ...overrides,
  } as never;
}

/**
 * Build a fake persisted RefreshToken row. `revoke`/`markAsUsed`/`destroy`
 * are spies so call-order assertions work; `get` reads from `fields`.
 */
function buildRefreshTokenRow(fields: Record<string, unknown>, isValid = true) {
  return {
    isValid,
    get: (key: string) => fields[key],
    revoke: vi.fn().mockResolvedValue(undefined),
    markAsUsed: vi.fn().mockResolvedValue(undefined),
    destroy: vi.fn().mockResolvedValue(undefined),
  };
}

/**
 * Build a chainable query-builder stub. `.where`/`.orderBy` return the same
 * builder; `.get` resolves to the provided rows.
 */
function buildQuery(rows: unknown[]) {
  const builder: Record<string, unknown> = {};
  builder.where = vi.fn(() => builder);
  builder.orderBy = vi.fn(() => builder);
  builder.get = vi.fn().mockResolvedValue(rows);
  return builder;
}

beforeEach(() => {
  vi.clearAllMocks();

  // sensible config defaults; individual tests override via mockImplementation
  configKey.mockImplementation((_key: string, fallback?: unknown) => fallback);
  configGet.mockImplementation((_key: string, fallback?: unknown) => fallback);

  vi.mocked(Random.string).mockReturnValue("random-family-id");
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("authService.buildAccessTokenPayload", () => {
  it("returns the default access-token claim shape", () => {
    const user = buildUser({ id: 99, userType: "admin" });

    const payload = authService.buildAccessTokenPayload(user);

    expect(payload).toEqual({
      id: 99,
      userType: "admin",
      created_at: expect.any(Number),
    });
  });

  it("stamps created_at with the current time in milliseconds", () => {
    const before = Date.now();
    const payload = authService.buildAccessTokenPayload(buildUser());
    const after = Date.now();

    expect(payload.created_at).toBeGreaterThanOrEqual(before);
    expect(payload.created_at).toBeLessThanOrEqual(after);
  });
});

describe("authService password helpers", () => {
  it("delegates hashPassword to @warlock.js/core", async () => {
    vi.mocked(hashPassword).mockResolvedValue("hashed-value");

    const result = await authService.hashPassword("plaintext");

    expect(hashPassword).toHaveBeenCalledWith("plaintext");
    expect(result).toBe("hashed-value");
  });

  it("delegates verifyPassword in (plain, hash) order", async () => {
    vi.mocked(verifyPassword).mockResolvedValue(true);

    const result = await authService.verifyPassword("plain-input", "stored-hash");

    expect(verifyPassword).toHaveBeenCalledWith("plain-input", "stored-hash");
    expect(result).toBe(true);
  });
});

describe("authService.generateAccessToken", () => {
  beforeEach(() => {
    jwtGenerate.mockResolvedValue("signed-access-token");
    // exp is a UNIX timestamp in SECONDS
    jwtVerify.mockResolvedValue({ exp: 1_700_000_000 });
    accessTokenCreate.mockResolvedValue(undefined);
  });

  it("signs the built payload and persists an AccessToken row", async () => {
    const user = buildUser({ id: 7, userType: "user" });

    const result = await authService.generateAccessToken(user);

    // the default payload is the built claim shape
    expect(jwtGenerate).toHaveBeenCalledTimes(1);
    const [signedPayload] = jwtGenerate.mock.calls[0];
    expect(signedPayload).toMatchObject({ id: 7, userType: "user" });

    expect(accessTokenCreate).toHaveBeenCalledWith({
      token: "signed-access-token",
      user_id: 7,
      user_type: "user",
    });

    expect(result.token).toBe("signed-access-token");
    expect(result.expiresAt).toBe(new Date(1_700_000_000 * 1_000).toISOString());
  });

  it("uses the default 3600s expiry when auth.jwt.expiresIn is unset", async () => {
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.expiresIn" ? undefined : fallback,
    );

    await authService.generateAccessToken(buildUser());

    expect(jwtGenerate).toHaveBeenCalledWith(expect.any(Object), { expiresIn: 3_600 });
  });

  it("converts a configured expiresIn string through `ms`", async () => {
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.expiresIn" ? "2h" : fallback,
    );

    await authService.generateAccessToken(buildUser());

    // ms("2h") === 7_200_000
    expect(jwtGenerate).toHaveBeenCalledWith(expect.any(Object), { expiresIn: 7_200_000 });
  });

  it("honours an explicit payload override instead of the built claims", async () => {
    const custom = { id: 1, scope: "limited" };

    await authService.generateAccessToken(buildUser(), custom);

    expect(jwtGenerate).toHaveBeenCalledWith(custom, expect.any(Object));
  });
});

describe("authService.createRefreshToken", () => {
  beforeEach(() => {
    jwtGenerateRefreshToken.mockResolvedValue("signed-refresh-token");
    refreshTokenCreate.mockResolvedValue(buildRefreshTokenRow({ token: "signed-refresh-token" }));
    // no existing tokens => enforceMaxRefreshTokens is a no-op
    refreshTokenQuery.mockReturnValue(buildQuery([]));
  });

  it("returns undefined when refresh tokens are disabled", async () => {
    configGet.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.enabled" ? false : fallback,
    );

    const result = await authService.createRefreshToken(buildUser());

    expect(result).toBeUndefined();
    expect(jwtGenerateRefreshToken).not.toHaveBeenCalled();
    expect(refreshTokenCreate).not.toHaveBeenCalled();
  });

  it("generates a fresh familyId via Random.string when none supplied", async () => {
    await authService.createRefreshToken(buildUser({ id: 5, userType: "user" }));

    expect(Random.string).toHaveBeenCalledWith(32);

    const [payload] = jwtGenerateRefreshToken.mock.calls[0];
    expect(payload).toEqual({ userId: 5, userType: "user", familyId: "random-family-id" });
  });

  it("reuses the familyId from deviceInfo when provided (rotation continuity)", async () => {
    await authService.createRefreshToken(buildUser(), { familyId: "existing-family" });

    expect(Random.string).not.toHaveBeenCalled();
    const [payload] = jwtGenerateRefreshToken.mock.calls[0];
    expect(payload.familyId).toBe("existing-family");
  });

  it("persists the row with family_id, expires_at, and device_info", async () => {
    configGet.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.expiresIn" ? "7d" : fallback,
    );

    const deviceInfo = {
      familyId: "fam-9",
      userAgent: "jest-agent",
      ip: "10.0.0.1",
      deviceId: "device-xyz",
    };

    await authService.createRefreshToken(buildUser({ id: 3, userType: "user" }), deviceInfo);

    expect(refreshTokenCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        token: "signed-refresh-token",
        user_id: 3,
        user_type: "user",
        family_id: "fam-9",
        device_info: {
          userAgent: "jest-agent",
          ip: "10.0.0.1",
          deviceId: "device-xyz",
        },
      }),
    );

    const [[row]] = refreshTokenCreate.mock.calls;
    // expires_at is an ISO string roughly 7d out
    expect(typeof row.expires_at).toBe("string");
    expect(new Date(row.expires_at).getTime()).toBeGreaterThan(Date.now());
  });

  it("omits device_info when no deviceInfo is given", async () => {
    await authService.createRefreshToken(buildUser());

    const [[row]] = refreshTokenCreate.mock.calls;
    expect(row.device_info).toBeUndefined();
  });

  it("enforces the max-per-user cap by revoking the oldest active tokens", async () => {
    // maxPerUser default is 5; supply 5 existing active tokens -> revoke 1 oldest
    const rows = Array.from({ length: 5 }, (_value, index) =>
      buildRefreshTokenRow({ family_id: `fam-${index}` }),
    );
    refreshTokenQuery.mockReturnValue(buildQuery(rows));

    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.maxPerUser" ? 5 : fallback,
    );

    await authService.createRefreshToken(buildUser());

    // slice(0, length - max + 1) = slice(0, 1) -> only the oldest is revoked
    expect(rows[0].revoke).toHaveBeenCalledOnce();
    expect(rows[1].revoke).not.toHaveBeenCalled();
  });
});

describe("authService.createTokenPair", () => {
  beforeEach(() => {
    jwtGenerate.mockResolvedValue("signed-access-token");
    jwtVerify.mockResolvedValue({ exp: 1_700_000_000 });
    accessTokenCreate.mockResolvedValue(undefined);
    jwtGenerateRefreshToken.mockResolvedValue("signed-refresh-token");
    refreshTokenQuery.mockReturnValue(buildQuery([]));
  });

  it("returns both tokens and emits token.created + session.created", async () => {
    refreshTokenCreate.mockResolvedValue(
      buildRefreshTokenRow({ token: "signed-refresh-token", expires_at: "2099-01-01T00:00:00.000Z" }),
    );

    const user = buildUser();
    const pair = await authService.createTokenPair(user);

    expect(pair.accessToken.token).toBe("signed-access-token");
    expect(pair.refreshToken).toEqual({
      token: "signed-refresh-token",
      expiresAt: "2099-01-01T00:00:00.000Z",
    });

    expect(emit).toHaveBeenCalledWith("token.created", user, pair);
    expect(emit).toHaveBeenCalledWith("session.created", user, expect.anything(), undefined);
  });

  it("omits refreshToken and skips session.created when refresh is disabled", async () => {
    configGet.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.enabled" ? false : fallback,
    );

    const user = buildUser();
    const pair = await authService.createTokenPair(user);

    expect(pair.refreshToken).toBeUndefined();
    expect(emit).toHaveBeenCalledWith("token.created", user, pair);
    expect(emit).not.toHaveBeenCalledWith("session.created", expect.anything(), expect.anything(), expect.anything());
  });

  it("forwards deviceInfo.payload as the access-token claims", async () => {
    refreshTokenCreate.mockResolvedValue(buildRefreshTokenRow({ token: "signed-refresh-token" }));

    const customPayload = { id: 1, custom: "claim" };
    await authService.createTokenPair(buildUser(), { payload: customPayload });

    expect(jwtGenerate).toHaveBeenCalledWith(customPayload, expect.any(Object));
  });
});

describe("authService.refreshTokens", () => {
  beforeEach(() => {
    jwtGenerate.mockResolvedValue("signed-access-token");
    jwtVerify.mockResolvedValue({ exp: 1_700_000_000 });
    accessTokenCreate.mockResolvedValue(undefined);
    jwtGenerateRefreshToken.mockResolvedValue("new-refresh-token");
    refreshTokenCreate.mockResolvedValue(buildRefreshTokenRow({ token: "new-refresh-token" }));
  });

  it("returns null when the refresh JWT fails verification", async () => {
    jwtVerifyRefreshToken.mockRejectedValue(new Error("bad signature"));

    const result = await authService.refreshTokens("garbage");

    expect(result).toBeNull();
  });

  it("returns null and revokes the family when the stored token is already invalid (replay)", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });

    const usedRow = buildRefreshTokenRow({ family_id: "fam-1" }, false);
    refreshTokenFirst.mockResolvedValue(usedRow);

    // revokeTokenFamily queries the family and revokes each
    const familyRows = [buildRefreshTokenRow({}), buildRefreshTokenRow({})];
    refreshTokenQuery.mockReturnValue(buildQuery(familyRows));

    const result = await authService.refreshTokens("replayed-token");

    expect(result).toBeNull();
    expect(familyRows[0].revoke).toHaveBeenCalledOnce();
    expect(familyRows[1].revoke).toHaveBeenCalledOnce();
    expect(emit).toHaveBeenCalledWith("token.familyRevoked", "fam-1", familyRows);
  });

  it("returns null when the user type maps to no registered model", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "ghost", familyId: "fam-1" });
    refreshTokenFirst.mockResolvedValue(buildRefreshTokenRow({ family_id: "fam-1" }, true));

    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.userType.ghost" ? undefined : fallback,
    );

    const result = await authService.refreshTokens("valid-token");

    expect(result).toBeNull();
  });

  it("returns null when the user row no longer exists", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });
    refreshTokenFirst.mockResolvedValue(buildRefreshTokenRow({ family_id: "fam-1" }, true));

    const UserModel = { find: vi.fn().mockResolvedValue(null) };
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.userType.user" ? UserModel : fallback,
    );

    const result = await authService.refreshTokens("valid-token");

    expect(result).toBeNull();
  });

  it("rotates (revokes the old token) and issues a new pair when rotation is enabled", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });

    const oldRow = buildRefreshTokenRow({ family_id: "fam-1" }, true);
    refreshTokenFirst.mockResolvedValue(oldRow);
    refreshTokenCreate.mockResolvedValue(buildRefreshTokenRow({ token: "new-refresh-token" }));
    refreshTokenQuery.mockReturnValue(buildQuery([])); // enforceMaxRefreshTokens no-op

    const user = buildUser();
    const UserModel = { find: vi.fn().mockResolvedValue(user) };

    configKey.mockImplementation((key: string, fallback?: unknown) => {
      if (key === "auth.userType.user") return UserModel;
      if (key === "auth.jwt.refresh.rotation") return true;
      return fallback;
    });

    const result = await authService.refreshTokens("valid-token");

    expect(oldRow.revoke).toHaveBeenCalledOnce();
    expect(oldRow.markAsUsed).not.toHaveBeenCalled();
    expect(result).not.toBeNull();
    expect(result?.accessToken.token).toBe("signed-access-token");
    expect(emit).toHaveBeenCalledWith("token.refreshed", user, result, oldRow);
  });

  it("only marks the old token as used (no revoke) when rotation is disabled", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });

    const oldRow = buildRefreshTokenRow({ family_id: "fam-1" }, true);
    refreshTokenFirst.mockResolvedValue(oldRow);
    refreshTokenCreate.mockResolvedValue(buildRefreshTokenRow({ token: "new-refresh-token" }));
    refreshTokenQuery.mockReturnValue(buildQuery([]));

    const user = buildUser();
    const UserModel = { find: vi.fn().mockResolvedValue(user) };

    configKey.mockImplementation((key: string, fallback?: unknown) => {
      if (key === "auth.userType.user") return UserModel;
      if (key === "auth.jwt.refresh.rotation") return false;
      return fallback;
    });

    const result = await authService.refreshTokens("valid-token");

    expect(oldRow.markAsUsed).toHaveBeenCalledOnce();
    expect(oldRow.revoke).not.toHaveBeenCalled();
    expect(result).not.toBeNull();
  });

  it("reuses the same family_id for the rotated pair", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });

    const oldRow = buildRefreshTokenRow({ family_id: "fam-keep" }, true);
    refreshTokenFirst.mockResolvedValue(oldRow);
    refreshTokenCreate.mockResolvedValue(buildRefreshTokenRow({ token: "new-refresh-token" }));
    refreshTokenQuery.mockReturnValue(buildQuery([]));

    const user = buildUser();
    const UserModel = { find: vi.fn().mockResolvedValue(user) };
    configKey.mockImplementation((key: string, fallback?: unknown) => {
      if (key === "auth.userType.user") return UserModel;
      if (key === "auth.jwt.refresh.rotation") return true;
      return fallback;
    });

    await authService.refreshTokens("valid-token");

    // the newly-created refresh row keeps the old family_id, not a random one
    expect(refreshTokenCreate).toHaveBeenCalledWith(
      expect.objectContaining({ family_id: "fam-keep" }),
    );
    expect(Random.string).not.toHaveBeenCalled();
  });
});

describe("authService.attemptLogin", () => {
  it("emits login.attempt then returns null and emits login.failed when no user found", async () => {
    const Model = { first: vi.fn().mockResolvedValue(null) } as never;

    const result = await authService.attemptLogin(Model, {
      email: "a@b.c",
      password: "secret",
    });

    expect(result).toBeNull();
    expect(emit).toHaveBeenCalledWith("login.attempt", { email: "a@b.c" });
    expect(emit).toHaveBeenCalledWith("login.failed", { email: "a@b.c" }, "User not found");
  });

  it("strips the password from the lookup criteria", async () => {
    const first = vi.fn().mockResolvedValue(null);
    const Model = { first } as never;

    await authService.attemptLogin(Model, { email: "a@b.c", password: "secret" });

    expect(first).toHaveBeenCalledWith({ email: "a@b.c" });
  });

  it("returns null and emits login.failed when the password is wrong", async () => {
    const user = buildUser();
    const Model = { first: vi.fn().mockResolvedValue(user) } as never;
    vi.mocked(verifyPassword).mockResolvedValue(false);

    const result = await authService.attemptLogin(Model, { email: "a@b.c", password: "wrong" });

    expect(result).toBeNull();
    expect(emit).toHaveBeenCalledWith("login.failed", { email: "a@b.c" }, "Invalid password");
  });

  it("returns the user when credentials are valid", async () => {
    const user = buildUser();
    const Model = { first: vi.fn().mockResolvedValue(user) } as never;
    vi.mocked(verifyPassword).mockResolvedValue(true);

    const result = await authService.attemptLogin(Model, { email: "a@b.c", password: "right" });

    expect(result).toBe(user);
    expect(verifyPassword).toHaveBeenCalledWith("right", "stored-hash");
  });
});

describe("authService.login", () => {
  beforeEach(() => {
    jwtGenerate.mockResolvedValue("signed-access-token");
    jwtVerify.mockResolvedValue({ exp: 1_700_000_000 });
    accessTokenCreate.mockResolvedValue(undefined);
    jwtGenerateRefreshToken.mockResolvedValue("signed-refresh-token");
    refreshTokenCreate.mockResolvedValue(buildRefreshTokenRow({ token: "signed-refresh-token" }));
    refreshTokenQuery.mockReturnValue(buildQuery([]));
    vi.mocked(verifyPassword).mockResolvedValue(true);
  });

  it("returns null when credentials are invalid", async () => {
    const Model = { first: vi.fn().mockResolvedValue(null) } as never;

    const result = await authService.login(Model, { email: "a@b.c", password: "x" });

    expect(result).toBeNull();
  });

  it("returns access token only (no refresh) when refresh is disabled", async () => {
    const user = buildUser();
    const Model = { first: vi.fn().mockResolvedValue(user) } as never;

    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.enabled" ? false : fallback,
    );

    const result = await authService.login(Model, { email: "a@b.c", password: "x" });

    expect(result).not.toBeNull();
    expect(result?.user).toBe(user);
    expect(result?.tokens.accessToken.token).toBe("signed-access-token");
    expect(result?.tokens.refreshToken).toBeUndefined();
    expect(jwtGenerateRefreshToken).not.toHaveBeenCalled();
  });

  it("returns a full token pair and emits login.success when refresh is enabled", async () => {
    const user = buildUser();
    const Model = { first: vi.fn().mockResolvedValue(user) } as never;

    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.enabled" ? true : fallback,
    );

    const deviceInfo = { ip: "1.2.3.4" };
    const result = await authService.login(Model, { email: "a@b.c", password: "x" }, deviceInfo);

    expect(result?.tokens.accessToken.token).toBe("signed-access-token");
    expect(result?.tokens.refreshToken).toBeDefined();
    expect(emit).toHaveBeenCalledWith("login.success", user, result?.tokens, deviceInfo);
  });
});

describe("authService.logout", () => {
  it("removes the access token when one is supplied", async () => {
    const user = buildUser({ id: 8 });

    await authService.logout(user, "the-access-token");

    expect(accessTokenDelete).toHaveBeenCalledWith({
      token: "the-access-token",
      userId: 8,
    });
    expect(emit).toHaveBeenCalledWith("logout", user);
  });

  it("revokes the specific refresh token (scoped to the user) and emits session.destroyed", async () => {
    const row = buildRefreshTokenRow({});
    refreshTokenFirst.mockResolvedValue(row);

    const user = buildUser({ id: 8 });
    await authService.logout(user, undefined, "the-refresh-token");

    expect(refreshTokenFirst).toHaveBeenCalledWith({
      token: "the-refresh-token",
      userId: 8,
    });
    expect(row.revoke).toHaveBeenCalledOnce();
    expect(emit).toHaveBeenCalledWith("session.destroyed", user, row);
    expect(emit).toHaveBeenCalledWith("logout", user);
  });

  it("does not emit session.destroyed when the refresh token is not found", async () => {
    refreshTokenFirst.mockResolvedValue(null);

    const user = buildUser();
    await authService.logout(user, undefined, "missing-token");

    expect(emit).not.toHaveBeenCalledWith("session.destroyed", expect.anything(), expect.anything());
    expect(emit).toHaveBeenCalledWith("logout", user);
  });

  it("revokes all tokens (fail-safe) when no refresh token is given and behavior is revoke-all", async () => {
    refreshTokenQuery.mockReturnValue(buildQuery([])); // revokeAllTokens query
    accessTokenDelete.mockResolvedValue(undefined);

    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.logoutWithoutToken" ? "revoke-all" : fallback,
    );

    const user = buildUser();
    await authService.logout(user);

    expect(emit).toHaveBeenCalledWith("logout.failsafe", user);
    expect(emit).toHaveBeenCalledWith("logout.all", user);
    expect(emit).toHaveBeenCalledWith("logout", user);
  });

  it("throws when no refresh token is given and behavior is error", async () => {
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.logoutWithoutToken" ? "error" : fallback,
    );

    await expect(authService.logout(buildUser())).rejects.toThrow(
      "Refresh token required for logout",
    );
  });
});

describe("authService.revokeAllTokens", () => {
  it("revokes every active refresh token, deletes access tokens, and emits per-token + logout.all", async () => {
    const rows = [buildRefreshTokenRow({}), buildRefreshTokenRow({})];
    const query = buildQuery(rows);
    refreshTokenQuery.mockReturnValue(query);
    accessTokenDelete.mockResolvedValue(undefined);

    const user = buildUser({ id: 4, userType: "user" });
    await authService.revokeAllTokens(user);

    expect(rows[0].revoke).toHaveBeenCalledOnce();
    expect(rows[1].revoke).toHaveBeenCalledOnce();
    expect(emit).toHaveBeenCalledWith("token.revoked", user, rows[0]);
    expect(emit).toHaveBeenCalledWith("token.revoked", user, rows[1]);
    expect(accessTokenDelete).toHaveBeenCalledWith({ user_id: 4 });
    expect(emit).toHaveBeenCalledWith("logout.all", user);
  });

  it("filters by user_id, user_type, and unrevoked tokens", async () => {
    const query = buildQuery([]);
    refreshTokenQuery.mockReturnValue(query);

    const user = buildUser({ id: 4, userType: "admin" });
    await authService.revokeAllTokens(user);

    expect(query.where).toHaveBeenCalledWith("user_id", 4);
    expect(query.where).toHaveBeenCalledWith("user_type", "admin");
    expect(query.where).toHaveBeenCalledWith("revoked_at", null);
  });
});

describe("authService.revokeTokenFamily", () => {
  it("revokes each token in the family and emits token.familyRevoked", async () => {
    const rows = [buildRefreshTokenRow({}), buildRefreshTokenRow({})];
    const query = buildQuery(rows);
    refreshTokenQuery.mockReturnValue(query);

    await authService.revokeTokenFamily("fam-42");

    expect(query.where).toHaveBeenCalledWith("family_id", "fam-42");
    expect(query.where).toHaveBeenCalledWith("revoked_at", null);
    expect(rows[0].revoke).toHaveBeenCalledOnce();
    expect(rows[1].revoke).toHaveBeenCalledOnce();
    expect(emit).toHaveBeenCalledWith("token.familyRevoked", "fam-42", rows);
  });
});

describe("authService.cleanupExpiredTokens", () => {
  it("destroys each expired token, emits token.expired + cleanup.completed, and returns the count", async () => {
    const rows = [buildRefreshTokenRow({}), buildRefreshTokenRow({}), buildRefreshTokenRow({})];
    const query = buildQuery(rows);
    refreshTokenQuery.mockReturnValue(query);

    const count = await authService.cleanupExpiredTokens();

    expect(count).toBe(3);
    for (const row of rows) {
      expect(row.destroy).toHaveBeenCalledOnce();
      expect(emit).toHaveBeenCalledWith("token.expired", row);
    }
    expect(emit).toHaveBeenCalledWith("cleanup.completed", 3);
  });

  it("returns 0 and still emits cleanup.completed when nothing is expired", async () => {
    refreshTokenQuery.mockReturnValue(buildQuery([]));

    const count = await authService.cleanupExpiredTokens();

    expect(count).toBe(0);
    expect(emit).toHaveBeenCalledWith("cleanup.completed", 0);
  });
});

describe("authService.getActiveSessions", () => {
  it("returns active, unexpired sessions ordered by newest first", async () => {
    const rows = [buildRefreshTokenRow({}), buildRefreshTokenRow({})];
    const query = buildQuery(rows);
    refreshTokenQuery.mockReturnValue(query);

    const user = buildUser({ id: 2, userType: "user" });
    const sessions = await authService.getActiveSessions(user);

    expect(sessions).toBe(rows);
    expect(query.where).toHaveBeenCalledWith({
      user_id: 2,
      user_type: "user",
      revoked_at: null,
    });
    expect(query.orderBy).toHaveBeenCalledWith("created_at", "desc");
  });
});

describe("authService token removal helpers", () => {
  it("removeAccessToken deletes by token + userId", async () => {
    await authService.removeAccessToken(buildUser({ id: 11 }), "tok");

    expect(accessTokenDelete).toHaveBeenCalledWith({ token: "tok", userId: 11 });
  });

  it("removeAllAccessTokens deletes by user_id", async () => {
    await authService.removeAllAccessTokens(buildUser({ id: 11 }));

    expect(accessTokenDelete).toHaveBeenCalledWith({ user_id: 11 });
  });

  it("removeRefreshToken deletes by token + userId", async () => {
    await authService.removeRefreshToken(buildUser({ id: 11 }), "rtok");

    expect(refreshTokenDelete).toHaveBeenCalledWith({ token: "rtok", userId: 11 });
  });
});
