import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ── access-token model ──────────────────────────────────────────────────────
const accessTokenIssue = vi.fn();
const accessTokenDeleteForUser = vi.fn();
const accessTokenDeleteAllForUser = vi.fn();
const accessTokenPurgeExpired = vi.fn();
const accessTokenFindNeverExpiring = vi.fn();
const accessTokenPurgeNeverExpiring = vi.fn();

vi.mock("../models/access-token", () => ({
  AccessToken: {
    issue: (...args: unknown[]) => accessTokenIssue(...args),
    deleteForUser: (...args: unknown[]) => accessTokenDeleteForUser(...args),
    deleteAllForUser: (...args: unknown[]) => accessTokenDeleteAllForUser(...args),
    purgeExpired: (...args: unknown[]) => accessTokenPurgeExpired(...args),
    findNeverExpiring: (...args: unknown[]) => accessTokenFindNeverExpiring(...args),
    purgeNeverExpiring: (...args: unknown[]) => accessTokenPurgeNeverExpiring(...args),
  },
}));

// ── refresh-token model ─────────────────────────────────────────────────────
const refreshTokenIssue = vi.fn();
const refreshTokenEnforceMax = vi.fn();
const refreshTokenFindByToken = vi.fn();
const refreshTokenFindForUser = vi.fn();
const refreshTokenDeleteForUser = vi.fn();
const refreshTokenRevokeAllFor = vi.fn();
const refreshTokenRevokeFamily = vi.fn();
const refreshTokenPurgeExpired = vi.fn();
const refreshTokenActiveFor = vi.fn();
const refreshTokenFindNeverExpiring = vi.fn();
const refreshTokenPurgeNeverExpiring = vi.fn();

vi.mock("../models/refresh-token", () => ({
  RefreshToken: {
    issue: (...args: unknown[]) => refreshTokenIssue(...args),
    enforceMax: (...args: unknown[]) => refreshTokenEnforceMax(...args),
    findByToken: (...args: unknown[]) => refreshTokenFindByToken(...args),
    findForUser: (...args: unknown[]) => refreshTokenFindForUser(...args),
    deleteForUser: (...args: unknown[]) => refreshTokenDeleteForUser(...args),
    revokeAllFor: (...args: unknown[]) => refreshTokenRevokeAllFor(...args),
    revokeFamily: (...args: unknown[]) => refreshTokenRevokeFamily(...args),
    purgeExpired: (...args: unknown[]) => refreshTokenPurgeExpired(...args),
    activeFor: (...args: unknown[]) => refreshTokenActiveFor(...args),
    findNeverExpiring: (...args: unknown[]) => refreshTokenFindNeverExpiring(...args),
    purgeNeverExpiring: (...args: unknown[]) => refreshTokenPurgeNeverExpiring(...args),
  },
}));

// ── jwt service ─────────────────────────────────────────────────────────────
const jwtGenerate = vi.fn();
const jwtGenerateRefreshToken = vi.fn();
const jwtVerifyRefreshToken = vi.fn();

vi.mock("./jwt", () => ({
  jwt: {
    generate: (...args: unknown[]) => jwtGenerate(...args),
    generateRefreshToken: (...args: unknown[]) => jwtGenerateRefreshToken(...args),
    verifyRefreshToken: (...args: unknown[]) => jwtVerifyRefreshToken(...args),
  },
}));

// ── events ──────────────────────────────────────────────────────────────────
const emit = vi.fn();

vi.mock("./auth-events", () => ({
  authEvents: { emit: (...args: unknown[]) => emit(...args) },
}));

// ── core ────────────────────────────────────────────────────────────────────
const configKey = vi.fn();
const configGet = vi.fn();
const hashPassword = vi.fn();
const verifyPassword = vi.fn();

vi.mock("@warlock.js/core", () => ({
  config: {
    key: (...args: unknown[]) => configKey(...args),
    get: (...args: unknown[]) => configGet(...args),
  },
  hashPassword: (...args: unknown[]) => hashPassword(...args),
  verifyPassword: (...args: unknown[]) => verifyPassword(...args),
}));

vi.mock("@warlock.js/logger", () => ({
  log: { warn: vi.fn(), error: vi.fn() },
}));

const randomString = vi.fn();

vi.mock("@mongez/reinforcements", () => ({
  Random: { string: (...args: unknown[]) => randomString(...args) },
}));

import { NO_EXPIRATION } from "../contracts/types";
import { authService } from "./auth.service";

function buildUser(overrides: Record<string, unknown> = {}) {
  const fields: Record<string, unknown> = {
    id: 1,
    userType: "user",
    password: "hashed-password",
    ...overrides,
  };

  return {
    id: fields.id,
    userType: fields.userType,
    string: (key: string) => fields[key],
    get: (key: string) => fields[key],
  } as never;
}

function buildRefreshTokenRow(fields: Record<string, unknown>, isValid = true) {
  return {
    id: (fields.id as string) ?? "rt-id",
    isValid,
    familyId: (fields.family_id as string) ?? "fam-id",
    get: (key: string) => fields[key],
    revoke: vi.fn().mockResolvedValue(undefined),
    markAsUsed: vi.fn().mockResolvedValue(undefined),
    revokeIfActive: vi.fn().mockResolvedValue(true),
  };
}

beforeEach(() => {
  vi.clearAllMocks();

  // model statics resolve to the (mocked) default class via config fallback
  configKey.mockImplementation((_key: string, fallback?: unknown) => fallback);
  configGet.mockImplementation((_key: string, fallback?: unknown) => fallback);

  randomString.mockReturnValue("random-family-id");
  jwtGenerate.mockResolvedValue("signed-access-token");
  jwtGenerateRefreshToken.mockResolvedValue("signed-refresh-token");
  refreshTokenIssue.mockResolvedValue(buildRefreshTokenRow({ token: "signed-refresh-token" }));
  refreshTokenEnforceMax.mockResolvedValue(undefined);

  // bulk operations resolve to an empty set by default so the per-token event
  // loops have something iterable
  refreshTokenRevokeAllFor.mockResolvedValue([]);
  refreshTokenRevokeFamily.mockResolvedValue([]);
  refreshTokenPurgeExpired.mockResolvedValue([]);
  refreshTokenActiveFor.mockResolvedValue([]);
  accessTokenPurgeExpired.mockResolvedValue(0);
  accessTokenFindNeverExpiring.mockResolvedValue([]);
  accessTokenPurgeNeverExpiring.mockResolvedValue([]);
  refreshTokenFindNeverExpiring.mockResolvedValue([]);
  refreshTokenPurgeNeverExpiring.mockResolvedValue([]);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("authService.buildAccessTokenPayload", () => {
  it("includes id, userType, and a created_at timestamp", () => {
    const payload = authService.buildAccessTokenPayload(buildUser({ id: 7 }));

    expect(payload.id).toBe(7);
    expect(payload.userType).toBe("user");
    expect(typeof payload.created_at).toBe("number");
  });
});

describe("authService.generateAccessToken", () => {
  it("signs, persists via AccessToken.issue, and returns the token + expiry", async () => {
    const user = buildUser({ id: 7 });

    const result = await authService.generateAccessToken(user);

    expect(jwtGenerate).toHaveBeenCalledWith(
      expect.objectContaining({ id: 7, userType: "user" }),
      { expiresIn: 3_600_000 }, // ms("1h") default
    );
    expect(accessTokenIssue).toHaveBeenCalledWith(user, "signed-access-token", expect.any(Date));
    expect(result.token).toBe("signed-access-token");
    expect(typeof result.expiresAt).toBe("string");
    expect(new Date(result.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });

  it("does NOT re-verify the freshly-signed token (expiry computed locally)", async () => {
    await authService.generateAccessToken(buildUser());

    // generate is the only jwt call — no redundant verify round-trip
    expect(jwtGenerate).toHaveBeenCalledOnce();
  });

  it("converts a configured expiresIn string through `ms`", async () => {
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.expiresIn" ? "2h" : fallback,
    );

    await authService.generateAccessToken(buildUser());

    expect(jwtGenerate).toHaveBeenCalledWith(expect.any(Object), { expiresIn: 7_200_000 });
  });

  it("honours an explicit payload override", async () => {
    const custom = { id: 1, scope: "limited" };

    await authService.generateAccessToken(buildUser(), custom);

    expect(jwtGenerate).toHaveBeenCalledWith(custom, expect.any(Object));
  });
});

/**
 * A token lifetime is a security boundary: an `expiresIn` the `ms` package
 * cannot turn into a positive number of milliseconds must fail loudly, because
 * every quiet outcome is a wrong credential — `undefined` reaches the signer as
 * a token with NO `exp` claim, and `0` mints one that is already expired.
 */
describe("authService expiresIn validation", () => {
  function withConfig(key: string, value: unknown) {
    configKey.mockImplementation((configuredKey: string, fallback?: unknown) =>
      configuredKey === key ? value : fallback,
    );
  }

  describe("access token", () => {
    it("throws naming the config key when expiresIn is unparseable", async () => {
      withConfig("auth.accessToken.expiresIn", "30dayz");

      await expect(authService.generateAccessToken(buildUser())).rejects.toThrow(
        /auth\.accessToken\.expiresIn/,
      );

      // nothing is signed and nothing is persisted with a broken lifetime
      expect(jwtGenerate).not.toHaveBeenCalled();
      expect(accessTokenIssue).not.toHaveBeenCalled();
    });

    it("throws for an unparseable value that reads like prose", async () => {
      withConfig("auth.accessToken.expiresIn", "thirty days");

      await expect(authService.generateAccessToken(buildUser())).rejects.toThrow(
        /auth\.accessToken\.expiresIn/,
      );
    });

    it("throws for a value that parses to zero (`0d`)", async () => {
      // "0d" is truthy AND parses cleanly to 0 — it survives any guard that only
      // rejects undefined/NaN, and would mint an already-expired token.
      withConfig("auth.accessToken.expiresIn", "0d");

      await expect(authService.generateAccessToken(buildUser())).rejects.toThrow(
        /auth\.accessToken\.expiresIn/,
      );
      expect(jwtGenerate).not.toHaveBeenCalled();
    });

    it("throws for a negative duration", async () => {
      withConfig("auth.accessToken.expiresIn", "-1h");

      await expect(authService.generateAccessToken(buildUser())).rejects.toThrow(
        /auth\.accessToken\.expiresIn/,
      );
    });

    it("throws for a bare number (ms formats it instead of parsing it)", async () => {
      withConfig("auth.accessToken.expiresIn", 2_592_000);

      await expect(authService.generateAccessToken(buildUser())).rejects.toThrow(
        /auth\.accessToken\.expiresIn/,
      );
    });

    it("accepts a valid spaced duration", async () => {
      withConfig("auth.accessToken.expiresIn", "30 days");

      await authService.generateAccessToken(buildUser());

      expect(jwtGenerate).toHaveBeenCalledWith(expect.any(Object), { expiresIn: 2_592_000_000 });
    });

    it("accepts NO_EXPIRATION (100y) unchanged", async () => {
      withConfig("auth.accessToken.expiresIn", NO_EXPIRATION);

      await authService.generateAccessToken(buildUser());

      expect(jwtGenerate).toHaveBeenCalledWith(expect.any(Object), {
        expiresIn: 3_155_760_000_000,
      });
    });

    it("defaults to 1h when expiresIn is absent", async () => {
      // auth-config declares accessToken.expiresIn as `string | undefined` with
      // no default of its own, so this path is real.
      configKey.mockImplementation((_key: string, fallback?: unknown) => fallback);

      await authService.generateAccessToken(buildUser());

      expect(jwtGenerate).toHaveBeenCalledWith(expect.any(Object), { expiresIn: 3_600_000 });
    });

    it("never hands a non-positive or non-finite expiresIn to the signer", async () => {
      withConfig("auth.accessToken.expiresIn", "1h");

      await authService.generateAccessToken(buildUser());

      const { expiresIn } = jwtGenerate.mock.calls[0][1] as { expiresIn: unknown };

      expect(typeof expiresIn).toBe("number");
      expect(Number.isFinite(expiresIn as number)).toBe(true);
      expect(expiresIn as number).toBeGreaterThan(0);
    });
  });

  describe("refresh token", () => {
    it("throws naming the config key when expiresIn is unparseable", async () => {
      withConfig("auth.refreshToken.expiresIn", "30dayz");

      await expect(authService.createRefreshToken(buildUser())).rejects.toThrow(
        /auth\.refreshToken\.expiresIn/,
      );

      // validation happens before any side effect — no cap enforcement, no issue
      expect(refreshTokenEnforceMax).not.toHaveBeenCalled();
      expect(jwtGenerateRefreshToken).not.toHaveBeenCalled();
      expect(refreshTokenIssue).not.toHaveBeenCalled();
    });

    it("throws for a value that parses to zero (`0d`)", async () => {
      withConfig("auth.refreshToken.expiresIn", "0d");

      await expect(authService.createRefreshToken(buildUser())).rejects.toThrow(
        /auth\.refreshToken\.expiresIn/,
      );
      expect(refreshTokenIssue).not.toHaveBeenCalled();
    });

    it("keeps the documented 7d default working", async () => {
      configKey.mockImplementation((_key: string, fallback?: unknown) => fallback);

      await authService.createRefreshToken(buildUser());

      expect(jwtGenerateRefreshToken).toHaveBeenCalledWith(expect.any(Object), {
        expiresIn: 604_800_000,
      });
    });

    it("accepts a valid configured duration and persists a real expiry", async () => {
      withConfig("auth.refreshToken.expiresIn", "30 days");

      await authService.createRefreshToken(buildUser());

      expect(jwtGenerateRefreshToken).toHaveBeenCalledWith(expect.any(Object), {
        expiresIn: 2_592_000_000,
      });

      const { expiresAt } = refreshTokenIssue.mock.calls[0][2] as { expiresAt: string };

      expect(Number.isNaN(new Date(expiresAt).getTime())).toBe(false);
    });
  });
});

describe("authService.createRefreshToken", () => {
  it("returns undefined when refresh tokens are disabled", async () => {
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.enabled" ? false : fallback,
    );

    const result = await authService.createRefreshToken(buildUser());

    expect(result).toBeUndefined();
    expect(refreshTokenIssue).not.toHaveBeenCalled();
  });

  it("enforces the per-user cap before issuing", async () => {
    const user = buildUser({ id: 5 });

    await authService.createRefreshToken(user);

    expect(refreshTokenEnforceMax).toHaveBeenCalledWith(user, 5);
    expect(refreshTokenIssue).toHaveBeenCalledWith(
      user,
      "signed-refresh-token",
      expect.objectContaining({ familyId: "random-family-id" }),
    );
  });

  it("reuses a supplied familyId instead of generating one", async () => {
    await authService.createRefreshToken(buildUser(), { familyId: "fam-keep" });

    expect(randomString).not.toHaveBeenCalled();
    expect(refreshTokenIssue).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ familyId: "fam-keep" }),
    );
  });

  it("forwards deviceInfo to the issued token", async () => {
    const deviceInfo = { ip: "127.0.0.1", userAgent: "test" };

    await authService.createRefreshToken(buildUser(), deviceInfo);

    expect(refreshTokenIssue).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ deviceInfo }),
    );
  });
});

describe("authService.createTokenPair", () => {
  it("issues both tokens and emits token.created + session.created", async () => {
    const user = buildUser();

    const pair = await authService.createTokenPair(user);

    expect(pair.accessToken.token).toBe("signed-access-token");
    expect(pair.refreshToken?.token).toBe("signed-refresh-token");
    expect(emit).toHaveBeenCalledWith("token.created", user, pair);
    expect(emit).toHaveBeenCalledWith("session.created", user, expect.anything(), undefined);
  });

  it("omits the refresh token (and session event) when refresh is disabled", async () => {
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.enabled" ? false : fallback,
    );

    const pair = await authService.createTokenPair(buildUser());

    expect(pair.refreshToken).toBeUndefined();
    expect(emit).not.toHaveBeenCalledWith("session.created", expect.anything(), expect.anything(), undefined);
  });
});

describe("authService.refreshTokens", () => {
  function configureRotation(rotation: boolean, user: unknown) {
    const UserModel = { find: vi.fn().mockResolvedValue(user) };

    configKey.mockImplementation((key: string, fallback?: unknown) => {
      if (key === "auth.userType.user") return UserModel;
      if (key === "auth.jwt.refresh.rotation") return rotation;
      return fallback;
    });

    return UserModel;
  }

  it("returns null on an invalid JWT", async () => {
    jwtVerifyRefreshToken.mockResolvedValue(null);

    expect(await authService.refreshTokens("bad")).toBeNull();
  });

  it("revokes the family and returns null when the stored token is already invalid (replay)", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });
    refreshTokenFindByToken.mockResolvedValue(buildRefreshTokenRow({ family_id: "fam-1" }, false));
    refreshTokenRevokeFamily.mockResolvedValue([]);

    const result = await authService.refreshTokens("valid");

    expect(result).toBeNull();
    expect(refreshTokenRevokeFamily).toHaveBeenCalledWith("fam-1");
  });

  it("rotates via revokeIfActive and issues a new pair when rotation is enabled", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });
    const oldRow = buildRefreshTokenRow({ family_id: "fam-1" }, true);
    refreshTokenFindByToken.mockResolvedValue(oldRow);
    const user = buildUser();
    configureRotation(true, user);

    const result = await authService.refreshTokens("valid");

    expect(oldRow.revokeIfActive).toHaveBeenCalledOnce();
    expect(oldRow.markAsUsed).not.toHaveBeenCalled();
    expect(result?.accessToken.token).toBe("signed-access-token");
    expect(emit).toHaveBeenCalledWith("token.refreshed", user, result, oldRow);
  });

  it("rejects and revokes the family when revokeIfActive loses the race", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });
    const oldRow = buildRefreshTokenRow({ family_id: "fam-1" }, true);
    oldRow.revokeIfActive.mockResolvedValue(false); // concurrent rotation already won
    refreshTokenFindByToken.mockResolvedValue(oldRow);
    refreshTokenRevokeFamily.mockResolvedValue([]);
    configureRotation(true, buildUser());

    const result = await authService.refreshTokens("valid");

    expect(result).toBeNull();
    expect(refreshTokenRevokeFamily).toHaveBeenCalledWith("fam-1");
    expect(refreshTokenIssue).not.toHaveBeenCalled();
  });

  it("only marks the token as used (no revoke) when rotation is disabled", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });
    const oldRow = buildRefreshTokenRow({ family_id: "fam-1" }, true);
    refreshTokenFindByToken.mockResolvedValue(oldRow);
    configureRotation(false, buildUser());

    await authService.refreshTokens("valid");

    expect(oldRow.markAsUsed).toHaveBeenCalledOnce();
    expect(oldRow.revokeIfActive).not.toHaveBeenCalled();
  });

  it("returns null when the user type maps to no model", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "ghost", familyId: "fam" });
    refreshTokenFindByToken.mockResolvedValue(buildRefreshTokenRow({ family_id: "fam" }, true));

    expect(await authService.refreshTokens("valid")).toBeNull();
  });

  it("keeps the same family_id on the rotated pair", async () => {
    jwtVerifyRefreshToken.mockResolvedValue({ userId: 1, userType: "user", familyId: "fam-1" });
    refreshTokenFindByToken.mockResolvedValue(buildRefreshTokenRow({ family_id: "fam-keep" }, true));
    configureRotation(true, buildUser());

    await authService.refreshTokens("valid");

    expect(refreshTokenIssue).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ familyId: "fam-keep" }),
    );
  });
});

describe("authService.attemptLogin", () => {
  it("returns null and emits login.failed when no user is found", async () => {
    const Model = { first: vi.fn().mockResolvedValue(null) } as never;

    const result = await authService.attemptLogin(Model, { email: "a@b.c", password: "x" });

    expect(result).toBeNull();
    expect(emit).toHaveBeenCalledWith("login.attempt", { email: "a@b.c" });
    expect(emit).toHaveBeenCalledWith("login.failed", { email: "a@b.c" }, "User not found");
  });

  it("returns null and emits login.failed on a wrong password", async () => {
    const Model = { first: vi.fn().mockResolvedValue(buildUser()) } as never;
    verifyPassword.mockResolvedValue(false);

    const result = await authService.attemptLogin(Model, { email: "a@b.c", password: "x" });

    expect(result).toBeNull();
    expect(emit).toHaveBeenCalledWith("login.failed", { email: "a@b.c" }, "Invalid password");
  });

  it("returns the user on a correct password", async () => {
    const user = buildUser();
    const Model = { first: vi.fn().mockResolvedValue(user) } as never;
    verifyPassword.mockResolvedValue(true);

    expect(await authService.attemptLogin(Model, { email: "a@b.c", password: "x" })).toBe(user);
  });
});

describe("authService.login", () => {
  it("returns null on invalid credentials", async () => {
    const Model = { first: vi.fn().mockResolvedValue(null) } as never;

    expect(await authService.login(Model, { email: "a@b.c", password: "x" })).toBeNull();
  });

  it("returns access-only tokens when refresh is disabled", async () => {
    const Model = { first: vi.fn().mockResolvedValue(buildUser()) } as never;
    verifyPassword.mockResolvedValue(true);
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.enabled" ? false : fallback,
    );

    const result = await authService.login(Model, { email: "a@b.c", password: "x" });

    expect(result?.tokens.accessToken.token).toBe("signed-access-token");
    expect(result?.tokens.refreshToken).toBeUndefined();
  });

  it("returns a full pair and emits login.success", async () => {
    const user = buildUser();
    const Model = { first: vi.fn().mockResolvedValue(user) } as never;
    verifyPassword.mockResolvedValue(true);

    const result = await authService.login(Model, { email: "a@b.c", password: "x" });

    expect(result?.tokens.refreshToken?.token).toBe("signed-refresh-token");
    expect(emit).toHaveBeenCalledWith("login.success", user, result?.tokens, undefined);
  });
});

describe("authService.logout", () => {
  it("removes the access token when supplied", async () => {
    const user = buildUser({ id: 8 });

    await authService.logout(user, "the-access-token");

    expect(accessTokenDeleteForUser).toHaveBeenCalledWith(user, "the-access-token");
    expect(emit).toHaveBeenCalledWith("logout", user);
  });

  it("revokes a specific refresh token scoped to the user and emits session.destroyed", async () => {
    const row = buildRefreshTokenRow({});
    refreshTokenFindForUser.mockResolvedValue(row);
    const user = buildUser({ id: 8 });

    await authService.logout(user, undefined, "the-refresh-token");

    expect(refreshTokenFindForUser).toHaveBeenCalledWith(user, "the-refresh-token");
    expect(row.revoke).toHaveBeenCalledOnce();
    expect(emit).toHaveBeenCalledWith("session.destroyed", user, row);
  });

  it("does not emit session.destroyed when the refresh token is not found", async () => {
    refreshTokenFindForUser.mockResolvedValue(null);

    await authService.logout(buildUser(), undefined, "missing");

    expect(emit).not.toHaveBeenCalledWith("session.destroyed", expect.anything(), expect.anything());
  });

  it("revokes all tokens (fail-safe) when no refresh token is given", async () => {
    refreshTokenRevokeAllFor.mockResolvedValue([]);
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.logoutWithoutToken" ? "revoke-all" : fallback,
    );

    const user = buildUser();
    await authService.logout(user);

    expect(refreshTokenRevokeAllFor).toHaveBeenCalledWith(user);
    expect(emit).toHaveBeenCalledWith("logout.failsafe", user);
  });

  it("throws when logoutWithoutToken is 'error' and no refresh token is given", async () => {
    configKey.mockImplementation((key: string, fallback?: unknown) =>
      key === "auth.jwt.refresh.logoutWithoutToken" ? "error" : fallback,
    );

    await expect(authService.logout(buildUser())).rejects.toThrow("Refresh token required");
  });
});

describe("authService token removal helpers", () => {
  it("removeAccessToken delegates to AccessToken.deleteForUser", async () => {
    const user = buildUser({ id: 11 });

    await authService.removeAccessToken(user, "tok");

    expect(accessTokenDeleteForUser).toHaveBeenCalledWith(user, "tok");
  });

  it("removeAllAccessTokens delegates to AccessToken.deleteAllForUser", async () => {
    const user = buildUser({ id: 11 });

    await authService.removeAllAccessTokens(user);

    expect(accessTokenDeleteAllForUser).toHaveBeenCalledWith(user);
  });

  it("removeRefreshToken delegates to RefreshToken.deleteForUser", async () => {
    const user = buildUser({ id: 11 });

    await authService.removeRefreshToken(user, "rtok");

    expect(refreshTokenDeleteForUser).toHaveBeenCalledWith(user, "rtok");
  });
});

describe("authService.revokeAllTokens", () => {
  it("bulk-revokes refresh tokens, emits per-token + logout.all, and clears access tokens", async () => {
    const rows = [buildRefreshTokenRow({ id: "a" }), buildRefreshTokenRow({ id: "b" })];
    refreshTokenRevokeAllFor.mockResolvedValue(rows);
    const user = buildUser();

    await authService.revokeAllTokens(user);

    expect(refreshTokenRevokeAllFor).toHaveBeenCalledWith(user);
    expect(emit).toHaveBeenCalledWith("token.revoked", user, rows[0]);
    expect(emit).toHaveBeenCalledWith("token.revoked", user, rows[1]);
    expect(accessTokenDeleteAllForUser).toHaveBeenCalledWith(user);
    expect(emit).toHaveBeenCalledWith("logout.all", user);
  });
});

describe("authService.revokeTokenFamily", () => {
  it("bulk-revokes the family and emits token.familyRevoked", async () => {
    const rows = [buildRefreshTokenRow({ id: "a" })];
    refreshTokenRevokeFamily.mockResolvedValue(rows);

    await authService.revokeTokenFamily("fam-42");

    expect(refreshTokenRevokeFamily).toHaveBeenCalledWith("fam-42");
    expect(emit).toHaveBeenCalledWith("token.familyRevoked", "fam-42", rows);
  });
});

describe("authService.cleanupExpiredTokens", () => {
  it("purges refresh + access tokens, emits per-token + cleanup.completed, returns the refresh count", async () => {
    const rows = [buildRefreshTokenRow({ id: "a" }), buildRefreshTokenRow({ id: "b" })];
    refreshTokenPurgeExpired.mockResolvedValue(rows);
    accessTokenPurgeExpired.mockResolvedValue(3);

    const count = await authService.cleanupExpiredTokens();

    expect(count).toBe(2);
    expect(emit).toHaveBeenCalledWith("token.expired", rows[0]);
    expect(accessTokenPurgeExpired).toHaveBeenCalledOnce();
    expect(emit).toHaveBeenCalledWith("cleanup.completed", 2);
  });
});

/**
 * #27 remediation. These rows are invisible to `cleanupExpiredTokens`: its
 * predicate is `expires_at < now`, which an `Invalid Date` never satisfies.
 */
describe("authService never-expiring token remediation", () => {
  it("reports access and refresh rows from both models", async () => {
    const accessRow = { id: "at-1" };
    const refreshRow = buildRefreshTokenRow({ id: "rt-1" });
    accessTokenFindNeverExpiring.mockResolvedValue([accessRow]);
    refreshTokenFindNeverExpiring.mockResolvedValue([refreshRow]);

    const found = await authService.findNeverExpiringTokens();

    expect(found.accessTokens).toEqual([accessRow]);
    expect(found.refreshTokens).toEqual([refreshRow]);
  });

  it("finding is read-only — it deletes nothing", async () => {
    await authService.findNeverExpiringTokens();

    expect(accessTokenPurgeNeverExpiring).not.toHaveBeenCalled();
    expect(refreshTokenPurgeNeverExpiring).not.toHaveBeenCalled();
  });

  it("purges both models and returns the counts", async () => {
    accessTokenPurgeNeverExpiring.mockResolvedValue([{ id: "at-1" }, { id: "at-2" }]);
    refreshTokenPurgeNeverExpiring.mockResolvedValue([buildRefreshTokenRow({ id: "rt-1" })]);

    const purged = await authService.purgeNeverExpiringTokens();

    expect(purged).toEqual({ accessTokens: 2, refreshTokens: 1 });
  });

  it("emits token.expired per removed refresh token", async () => {
    const row = buildRefreshTokenRow({ id: "rt-1" });
    refreshTokenPurgeNeverExpiring.mockResolvedValue([row]);

    await authService.purgeNeverExpiringTokens();

    expect(emit).toHaveBeenCalledWith("token.expired", row);
  });
});

describe("authService.getActiveSessions", () => {
  it("delegates to RefreshToken.activeFor", async () => {
    const rows = [buildRefreshTokenRow({})];
    refreshTokenActiveFor.mockResolvedValue(rows);
    const user = buildUser();

    expect(await authService.getActiveSessions(user)).toBe(rows);
    expect(refreshTokenActiveFor).toHaveBeenCalledWith(user);
  });
});
