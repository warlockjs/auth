import { beforeEach, describe, expect, it, vi } from "vitest";
import { createSigner } from "fast-jwt";

const configKey = vi.fn();

vi.mock("@warlock.js/core", () => ({
  config: { key: (...args: unknown[]) => configKey(...args) },
}));

import { jwt } from "./jwt";

const ACCESS_SECRET = "access-secret-key-for-tests-0123456789";
const REFRESH_SECRET = "refresh-secret-key-for-tests-0123456789";

function stubConfig(overrides: Record<string, unknown> = {}) {
  const values: Record<string, unknown> = {
    "auth.jwt.secret": ACCESS_SECRET,
    "auth.jwt.algorithm": "HS256",
    "auth.jwt.refresh.secret": REFRESH_SECRET,
    ...overrides,
  };

  configKey.mockImplementation((key: string, fallback?: unknown) => {
    return key in values ? values[key] : fallback;
  });
}

describe("jwt", () => {
  beforeEach(() => {
    configKey.mockReset();
    stubConfig();
  });

  describe("generate + verify", () => {
    it("round-trips a payload through sign and verify", async () => {
      const token = await jwt.generate({ id: 42, userType: "user" });
      const decoded = await jwt.verify<{ id: number; userType: string }>(token);

      expect(decoded.id).toBe(42);
      expect(decoded.userType).toBe("user");
    });

    it("produces a three-segment JWT string", async () => {
      const token = await jwt.generate({ id: 1 });

      expect(token.split(".")).toHaveLength(3);
    });

    it("stamps an `exp` claim when `expiresIn` is given", async () => {
      const token = await jwt.generate({ id: 1 }, { expiresIn: 3_600_000 });
      const decoded = await jwt.verify<{ exp: number; iat: number }>(token);

      expect(decoded.exp).toBeGreaterThan(decoded.iat);
    });

    it("rejects a token signed with a different secret", async () => {
      const foreignToken = await jwt.generate({ id: 1 }, { key: "a-totally-different-secret-value" });

      await expect(jwt.verify(foreignToken)).rejects.toThrow();
    });

    it("rejects an already-expired token", async () => {
      const token = await jwt.generate({ id: 1 }, { expiresIn: 1, clockTimestamp: Date.now() });

      await new Promise((resolve) => setTimeout(resolve, 5));

      await expect(jwt.verify(token)).rejects.toThrow();
    });

    it("round-trips under a non-default algorithm pulled from config", async () => {
      stubConfig({ "auth.jwt.algorithm": "HS512" });

      const token = await jwt.generate({ id: 5 });
      const decoded = await jwt.verify<{ id: number }>(token);

      expect(decoded.id).toBe(5);
    });

    it("rejects a token whose algorithm is not in the allowed list", async () => {
      // sign with the config default (HS256) ...
      const token = await jwt.generate({ id: 1 });

      // ... then demand HS512 only on verify
      await expect(jwt.verify(token, { algorithms: ["HS512"] })).rejects.toThrow();
    });

    it("verifies with an explicit key override, ignoring the configured secret", async () => {
      const customKey = "explicit-override-key-abcdefghijklmnop";
      const token = await jwt.generate({ id: 1 }, { key: customKey });

      const decoded = await jwt.verify<{ id: number }>(token, { key: customKey });

      expect(decoded.id).toBe(1);
    });

    it("does not stamp an exp claim when expiresIn is omitted", async () => {
      const token = await jwt.generate({ id: 1 });
      const decoded = await jwt.verify<{ exp?: number }>(token);

      expect(decoded.exp).toBeUndefined();
    });
  });

  describe("refresh tokens", () => {
    it("round-trips through generateRefreshToken and verifyRefreshToken", async () => {
      const token = await jwt.generateRefreshToken({ userId: 7, familyId: "fam-1" });
      const decoded = await jwt.verifyRefreshToken<{ userId: number; familyId: string }>(token);

      expect(decoded.userId).toBe(7);
      expect(decoded.familyId).toBe("fam-1");
    });

    it("signs refresh tokens with the refresh secret, not the access secret", async () => {
      const refreshToken = await jwt.generateRefreshToken({ userId: 7 });

      // verifying a refresh token with the ACCESS secret must fail
      await expect(jwt.verify(refreshToken)).rejects.toThrow();
    });

    it("stamps an exp claim on refresh tokens when expiresIn is given", async () => {
      const token = await jwt.generateRefreshToken({ userId: 7 }, { expiresIn: 7 * 24 * 3_600_000 });
      const decoded = await jwt.verifyRefreshToken<{ exp: number; iat: number }>(token);

      expect(decoded.exp).toBeGreaterThan(decoded.iat);
    });

    it("rejects a refresh token that was signed with the access secret", async () => {
      // sign a token with the access secret, then try to verify as a refresh token
      const accessToken = await jwt.generate({ userId: 7 });

      await expect(jwt.verifyRefreshToken(accessToken)).rejects.toThrow();
    });

    it("rejects an expired refresh token", async () => {
      const token = await jwt.generateRefreshToken(
        { userId: 7 },
        { expiresIn: 1, clockTimestamp: Date.now() },
      );

      await new Promise((resolve) => setTimeout(resolve, 5));

      await expect(jwt.verifyRefreshToken(token)).rejects.toThrow();
    });

    // `contracts/types.ts` documents the refresh secret as optional: when
    // omitted, `getRefreshSecretKey()` falls back to the main JWT secret. With
    // no refresh secret configured, refresh tokens are signed/verified with the
    // access secret, so the round-trip succeeds.
    it("falls back to the main JWT secret when no refresh secret is configured", async () => {
      stubConfig({ "auth.jwt.refresh.secret": undefined });

      const token = await jwt.generateRefreshToken({ userId: 7, familyId: "fam-1" });
      const decoded = await jwt.verifyRefreshToken<{ userId: number; familyId: string }>(token);

      expect(decoded.userId).toBe(7);
      expect(decoded.familyId).toBe("fam-1");

      // Even though the shared secret would let the signature validate, the
      // tokenType claim keeps the classes separate: the access verifier rejects
      // a refresh token.
      await expect(jwt.verify(token)).rejects.toThrow();
    });

    it("can verify refresh tokens with an explicit key override", async () => {
      const customKey = "explicit-refresh-override-0123456789";
      const token = await jwt.generateRefreshToken({ userId: 7 }, { key: customKey });

      const decoded = await jwt.verifyRefreshToken<{ userId: number }>(token, { key: customKey });

      expect(decoded.userId).toBe(7);
    });
  });

  describe("token-class separation", () => {
    it("rejects an access token at the refresh verifier even under a shared secret", async () => {
      stubConfig({ "auth.jwt.refresh.secret": undefined });

      const accessToken = await jwt.generate({ id: 7 });

      await expect(jwt.verifyRefreshToken(accessToken)).rejects.toThrow();
    });

    it("accepts a legacy token that carries no tokenType claim (backward compatible)", async () => {
      // a token minted before tokenType stamping has no tokenType claim
      const sign = createSigner({ key: ACCESS_SECRET, algorithm: "HS256" });
      const legacyToken = await sign({ id: 7 });

      const decoded = await jwt.verify<{ id: number }>(legacyToken);

      expect(decoded.id).toBe(7);
    });
  });
});
