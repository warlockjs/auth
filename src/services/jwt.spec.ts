import { beforeEach, describe, expect, it, vi } from "vitest";
import { createSigner } from "fast-jwt";
import ms from "ms";
import { NO_EXPIRATION } from "../contracts/types";

const configKey = vi.fn();

vi.mock("@warlock.js/core", () => ({
  config: { key: (...args: unknown[]) => configKey(...args) },
}));

vi.mock("@warlock.js/logger", () => ({
  log: { warn: vi.fn() },
}));

import { jwt } from "./jwt";

const ACCESS_SECRET = "access-secret-key-for-tests-0123456789";
const REFRESH_SECRET = "refresh-secret-key-for-tests-0123456789";

/**
 * Every token minted in this suite carries a lifetime: as of 4.12.0 both
 * verifiers require an `exp` claim, so a token signed without one is rejected
 * before any other assertion in the test can be reached — which is exactly the
 * point of #27, and means a spec that mints without `expiresIn` is no longer
 * describing a token this package could issue.
 */
const ONE_HOUR = 3_600_000;

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
      const token = await jwt.generate({ id: 42, userType: "user" }, { expiresIn: ONE_HOUR });
      const decoded = await jwt.verify<{ id: number; userType: string }>(token);

      expect(decoded.id).toBe(42);
      expect(decoded.userType).toBe("user");
    });

    it("produces a three-segment JWT string", async () => {
      const token = await jwt.generate({ id: 1 }, { expiresIn: ONE_HOUR });

      expect(token.split(".")).toHaveLength(3);
    });

    it("stamps an `exp` claim when `expiresIn` is given", async () => {
      const token = await jwt.generate({ id: 1 }, { expiresIn: 3_600_000 });
      const decoded = await jwt.verify<{ exp: number; iat: number }>(token);

      expect(decoded.exp).toBeGreaterThan(decoded.iat);
    });

    it("rejects a token signed with a different secret", async () => {
      const foreignToken = await jwt.generate(
        { id: 1 },
        { key: "a-totally-different-secret-value", expiresIn: ONE_HOUR },
      );

      await expect(jwt.verify(foreignToken)).rejects.toThrow();
    });

    it("rejects an already-expired token", async () => {
      const token = await jwt.generate({ id: 1 }, { expiresIn: 1, clockTimestamp: Date.now() });

      await new Promise((resolve) => setTimeout(resolve, 5));

      await expect(jwt.verify(token)).rejects.toThrow();
    });

    it("round-trips under a non-default algorithm pulled from config", async () => {
      stubConfig({ "auth.jwt.algorithm": "HS512" });

      const token = await jwt.generate({ id: 5 }, { expiresIn: ONE_HOUR });
      const decoded = await jwt.verify<{ id: number }>(token);

      expect(decoded.id).toBe(5);
    });

    it("rejects a token whose algorithm is not in the allowed list", async () => {
      // sign with the config default (HS256) ...
      const token = await jwt.generate({ id: 1 }, { expiresIn: ONE_HOUR });

      // ... then demand HS512 only on verify
      await expect(jwt.verify(token, { algorithms: ["HS512"] })).rejects.toThrow();
    });

    it("verifies with an explicit key override, ignoring the configured secret", async () => {
      const customKey = "explicit-override-key-abcdefghijklmnop";
      const token = await jwt.generate({ id: 1 }, { key: customKey, expiresIn: ONE_HOUR });

      const decoded = await jwt.verify<{ id: number }>(token, { key: customKey });

      expect(decoded.id).toBe(1);
    });

    // #27 (a). `fast-jwt` has no deadline to check on a token with no `exp`, so
    // it verifies it unchanged forever — measured against 6.2.4 at
    // `clockTimestamp` + 100 years. Every such token in the wild was minted by a
    // pre-4.12.0 `expiresIn` defect (#25); `NO_EXPIRATION` mints a real `exp`,
    // so no legitimate issuer produces one. The rejection therefore lives on
    // verify, where it catches a token from any version.
    it("rejects a token that carries no exp claim", async () => {
      const sign = createSigner({ key: ACCESS_SECRET, algorithm: "HS256" });
      const noExpToken = await sign({ id: 1, tokenType: "access" });

      await expect(jwt.verify(noExpToken)).rejects.toThrow(/exp claim is required/i);
    });

    it("rejects a no-exp token no matter how far the clock is moved", async () => {
      const sign = createSigner({ key: ACCESS_SECRET, algorithm: "HS256" });
      const noExpToken = await sign({ id: 1, tokenType: "access" });

      await expect(
        jwt.verify(noExpToken, { clockTimestamp: Date.now() + 100 * 365 * 24 * 3_600_000 }),
      ).rejects.toThrow(/exp claim is required/i);
    });

    it("keeps requiring exp even when the caller supplies its own requiredClaims", async () => {
      const sign = createSigner({ key: ACCESS_SECRET, algorithm: "HS256" });
      const noExpToken = await sign({ id: 1, tokenType: "access" });

      await expect(jwt.verify(noExpToken, { requiredClaims: ["iat"] })).rejects.toThrow(
        /exp claim is required/i,
      );
    });

    it("still honours a caller's additional requiredClaims alongside exp", async () => {
      const token = await jwt.generate({ id: 1 }, { expiresIn: 3_600_000 });

      await expect(jwt.verify(token, { requiredClaims: ["sub"] })).rejects.toThrow(
        /sub claim is required/i,
      );
    });

    it("accepts a NO_EXPIRATION token — a distant deadline is still a deadline", async () => {
      const token = await jwt.generate({ id: 1 }, { expiresIn: ms(NO_EXPIRATION as never) });
      const decoded = await jwt.verify<{ exp: number; iat: number }>(token);

      // ~100 years, in seconds
      expect(decoded.exp - decoded.iat).toBe(3_155_760_000);
    });
  });

  describe("refresh tokens", () => {
    it("round-trips through generateRefreshToken and verifyRefreshToken", async () => {
      const token = await jwt.generateRefreshToken(
        { userId: 7, familyId: "fam-1" },
        { expiresIn: ONE_HOUR },
      );
      const decoded = await jwt.verifyRefreshToken<{ userId: number; familyId: string }>(token);

      expect(decoded.userId).toBe(7);
      expect(decoded.familyId).toBe("fam-1");
    });

    it("signs refresh tokens with the refresh secret, not the access secret", async () => {
      const refreshToken = await jwt.generateRefreshToken({ userId: 7 }, { expiresIn: ONE_HOUR });

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
      const accessToken = await jwt.generate({ userId: 7 }, { expiresIn: ONE_HOUR });

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

      const token = await jwt.generateRefreshToken(
        { userId: 7, familyId: "fam-1" },
        { expiresIn: ONE_HOUR },
      );
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
      const token = await jwt.generateRefreshToken(
        { userId: 7 },
        { key: customKey, expiresIn: ONE_HOUR },
      );

      const decoded = await jwt.verifyRefreshToken<{ userId: number }>(token, { key: customKey });

      expect(decoded.userId).toBe(7);
    });
  });

  describe("token-class separation", () => {
    it("rejects an access token at the refresh verifier even under a shared secret", async () => {
      stubConfig({ "auth.jwt.refresh.secret": undefined });

      const accessToken = await jwt.generate({ id: 7 }, { expiresIn: ONE_HOUR });

      await expect(jwt.verifyRefreshToken(accessToken)).rejects.toThrow();
    });

    // Backward compatibility for a *missing tokenType* is preserved; backward
    // compatibility for a *missing exp* is not, and the two are unrelated. A
    // legacy token still needs a lifetime.
    it("accepts a legacy token that carries no tokenType claim (backward compatible)", async () => {
      // a token minted before tokenType stamping has no tokenType claim
      const sign = createSigner({ key: ACCESS_SECRET, algorithm: "HS256", expiresIn: ONE_HOUR });
      const legacyToken = await sign({ id: 7 });

      const decoded = await jwt.verify<{ id: number }>(legacyToken);

      expect(decoded.id).toBe(7);
    });
  });
});
