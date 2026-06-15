import { config } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import { type Algorithm } from "fast-jwt";
import type { LogoutWithoutTokenBehavior } from "../contracts/types";

const warnedLegacyKeys = new Set<string>();

/**
 * Resolve an auth setting, preferring the new `auth.accessToken.*` /
 * `auth.refreshToken.*` key and falling back to the deprecated `auth.jwt.*`
 * shape — warning once per legacy key. Returns `fallback` when neither is set.
 *
 * This is the backward-compatible shim that lets existing `auth.jwt.*` configs
 * keep working after the config split.
 */
function resolve<T>(newKey: string, legacyKey: string, fallback?: T): T {
  const fromNew = config.key(`auth.${newKey}`);

  if (fromNew !== undefined && fromNew !== null) {
    return fromNew as T;
  }

  const fromLegacy = config.key(`auth.${legacyKey}`);

  if (fromLegacy !== undefined && fromLegacy !== null) {
    if (!warnedLegacyKeys.has(legacyKey)) {
      warnedLegacyKeys.add(legacyKey);
      log.warn("auth", "config-deprecation", `auth.${legacyKey} is deprecated — use auth.${newKey}`);
    }

    return fromLegacy as T;
  }

  return fallback as T;
}

/**
 * Typed, backward-compatible access to auth configuration. The service and the
 * jwt signer read configuration exclusively through here, so the new split
 * config and the legacy `auth.jwt.*` shape both resolve the same way.
 */
export const authConfig = {
  accessToken: {
    /** Signing secret (legacy: `auth.jwt.secret`). Throws if neither is set. */
    secret: (): string => {
      const secret = resolve<string | undefined>("accessToken.secret", "jwt.secret");

      if (!secret) {
        throw new Error("auth: no JWT secret configured — set `auth.accessToken.secret`.");
      }

      return secret;
    },
    /** Signing algorithm (legacy: `auth.jwt.algorithm`). */
    algorithm: (): Algorithm => resolve("accessToken.algorithm", "jwt.algorithm", "HS256"),
    /** Lifetime as an `ms`-string (legacy: `auth.jwt.expiresIn`). */
    expiresIn: (): string | undefined => resolve("accessToken.expiresIn", "jwt.expiresIn"),
  },
  refreshToken: {
    /** Separate refresh secret (legacy: `auth.jwt.refresh.secret`); empty ⇒ fall back to the access secret. */
    secret: (): string | undefined => resolve("refreshToken.secret", "jwt.refresh.secret"),
    /** Whether refresh tokens are enabled (legacy: `auth.jwt.refresh.enabled`). */
    enabled: (): boolean => resolve("refreshToken.enabled", "jwt.refresh.enabled", true),
    /** Lifetime as an `ms`-string (legacy: `auth.jwt.refresh.expiresIn`). */
    expiresIn: (): string => resolve("refreshToken.expiresIn", "jwt.refresh.expiresIn", "7d"),
    /** Rotate-on-use (legacy: `auth.jwt.refresh.rotation`). */
    rotation: (): boolean => resolve("refreshToken.rotation", "jwt.refresh.rotation", true),
    /** Max active tokens per user (legacy: `auth.jwt.refresh.maxPerUser`). */
    maxPerUser: (): number => resolve("refreshToken.maxPerUser", "jwt.refresh.maxPerUser", 5),
    /** Logout-without-token behavior (legacy: `auth.jwt.refresh.logoutWithoutToken`). */
    logoutWithoutToken: (): LogoutWithoutTokenBehavior =>
      resolve("refreshToken.logoutWithoutToken", "jwt.refresh.logoutWithoutToken", "revoke-all"),
  },
};
