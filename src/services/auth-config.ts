import { config } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import { type Algorithm } from "fast-jwt";
import ms from "ms";
import type { LogoutWithoutTokenBehavior } from "../contracts/types";

const warnedLegacyKeys = new Set<string>();

/**
 * `ms` accepts anything at runtime and answers `undefined` for a string it
 * cannot parse (`"30dayz"`), a *formatted string* for a number (`2592000` ⇒
 * `"43m"`), and throws for `""`. Its published types claim the far narrower
 * `(value: ms.StringValue) => number`, which is exactly what let an
 * `as ms.StringValue` cast smuggle arbitrary config text past the compiler and
 * hand `undefined` to the JWT signer. Declare the honest runtime signature once,
 * here, so every caller is forced to deal with the `undefined`.
 */
const parseMs = ms as unknown as (value: unknown) => number | string | undefined;

/**
 * Turn a configured lifetime into a positive number of milliseconds, or throw
 * naming the key.
 *
 * A token lifetime is a security boundary, so an unusable value is a hard error
 * rather than a silent fallback: substituting a default would trade one
 * unintended lifetime for another, just as quietly — and quiet is the whole
 * problem. Every non-positive, non-finite or non-numeric parse is rejected:
 *
 * - `"30dayz"` / `"thirty days"` ⇒ `undefined` ⇒ a JWT signed with **no `exp`
 *   claim** and an `Invalid Date` written to the token row.
 * - `"0d"` ⇒ parses cleanly to `0`, which `fast-jwt` treats as falsy and also
 *   emits with **no `exp` claim** — it survives any guard that only rejects
 *   `undefined`. `"-1h"` signs an already-expired token.
 * - `2592000` (a bare number) ⇒ `ms` *formats* it as `"43m"`, a string, which
 *   then turns `Date.now() + expiresIn` into an `Invalid Date`.
 */
function parseDuration(key: string, raw: unknown): number {
  let parsed: number | string | undefined;

  try {
    parsed = parseMs(raw);
  } catch {
    // ms throws (rather than returning undefined) for "" and non-strings
    parsed = undefined;
  }

  if (typeof parsed !== "number" || !Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(
      `auth.${key}: ${JSON.stringify(raw)} is not a valid ms duration — ` +
        `use a positive duration string such as "1h", "7d", or NO_EXPIRATION.`,
    );
  }

  return parsed;
}

/** Access-token lifetime used when nothing is configured. */
const DEFAULT_ACCESS_TOKEN_EXPIRES_IN = "1h";

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
    /**
     * Lifetime in milliseconds — the only form a token issuer may use. Defaults
     * to 1 hour when unset; throws naming the key when the configured value is
     * not a positive `ms` duration. See {@link parseDuration}.
     */
    expiresInMs: (): number =>
      parseDuration(
        "accessToken.expiresIn",
        authConfig.accessToken.expiresIn() ?? DEFAULT_ACCESS_TOKEN_EXPIRES_IN,
      ),
  },
  refreshToken: {
    /** Separate refresh secret (legacy: `auth.jwt.refresh.secret`); empty ⇒ fall back to the access secret. */
    secret: (): string | undefined => resolve("refreshToken.secret", "jwt.refresh.secret"),
    /** Whether refresh tokens are enabled (legacy: `auth.jwt.refresh.enabled`). */
    enabled: (): boolean => resolve("refreshToken.enabled", "jwt.refresh.enabled", true),
    /** Lifetime as an `ms`-string (legacy: `auth.jwt.refresh.expiresIn`). */
    expiresIn: (): string => resolve("refreshToken.expiresIn", "jwt.refresh.expiresIn", "7d"),
    /**
     * Lifetime in milliseconds — the only form a token issuer may use. Throws
     * naming the key when the configured value is not a positive `ms` duration.
     */
    expiresInMs: (): number =>
      parseDuration("refreshToken.expiresIn", authConfig.refreshToken.expiresIn()),
    /** Rotate-on-use (legacy: `auth.jwt.refresh.rotation`). */
    rotation: (): boolean => resolve("refreshToken.rotation", "jwt.refresh.rotation", true),
    /** Max active tokens per user (legacy: `auth.jwt.refresh.maxPerUser`). */
    maxPerUser: (): number => resolve("refreshToken.maxPerUser", "jwt.refresh.maxPerUser", 5),
    /** Logout-without-token behavior (legacy: `auth.jwt.refresh.logoutWithoutToken`). */
    logoutWithoutToken: (): LogoutWithoutTokenBehavior =>
      resolve("refreshToken.logoutWithoutToken", "jwt.refresh.logoutWithoutToken", "revoke-all"),
  },
};
