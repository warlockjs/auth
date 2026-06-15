import { type ChildModel } from "@warlock.js/cascade";
import { type Algorithm } from "fast-jwt";
import type { AccessToken } from "../models/access-token";
import type { Auth } from "../models/auth.model";
import type { RefreshToken } from "../models/refresh-token";

/**
 * Symbol to indicate no expiration for tokens
 * Use this when you explicitly want tokens to never expire
 *
 * @example
 * ```typescript
 * // src/config/auth.ts
 * import { NO_EXPIRATION, type AuthConfigurations } from "@warlock.js/auth";
 *
 * const authConfigurations: AuthConfigurations = {
 *   accessToken: {
 *     secret: env("JWT_SECRET"),
 *     expiresIn: NO_EXPIRATION,  // Token expires within 100 years
 *   },
 * };
 *
 * export default authConfigurations;
 * ```
 */
export const NO_EXPIRATION = "100y";

/**
 * Behavior when logout is called without a refresh token
 * - "revoke-all": Revoke all refresh tokens for the user (secure default)
 * - "error": Return an error requiring the refresh token
 */
export type LogoutWithoutTokenBehavior = "revoke-all" | "error";

/**
 * Access-token configuration.
 *
 * `secret` may also be supplied via the deprecated `jwt.secret` (resolved by a
 * backward-compatible shim); one of the two is required at runtime.
 */
export type AccessTokenConfig = {
  /**
   * Override the persisted access-token model — extend {@link AccessToken} to
   * add columns (e.g. a tenant key) or rename them, then register the subclass
   * here. Defaults to the package's `AccessToken`.
   */
  model?: typeof AccessToken;
  /**
   * Secret used to sign access tokens.
   */
  secret?: string;
  /**
   * JWT algorithm.
   * @default "HS256"
   */
  algorithm?: Algorithm;
  /**
   * Access-token lifetime — any value the `ms` package accepts.
   * @example "1h" or NO_EXPIRATION
   * @default "1h"
   */
  expiresIn?: string;
};

/**
 * Refresh-token configuration.
 */
export type RefreshTokenConfig = {
  /**
   * Override the persisted refresh-token model — extend {@link RefreshToken}.
   * Defaults to the package's `RefreshToken`.
   */
  model?: typeof RefreshToken;
  /**
   * Enable refresh tokens.
   * @default true
   */
  enabled?: boolean;
  /**
   * Separate secret for refresh tokens (recommended for security). Falls back
   * to the access-token secret when omitted.
   */
  secret?: string;
  /**
   * Refresh-token lifetime — any value the `ms` package accepts.
   * @example "7d" or "1w"
   * @default "7d"
   */
  expiresIn?: string;
  /**
   * Rotate the refresh token on each use (old token revoked, replay detected).
   * @default true
   */
  rotation?: boolean;
  /**
   * Maximum active refresh tokens per user; the oldest are revoked past it.
   * @default 5
   */
  maxPerUser?: number;
  /**
   * Behavior when logout is called without a refresh token.
   * @default "revoke-all"
   */
  logoutWithoutToken?: LogoutWithoutTokenBehavior;
};

/**
 * Legacy JWT configuration shape. Still honored by the resolver shim with a
 * deprecation warning.
 *
 * @deprecated Use the top-level `accessToken` / `refreshToken` blocks.
 */
export type LegacyJwtConfig = {
  secret?: string;
  algorithm?: Algorithm;
  expiresIn?: string;
  refresh?: {
    secret?: string;
    enabled?: boolean;
    expiresIn?: string;
    rotation?: boolean;
    maxPerUser?: number;
    logoutWithoutToken?: LogoutWithoutTokenBehavior;
  };
};

export type AuthConfigurations = {
  /**
   * Define all user types — maps a user-type slug to its `Auth` model class so
   * tokens and the middleware can resolve the right model.
   */
  userType: {
    [userType: string]: ChildModel<Auth>;
  };
  /**
   * Access-token configuration (secret, expiry, algorithm, model override).
   */
  accessToken?: AccessTokenConfig;
  /**
   * Refresh-token configuration (rotation, lifetime, cap, model override).
   */
  refreshToken?: RefreshTokenConfig;
  /**
   * @deprecated Use `accessToken` / `refreshToken`. Read via a backward-compatible shim.
   */
  jwt?: LegacyJwtConfig;
};

export type AccessTokenOutput = {
  /**
   * JWT Token
   */
  token: string;
  /**
   * Exprie time in ISO format UTC time
   */
  expiresAt: string;
};

/**
 * Token pair returned after login or token refresh
 */
export type TokenPair = {
  /**
   * JWT access token (short-lived)
   */
  accessToken: AccessTokenOutput;
  /**
   * JWT refresh token (long-lived)
   */
  refreshToken?: AccessTokenOutput;
};

/**
 * Device information for session tracking
 */
export type DeviceInfo = {
  /**
   * User agent string from request
   */
  userAgent?: string;
  /**
   * Client IP address
   */
  ip?: string;
  /**
   * Optional device identifier
   */
  deviceId?: string;
  /**
   * Token family ID (for rotation tracking)
   * @internal
   */
  familyId?: string;
  /**
   * Access token payload
   */
  payload?: Record<string, any>;
};

export type LoginResult<UserType extends Auth> = {
  user: UserType;
  tokens: TokenPair;
};
