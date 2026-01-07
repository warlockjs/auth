import { ChildModel } from "@warlock.js/cascade";
import { type Algorithm } from "fast-jwt";
import type { Auth } from "../models/auth";
import type { Duration, ExpiresIn } from "../utils/duration";

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
 *   jwt: {
 *     secret: env("JWT_SECRET"),
 *     expiresIn: NO_EXPIRATION,  // Token never expires
 *   },
 * };
 *
 * export default authConfigurations;
 * ```
 */
export const NO_EXPIRATION = Symbol("NO_EXPIRATION");

/**
 * Behavior when logout is called without a refresh token
 * - "revoke-all": Revoke all refresh tokens for the user (secure default)
 * - "error": Return an error requiring the refresh token
 */
export type LogoutWithoutTokenBehavior = "revoke-all" | "error";

export type AuthConfigurations = {
  /**
   * Define all user types
   * This is important to differentiate between user types when validating and generating tokens
   */
  userType: {
    [userType: string]: ChildModel<Auth>;
  };
  /**
   * JWT configurations
   */
  jwt: {
    /**
     * JWT secret key for signing access tokens
     */
    secret: string;
    /**
     * JWT algorithm
     * @default "HS256"
     */
    algorithm?: Algorithm;
    /**
     * Access token expiration time
     * Supports Duration object, string format, or NO_EXPIRATION
     * @example { hours: 1 }, { days: 7, hours: 12 }, "1h", "1d 2h", NO_EXPIRATION
     * @default { hours: 1 }
     */
    expiresIn?: ExpiresIn;
    /**
     * Refresh token configurations
     */
    refresh?: {
      /**
       * Separate secret for refresh tokens (recommended for security)
       * If not provided, falls back to main JWT secret
       */
      secret?: string;
      /**
       * Enable refresh token
       * @default true
       */
      enabled?: boolean;
      /**
       * Refresh token expiration time
       * Supports Duration object or string format
       * @example { days: 7 }, { weeks: 1 }, "7d", "1w"
       * @default { days: 7 }
       */
      expiresIn?: Duration | string | number;
      /**
       * Enable token rotation (issue new refresh token on each use)
       * Old refresh token is invalidated after use
       * @default true
       */
      rotation?: boolean;
      /**
       * Maximum number of active refresh tokens per user
       * When exceeded, oldest tokens are revoked
       * @default 5
       */
      maxPerUser?: number;
      /**
       * Behavior when logout is called without a refresh token
       * - "revoke-all": Revoke all tokens for security (default)
       * - "error": Require refresh token, return error if missing
       * @default "revoke-all"
       */
      logoutWithoutToken?: LogoutWithoutTokenBehavior;
    };
  };
  /**
   * Password configurations
   */
  password?: {
    /**
     * Password salt
     * The higher the salt, the more secure the password is
     * But, it will take more time to generate the password
     * @default 12
     */
    salt?: number;
  };
};

/**
 * Token pair returned after login or token refresh
 */
export type TokenPair = {
  /**
   * JWT access token (short-lived)
   */
  accessToken: string;
  /**
   * JWT refresh token (long-lived)
   */
  refreshToken: string;
  /**
   * Access token expiration time in seconds or time string
   */
  expiresIn: number | string;
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
