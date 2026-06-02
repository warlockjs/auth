import type { RefreshToken } from "../models/refresh-token/refresh-token.model";
import type { AccessTokenOutput, DeviceInfo, TokenPair } from "./types";

/**
 * Surface every authenticable user model exposes once it extends the
 * `Auth` base. The `Auth` class implements this contract; subclasses only
 * need to provide the abstract `userType` getter.
 *
 * Kept in sync with `Auth` — if a method here drifts from the class, the
 * `implements Authenticable` clause on `Auth` fails to compile.
 */
export interface Authenticable {
  /**
   * Discriminator identifying which user type this model represents.
   * Drives token payloads and `authMiddleware` type checks.
   */
  get userType(): string;

  /**
   * Generate (and persist) an access token for this user.
   * Pass a custom payload to override the default token claims.
   */
  generateAccessToken(payload?: Record<string, unknown>): Promise<AccessTokenOutput>;

  /**
   * Generate a refresh token for this user. Resolves to `undefined` when
   * refresh tokens are disabled in config.
   */
  generateRefreshToken(deviceInfo?: DeviceInfo): Promise<RefreshToken | undefined>;

  /**
   * Issue both an access token and a refresh token in one call.
   */
  createTokenPair(deviceInfo?: DeviceInfo): Promise<TokenPair>;

  /**
   * Verify a plaintext password against this user's stored hash.
   */
  confirmPassword(password: string): Promise<boolean>;
}
