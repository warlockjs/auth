import type { ChildModel } from "@warlock.js/cascade";
import { Model } from "@warlock.js/cascade";
import type { DeviceInfo, TokenPair } from "../contracts/types";
import { authService } from "../services";
import type { RefreshToken } from "./refresh-token/refresh-token";

export abstract class Auth extends Model {
  /**
   * Get user type
   */
  public abstract get userType(): string;

  /**
   * Get access token payload
   */
  public accessTokenPayload() {
    // Dynamically import to avoid circular dependency
    const { authService } = require("../services/auth.service");
    return authService.buildAccessTokenPayload(this);
  }

  /**
   * Create both access and refresh tokens
   */
  public async createTokenPair(deviceInfo?: DeviceInfo): Promise<TokenPair> {
    return authService.createTokenPair(this, deviceInfo);
  }

  /**
   * Generate access token
   */
  public async generateAccessToken(data?: any): Promise<string> {
    return authService.generateAccessToken(this, data);
  }

  /**
   * Generate refresh token
   */
  public async generateRefreshToken(deviceInfo?: DeviceInfo): Promise<RefreshToken> {
    return authService.createRefreshToken(this, deviceInfo);
  }

  /**
   * Remove current access token
   */
  public async removeAccessToken(token: string): Promise<void> {
    return authService.removeAccessToken(this, token);
  }

  /**
   * Revoke all tokens (logout from all devices)
   */
  public async revokeAllTokens(): Promise<void> {
    return authService.revokeAllTokens(this);
  }

  /**
   * Get active sessions
   */
  public async activeSessions(): Promise<RefreshToken[]> {
    return authService.getActiveSessions(this);
  }

  /**
   * Attempt to login the user
   */
  public static async attempt<T>(this: ChildModel<T>, data: any): Promise<T | null> {
    return authService.attemptLogin(this, data);
  }

  /**
   * Confirm password
   */
  public confirmPassword(password: string): boolean {
    return authService.verifyPassword(this.get("password"), password);
  }
}
