import { type ChildModel, Model, type ModelSchema } from "@warlock.js/cascade";
import type { AccessTokenOutput, DeviceInfo, TokenPair } from "../contracts/types";
import { authService } from "../services";
import type { RefreshToken } from "./refresh-token/refresh-token.model";

export abstract class Auth<Schema extends ModelSchema = ModelSchema> extends Model<Schema> {
  /**
   * Get user type
   */
  public abstract get userType(): string;

  /**
   * Get access token payload
   */
  public accessTokenPayload() {
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
  public async generateAccessToken(data?: any): Promise<AccessTokenOutput> {
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
   * Remove refresh token
   */
  public async removeRefreshToken(token: string): Promise<void> {
    return authService.removeRefreshToken(this, token);
  }

  /**
   * Remove all access tokens
   */
  public async removeAllAccessTokens(): Promise<void> {
    return authService.removeAllAccessTokens(this);
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
  public static async attempt(this: ChildModel<Auth>, data: any): Promise<Auth | null> {
    return authService.attemptLogin(this, data);
  }

  /**
   * Confirm password
   */
  public async confirmPassword(password: string): Promise<boolean> {
    return authService.verifyPassword(this.string("password")!, password);
  }
}
