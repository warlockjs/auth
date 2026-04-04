import { Random } from "@mongez/reinforcements";
import type { ChildModel } from "@warlock.js/cascade";
import { config, hashPassword, verifyPassword } from "@warlock.js/core";
import type { AccessTokenOutput, DeviceInfo, TokenPair } from "../contracts/types";
import { AccessToken } from "../models/access-token";
import type { Auth } from "../models/auth.model";
import { RefreshToken } from "../models/refresh-token";
import { toJwtExpiresIn } from "../utils/duration";
import { authEvents } from "./auth-events";
import { jwt } from "./jwt";

class AuthService {
  /**
   * Build access token payload from user
   */
  public buildAccessTokenPayload(user: Auth) {
    return {
      id: user.id,
      userType: user.userType,
      created_at: Date.now(),
    };
  }

  /**
   * Generate access token for user
   */
  public async generateAccessToken(user: Auth, payload?: any): Promise<AccessTokenOutput> {
    const data = payload || this.buildAccessTokenPayload(user);
    const expiresInConfig = config.key("auth.jwt.expiresIn");
    const expiresIn = toJwtExpiresIn(expiresInConfig, 3_600); // default 1 hour

    // If expiresIn is undefined, token never expires
    const token = await jwt.generate(data, { expiresIn });

    const decoed = await jwt.verify(token);

    // Store in database
    await AccessToken.create({
      token,
      user_id: user.id,
      user_type: user.userType,
    });

    return { token, expiresAt: new Date(decoed.exp * 1_000).toISOString() };
  }

  /**
   * Create refresh token for user
   */
  public async createRefreshToken(user: Auth, deviceInfo?: DeviceInfo): Promise<RefreshToken> {
    const familyId = deviceInfo?.familyId || Random.string(32);

    const payload = {
      userId: user.id,
      userType: user.userType,
      familyId,
    };

    const token = await jwt.generateRefreshToken(payload);

    const decoed = await jwt.verifyRefreshToken(token);

    // Calculate expiration date (undefined means never expires, but we still set a far future date)
    const expiresAt = new Date(decoed.exp * 1_000).toISOString();

    // Enforce max tokens per user
    await this.enforceMaxRefreshTokens(user);

    // Store in database
    return RefreshToken.create({
      token,
      user_id: user.id,
      user_type: user.userType,
      family_id: familyId,
      expires_at: expiresAt,
      device_info: deviceInfo
        ? {
            userAgent: deviceInfo.userAgent,
            ip: deviceInfo.ip,
            deviceId: deviceInfo.deviceId,
          }
        : undefined,
    });
  }

  /**
   * Create both access and refresh tokens
   */
  public async createTokenPair(user: Auth, deviceInfo?: DeviceInfo): Promise<TokenPair> {
    const accessToken = await this.generateAccessToken(user, deviceInfo?.payload);
    const refreshToken = await this.createRefreshToken(user, deviceInfo);

    const tokenPair: TokenPair = {
      accessToken,
      refreshToken: {
        token: refreshToken.get("token"),
        expiresAt: refreshToken.get("expires_at"),
      },
    };

    // Emit events
    authEvents.emit("token.created", user, tokenPair);
    authEvents.emit("session.created", user, refreshToken, deviceInfo);

    return tokenPair;
  }

  /**
   * Refresh tokens using a refresh token
   */
  public async refreshTokens(
    refreshTokenString: string,
    deviceInfo?: DeviceInfo,
  ): Promise<TokenPair | null> {
    try {
      // 1. Verify JWT signature
      const decoded = await jwt.verifyRefreshToken<{
        userId: number;
        userType: string;
        familyId: string;
      }>(refreshTokenString);

      if (!decoded) return null;

      // 2. Find token in database
      const refreshToken = await RefreshToken.first({ token: refreshTokenString });

      if (!refreshToken?.isValid) {
        // If token was already used (rotation detection), revoke entire family
        if (refreshToken) {
          await this.revokeTokenFamily(refreshToken.get("family_id"));
        }
        return null;
      }

      // 3. Get user model and find user
      const UserModel = config.key(`auth.userType.${decoded.userType}`);
      if (!UserModel) return null;

      const user = (await UserModel.find(decoded.userId)) as Auth | null;
      if (!user) return null;

      // 4. Rotate token if enabled (revoke old token)
      const rotationEnabled = config.key("auth.jwt.refresh.rotation", true);
      if (rotationEnabled) {
        await refreshToken.revoke();
      } else {
        await refreshToken.markAsUsed();
      }

      // 5. Generate new token pair (keep same family)
      const newTokenPair = await this.createTokenPair(user, {
        ...deviceInfo,
        familyId: refreshToken.get("family_id"),
      });

      // Emit token refreshed event
      authEvents.emit("token.refreshed", user, newTokenPair, refreshToken);

      return newTokenPair;
    } catch {
      return null;
    }
  }

  /**
   * Verify password
   */
  public async verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return verifyPassword(plainPassword, hashedPassword);
  }

  /**
   * Hash password
   */
  public async hashPassword(password: string): Promise<string> {
    return hashPassword(password);
  }

  /**
   * Attempt to login user with given credentials
   */
  public async attemptLogin<T extends Auth>(Model: ChildModel<T>, data: any): Promise<T | null> {
    const { password, ...otherData } = data;

    // Emit login attempt event
    authEvents.emit("login.attempt", otherData);

    const user = (await Model.first(otherData)) as T | null;

    if (!user) {
      authEvents.emit("login.failed", otherData, "User not found");
      return null;
    }

    if (!(await this.verifyPassword(password, user.string("password")!))) {
      authEvents.emit("login.failed", otherData, "Invalid password");
      return null;
    }

    return user;
  }

  /**
   * Full login flow: validate credentials, create tokens, emit events
   * Returns token pair on success, null on failure
   */
  public async login<T extends Auth>(
    Model: ChildModel<T>,
    credentials: any,
    deviceInfo?: DeviceInfo,
  ): Promise<{ user: T; tokens: TokenPair } | null | { user: T; accessToken: AccessTokenOutput }> {
    const user = await this.attemptLogin(Model, credentials);

    if (!user) {
      return null;
    }

    // if no refresh token in config, then return user and access token only
    if (!config.key("auth.jwt.refresh.enabled", true)) {
      const accessToken = await this.generateAccessToken(user, deviceInfo?.payload);
      return { user, accessToken };
    }

    const tokens = await this.createTokenPair(user, deviceInfo);

    // Emit login success event
    authEvents.emit("login.success", user, tokens, deviceInfo);

    return { user, tokens };
  }

  /**
   * Logout user
   * @param user - The authenticated user
   * @param accessToken - Optional access token string to revoke
   * @param refreshToken - Optional refresh token string to revoke
   * If refresh token is not provided, behavior is determined by config:
   * - "revoke-all" (default): Revoke ALL refresh tokens for security
   * - "error": Throw error requiring refresh token
   */
  public async logout(user: Auth, accessToken?: string, refreshToken?: string): Promise<void> {
    // Remove access token if provided
    if (accessToken) {
      await this.removeAccessToken(user, accessToken);
    }

    if (refreshToken) {
      // Revoke specific refresh token
      const token = await RefreshToken.first({
        token: refreshToken,
        userId: user.id, // Security: ensure token belongs to this user
      });

      if (token) {
        await token.revoke();
        authEvents.emit("session.destroyed", user, token);
      }
    } else {
      // No refresh token provided - check configured behavior
      const behavior = config.key("auth.jwt.refresh.logoutWithoutToken", "revoke-all") as
        | "revoke-all"
        | "error";

      if (behavior === "error") {
        throw new Error("Refresh token required for logout");
      }

      // Default: revoke-all (fail-safe)
      await this.revokeAllTokens(user);
      authEvents.emit("logout.failsafe", user);
    }

    // Emit logout event
    authEvents.emit("logout", user);
  }

  /**
   * Remove specific access token
   */
  public async removeAccessToken(user: Auth, token: string): Promise<void> {
    AccessToken.delete({
      token,
      userId: user.id,
    });
  }

  /**
   * Remove all access tokens for a user
   */
  public async removeAllAccessTokens(user: Auth): Promise<void> {
    // Delete access token
    AccessToken.delete({
      user_id: user.id,
    });
  }

  /**
   * Remove specific refresh token
   */
  public async removeRefreshToken(user: Auth, token: string): Promise<void> {
    RefreshToken.delete({
      token,
      userId: user.id,
    });
  }

  /**
   * Revoke all tokens for a user
   */
  public async revokeAllTokens(user: Auth): Promise<void> {
    // Revoke all refresh tokens
    const refreshTokens = await RefreshToken.query()
      .where("user_id", user.id)
      .where("user_type", user.userType)
      .where("revoked_at", null)
      .get();

    for (const token of refreshTokens) {
      await token.revoke();
      authEvents.emit("token.revoked", user, token);
    }

    // Delete all access tokens
    await this.removeAllAccessTokens(user);

    // Emit logout all event
    authEvents.emit("logout.all", user);
  }

  /**
   * Revoke entire token family (for rotation breach detection)
   */
  public async revokeTokenFamily(familyId: string): Promise<void> {
    const tokens = await RefreshToken.query()
      .where("family_id", familyId)
      .where("revoked_at", null)
      .get();

    for (const token of tokens) {
      await token.revoke();
    }

    // Emit family revoked event
    authEvents.emit("token.familyRevoked", familyId, tokens);
  }

  /**
   * Cleanup expired tokens
   */
  public async cleanupExpiredTokens(): Promise<number> {
    const expiredTokens = await RefreshToken.query().where("expires_at", "<", new Date()).get();

    for (const token of expiredTokens) {
      authEvents.emit("token.expired", token);
      await token.destroy();
    }

    // Emit cleanup completed event
    authEvents.emit("cleanup.completed", expiredTokens.length);

    return expiredTokens.length;
  }

  /**
   * Enforce max refresh tokens per user
   */
  private async enforceMaxRefreshTokens(user: Auth): Promise<void> {
    const maxPerUser = config.key("auth.jwt.refresh.maxPerUser", 5);

    const activeTokens = await RefreshToken.query()
      .where({
        user_id: user.id,
        user_type: user.userType,
        revoked_at: null,
      })
      .orderBy("created_at", "asc")
      .get();

    // Revoke oldest tokens if exceeding limit
    if (activeTokens.length >= maxPerUser) {
      const tokensToRevoke = activeTokens.slice(0, activeTokens.length - maxPerUser + 1);
      for (const token of tokensToRevoke) {
        await token.revoke();
      }
    }
  }

  /**
   * Get active sessions for user
   */
  public async getActiveSessions(user: Auth): Promise<RefreshToken[]> {
    return RefreshToken.query()
      .where({
        user_id: user.id,
        user_type: user.userType,
        revoked_at: null,
      })
      .where("expires_at", ">", new Date())
      .orderBy("created_at", "desc")
      .get();
  }
}

export const authService = new AuthService();
