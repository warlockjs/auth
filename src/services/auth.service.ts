import { hash, verify } from "@mongez/password";
import { Random } from "@mongez/reinforcements";
import type { ChildModel } from "@warlock.js/cascade";
import { config } from "@warlock.js/core";
import type { DeviceInfo, TokenPair } from "../contracts/types";
import { AccessToken } from "../models/access-token";
import type { Auth } from "../models/auth.model";
import { RefreshToken } from "../models/refresh-token";
import { parseExpirationToMs, toJwtExpiresIn } from "../utils/duration";
import { authEvents } from "./auth-events";
import { jwt } from "./jwt";

class AuthService {
  /**
   * Build access token payload from user
   */
  public buildAccessTokenPayload(user: Auth) {
    return {
      id: user.id,
      _id: user.get("_id"),
      userType: user.userType,
      createdAt: Date.now(),
    };
  }

  /**
   * Generate access token for user
   */
  public async generateAccessToken(user: Auth, payload?: any): Promise<string> {
    const data = payload || this.buildAccessTokenPayload(user);
    const expiresInConfig = config.key("auth.jwt.expiresIn");
    const expiresIn = toJwtExpiresIn(expiresInConfig, 3600000); // default 1 hour

    // If expiresIn is undefined, token never expires
    const token = expiresIn ? await jwt.generate(data, { expiresIn }) : await jwt.generate(data);

    // Store in database
    await AccessToken.create({
      token,
      user: data,
    });

    return token;
  }

  /**
   * Create refresh token for user
   */
  public async createRefreshToken(user: Auth, deviceInfo?: DeviceInfo): Promise<RefreshToken> {
    const familyId = deviceInfo?.familyId || Random.string(32);
    const expiresInConfig = config.key("auth.jwt.refresh.expiresIn");
    const expiresInMs = parseExpirationToMs(expiresInConfig, 7 * 24 * 60 * 60 * 1000); // default 7 days

    const payload = {
      userId: user.id,
      userType: user.userType,
      familyId,
    };

    const token = await jwt.generateRefreshToken(payload);

    // Enforce max tokens per user
    await this.enforceMaxRefreshTokens(user);

    // Calculate expiration date (undefined means never expires, but we still set a far future date)
    const expiresAt = expiresInMs
      ? new Date(Date.now() + expiresInMs)
      : new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000);

    // Store in database
    return RefreshToken.create({
      token,
      userId: user.id,
      userType: user.userType,
      familyId,
      expiresAt,
      deviceInfo: deviceInfo
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
      refreshToken: refreshToken.get("token"),
      expiresIn: config.key("auth.jwt.expiresIn", "1h"),
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
          await this.revokeTokenFamily(refreshToken.get("familyId"));
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
        familyId: refreshToken.get("familyId"),
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
  public verifyPassword(hashedPassword: string, plainPassword: string): boolean {
    return verify(String(hashedPassword), String(plainPassword));
  }

  /**
   * Hash password
   */
  public hashPassword(password: string): string {
    return hash(String(password), config.key("auth.password.salt", 12));
  }

  /**
   * Attempt to login user with given credentials
   */
  public async attemptLogin(Model: ChildModel<Auth>, data: any): Promise<Auth | null> {
    const { password, ...otherData } = data;

    // Emit login attempt event
    authEvents.emit("login.attempt", otherData);

    const user = (await Model.first(otherData)) as Auth | null;

    if (!user) {
      authEvents.emit("login.failed", otherData, "User not found");
      return null;
    }

    if (!this.verifyPassword(user.string("password")!, password)) {
      authEvents.emit("login.failed", otherData, "Invalid password");
      return null;
    }

    return user;
  }

  /**
   * Full login flow: validate credentials, create tokens, emit events
   * Returns token pair on success, null on failure
   */
  public async login(
    Model: ChildModel<Auth>,
    credentials: any,
    deviceInfo?: DeviceInfo,
  ): Promise<{ user: Auth; tokens: TokenPair } | null | { user: Auth; accessToken: string }> {
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
      "user.id": user.id,
    });
  }

  /**
   * Revoke all tokens for a user
   */
  public async revokeAllTokens(user: Auth): Promise<void> {
    // Revoke all refresh tokens
    const refreshTokens = await RefreshToken.query()
      .where("userId", user.id)
      .where("userType", user.userType)
      .where("revokedAt", null)
      .get();

    for (const token of refreshTokens) {
      await token.revoke();
      authEvents.emit("token.revoked", user, token);
    }

    // Delete all access tokens
    await AccessToken.delete({
      "user.id": user.id,
      "user.userType": user.userType,
    });

    // Emit logout all event
    authEvents.emit("logout.all", user);
  }

  /**
   * Revoke entire token family (for rotation breach detection)
   */
  public async revokeTokenFamily(familyId: string): Promise<void> {
    const tokens = await RefreshToken.query()
      .where("familyId", familyId)
      .where("revokedAt", null)
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
    const expiredTokens = await RefreshToken.query().where("expiresAt", "<", new Date()).get();

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
        userId: user.id,
        userType: user.userType,
        reovkedAt: null,
      })
      .orderBy("createdAt", "asc")
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
        userId: user.id,
        userType: user.userType,
        revokedAt: null,
      })
      .where("expiresAt", ">", new Date())
      .orderBy("createdAt", "desc")
      .get();
  }
}

export const authService = new AuthService();
