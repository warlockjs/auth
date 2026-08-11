import { Random } from "@mongez/reinforcements";
import type { ChildModel } from "@warlock.js/cascade";
import { config, hashPassword, verifyPassword } from "@warlock.js/core";
import type { AccessTokenOutput, DeviceInfo, LoginResult, TokenPair } from "../contracts/types";
import { AccessToken } from "../models/access-token";
import type { Auth } from "../models/auth.model";
import { RefreshToken } from "../models/refresh-token";
import { authConfig } from "./auth-config";
import { authEvents } from "./auth-events";
import { jwt } from "./jwt";

class AuthService {
  /**
   * Resolve the active access-token model — the package default, or a subclass
   * an app registered under `config.auth.accessToken.model` (e.g. to add a
   * tenant column). The service never references the concrete class directly so
   * an override is a pure config change.
   */
  private get accessTokenModel(): typeof AccessToken {
    return config.key("auth.accessToken.model", AccessToken);
  }

  /**
   * Resolve the active refresh-token model (default or registered override).
   */
  private get refreshTokenModel(): typeof RefreshToken {
    return config.key("auth.refreshToken.model", RefreshToken);
  }

  /**
   * Build the default access-token JWT payload from a user.
   */
  public buildAccessTokenPayload(user: Auth) {
    return {
      id: user.id,
      userType: user.userType,
      created_at: Date.now(),
    };
  }

  /**
   * Sign + persist an access token for the user and return the token with its
   * expiry. The expiry is computed locally from `expiresIn` rather than by
   * re-verifying the token we just signed.
   */
  public async generateAccessToken(user: Auth, payload?: any): Promise<AccessTokenOutput> {
    const data = payload || this.buildAccessTokenPayload(user);
    // Validated before anything is signed or persisted: an unusable lifetime
    // throws naming the config key rather than minting a token whose expiry
    // nobody chose (defaults to 1h when unset).
    const expiresIn = authConfig.accessToken.expiresInMs();

    const token = await jwt.generate(data, { expiresIn });
    const expiresAt = new Date(Date.now() + expiresIn);

    await this.accessTokenModel.issue(user, token, expiresAt);

    return { token, expiresAt: expiresAt.toISOString() };
  }

  /**
   * Sign + persist a refresh token for the user (enforcing the per-user cap
   * first). Resolves to `undefined` when refresh tokens are disabled in config.
   */
  public async createRefreshToken(
    user: Auth,
    deviceInfo?: DeviceInfo,
  ): Promise<RefreshToken | undefined> {
    if (!authConfig.refreshToken.enabled()) return;

    // Validate the lifetime first — before the per-user cap is enforced, before
    // anything is signed — so a bad value can never revoke a user's oldest
    // session on its way to failing.
    const expiresIn = authConfig.refreshToken.expiresInMs();

    const familyId = deviceInfo?.familyId || Random.string(32);

    const payload = {
      userId: user.id,
      userType: user.userType,
      familyId,
    };

    const expiresAt = new Date(Date.now() + expiresIn).toISOString();

    await this.refreshTokenModel.enforceMax(user, authConfig.refreshToken.maxPerUser());

    const token = await jwt.generateRefreshToken(payload, { expiresIn });

    return this.refreshTokenModel.issue(user, token, { familyId, expiresAt, deviceInfo });
  }

  /**
   * Issue both an access and a refresh token, emitting the creation events.
   */
  public async createTokenPair(user: Auth, deviceInfo?: DeviceInfo): Promise<TokenPair> {
    const accessToken = await this.generateAccessToken(user, deviceInfo?.payload);
    const refreshToken = await this.createRefreshToken(user, deviceInfo);

    const tokenPair: TokenPair = {
      accessToken,
      refreshToken: refreshToken
        ? {
            token: refreshToken.get("token"),
            expiresAt: refreshToken.get("expires_at"),
          }
        : undefined,
    };

    authEvents.emit("token.created", user, tokenPair);

    if (refreshToken) {
      authEvents.emit("session.created", user, refreshToken, deviceInfo);
    }

    return tokenPair;
  }

  /**
   * Exchange a refresh token for a new token pair, with rotation + replay
   * detection. A concurrent reuse of the same token loses the atomic revoke and
   * is treated as a breach — the whole family is revoked and the request fails.
   */
  public async refreshTokens(
    refreshTokenString: string,
    deviceInfo?: DeviceInfo,
  ): Promise<TokenPair | null> {
    try {
      const decoded = await jwt.verifyRefreshToken<{
        userId: number;
        userType: string;
        familyId: string;
      }>(refreshTokenString);

      if (!decoded) return null;

      const refreshToken = await this.refreshTokenModel.findByToken(refreshTokenString);

      if (!refreshToken?.isValid) {
        // Already-invalid token presented → likely a replayed (rotated) token.
        if (refreshToken) {
          await this.revokeTokenFamily(refreshToken.familyId);
        }

        return null;
      }

      const UserModel = config.key(`auth.userType.${decoded.userType}`);

      if (!UserModel) return null;

      const user = (await UserModel.find(decoded.userId)) as Auth | null;

      if (!user) return null;

      const rotationEnabled = authConfig.refreshToken.rotation();

      if (rotationEnabled) {
        const won = await refreshToken.revokeIfActive();

        if (!won) {
          // A concurrent request already rotated this token (reuse / replay).
          await this.revokeTokenFamily(refreshToken.familyId);

          return null;
        }
      } else {
        await refreshToken.markAsUsed();
      }

      const newTokenPair = await this.createTokenPair(user, {
        ...deviceInfo,
        familyId: refreshToken.familyId,
      });

      authEvents.emit("token.refreshed", user, newTokenPair, refreshToken);

      return newTokenPair;
    } catch {
      return null;
    }
  }

  /**
   * Verify a plaintext password against a stored hash.
   */
  public async verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return verifyPassword(plainPassword, hashedPassword);
  }

  /**
   * Hash a plaintext password.
   */
  public async hashPassword(password: string): Promise<string> {
    return hashPassword(password);
  }

  /**
   * Resolve a user by credentials, verifying the password. Returns `null` on a
   * missing user or a wrong password, emitting `login.failed` either way.
   */
  public async attemptLogin<T extends Auth>(Model: ChildModel<T>, data: any): Promise<T | null> {
    const { password, ...otherData } = data;

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
   * Full login flow: validate credentials, issue tokens, emit events. Returns
   * the user + token pair on success, `null` on failure.
   */
  public async login<T extends Auth>(
    Model: ChildModel<T>,
    credentials: any,
    deviceInfo?: DeviceInfo,
  ): Promise<LoginResult<T> | null> {
    const user = await this.attemptLogin(Model, credentials);

    if (!user) {
      return null;
    }

    if (!authConfig.refreshToken.enabled()) {
      const accessToken = await this.generateAccessToken(user, deviceInfo?.payload);

      return { user, tokens: { accessToken } };
    }

    const tokens = await this.createTokenPair(user, deviceInfo);

    authEvents.emit("login.success", user, tokens, deviceInfo);

    return { user, tokens } as LoginResult<T>;
  }

  /**
   * Log a user out.
   *
   * @param accessToken - access token string to revoke (optional)
   * @param refreshToken - refresh token string to revoke (optional)
   *
   * When no refresh token is supplied, `config.auth.refreshToken.logoutWithoutToken`
   * decides the behavior: `"revoke-all"` (default, fail-safe) revokes every
   * refresh token; `"error"` requires the caller to pass one.
   */
  public async logout(user: Auth, accessToken?: string, refreshToken?: string): Promise<void> {
    if (accessToken) {
      await this.removeAccessToken(user, accessToken);
    }

    if (refreshToken) {
      const token = await this.refreshTokenModel.findForUser(user, refreshToken);

      if (token) {
        await token.revoke();
        authEvents.emit("session.destroyed", user, token);
      }
    } else {
      const behavior = authConfig.refreshToken.logoutWithoutToken();

      if (behavior === "error") {
        throw new Error("Refresh token required for logout");
      }

      await this.revokeAllTokens(user);
      authEvents.emit("logout.failsafe", user);
    }

    authEvents.emit("logout", user);
  }

  /**
   * Remove a specific access token belonging to the user.
   */
  public async removeAccessToken(user: Auth, token: string): Promise<void> {
    await this.accessTokenModel.deleteForUser(user, token);
  }

  /**
   * Remove every access token belonging to the user.
   */
  public async removeAllAccessTokens(user: Auth): Promise<void> {
    await this.accessTokenModel.deleteAllForUser(user);
  }

  /**
   * Remove a specific refresh token belonging to the user.
   */
  public async removeRefreshToken(user: Auth, token: string): Promise<void> {
    await this.refreshTokenModel.deleteForUser(user, token);
  }

  /**
   * Revoke every active refresh token for the user and delete their access
   * tokens — "log out of all devices". Revocation is a single bulk update; an
   * event fires per revoked token.
   */
  public async revokeAllTokens(user: Auth): Promise<void> {
    const revokedTokens = await this.refreshTokenModel.revokeAllFor(user);

    for (const token of revokedTokens) {
      authEvents.emit("token.revoked", user, token);
    }

    await this.removeAllAccessTokens(user);

    authEvents.emit("logout.all", user);
  }

  /**
   * Revoke an entire token family — rotation breach containment.
   */
  public async revokeTokenFamily(familyId: string): Promise<void> {
    const revokedTokens = await this.refreshTokenModel.revokeFamily(familyId);

    authEvents.emit("token.familyRevoked", familyId, revokedTokens);
  }

  /**
   * Delete expired tokens (refresh + access). Emits `token.expired` per refresh
   * token and `cleanup.completed` with the refresh count. Drives the
   * `auth.cleanup` CLI command.
   */
  public async cleanupExpiredTokens(): Promise<number> {
    const expiredTokens = await this.refreshTokenModel.purgeExpired();

    for (const token of expiredTokens) {
      authEvents.emit("token.expired", token);
    }

    await this.accessTokenModel.purgeExpired();

    authEvents.emit("cleanup.completed", expiredTokens.length);

    return expiredTokens.length;
  }

  /**
   * Find every persisted token — access and refresh — that can never retire
   * itself: an unusable `expires_at`, or a token carrying no `exp` claim.
   *
   * This is the remediation read for the pre-4.12.0 `expiresIn` defect (#25).
   * Nothing else surfaces these rows: `auth.cleanup` selects `expires_at < now`,
   * which an `Invalid Date` never satisfies, and a row whose date column is
   * perfectly fine can still hold a token with no deadline in it. Read-only —
   * pair with {@link purgeNeverExpiringTokens} to act on the answer.
   */
  public async findNeverExpiringTokens(): Promise<{
    accessTokens: AccessToken[];
    refreshTokens: RefreshToken[];
  }> {
    return {
      accessTokens: await this.accessTokenModel.findNeverExpiring(),
      refreshTokens: await this.refreshTokenModel.findNeverExpiring(),
    };
  }

  /**
   * Revoke every never-expiring token by deleting its row, emitting
   * `token.revoked` per refresh token. Drives `warlock auth.purge-never-expiring`.
   *
   * Access tokens first: deleting one is immediate revocation, while a refresh
   * token left in place for a moment can only mint an access token through a
   * verifier that now rejects it for the missing `exp`.
   */
  public async purgeNeverExpiringTokens(): Promise<{
    accessTokens: number;
    refreshTokens: number;
  }> {
    const accessTokens = await this.accessTokenModel.purgeNeverExpiring();
    const refreshTokens = await this.refreshTokenModel.purgeNeverExpiring();

    // `token.expired` (the event `auth.cleanup` already emits for a removed
    // refresh token) rather than `token.revoked`, which carries a loaded `Auth`
    // this batch path has no reason to fetch a user row for.
    for (const token of refreshTokens) {
      authEvents.emit("token.expired", token);
    }

    return { accessTokens: accessTokens.length, refreshTokens: refreshTokens.length };
  }

  /**
   * Active, unexpired sessions for the user, newest first.
   */
  public async getActiveSessions(user: Auth): Promise<RefreshToken[]> {
    return this.refreshTokenModel.activeFor(user);
  }
}

export const authService = new AuthService();
