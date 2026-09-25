import { Random } from "@mongez/reinforcements";
import { randomUUID } from "node:crypto";
import type { ChildModel } from "@warlock.js/cascade";
import {
  config,
  ForbiddenError,
  hashPassword,
  type Request,
  verifyPassword,
} from "@warlock.js/core";
import type {
  AccessTokenOutput,
  AuthCredentials,
  ClearAuthCookieOptions,
  CookieWriter,
  DeviceInfo,
  LoginResult,
  SetAuthCookieOptions,
  TokenPair,
} from "../contracts/types";
import { assertCsrfOriginAllowed } from "../middleware/csrf-origin-check";
import { AccessToken } from "../models/access-token";
import type { Auth } from "../models/auth.model";
import { AuthTokenFamily } from "../models/auth-token-family";
import { OneTimeToken } from "../models/one-time-token";
import { RefreshToken } from "../models/refresh-token";
import { authConfig } from "./auth-config";
import { authEvents } from "./auth-events";
import { isInvalidCredentialError, jwt } from "./jwt";
import {
  afterTokenFamilyOperation,
  runTokenFamilyOperation,
  TokenFamilyUnavailableError,
} from "./token-family-operation";

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
   * Resolve the active one-time-token model (default or registered override).
   */
  private get oneTimeTokenModel(): typeof OneTimeToken {
    return config.key("auth.oneTimeToken.model", OneTimeToken);
  }

  /**
   * Build the default access-token JWT payload from a user.
   */
  public buildAccessTokenPayload(user: Auth): Record<string, unknown> {
    return {
      id: user.id,
      userType: user.userType,
      created_at: Date.now(),
    };
  }

  /** One policy seam keeps account-state checks identical across all auth paths. */
  public async canAuthenticate(user: Auth): Promise<boolean> {
    return authConfig.canAuthenticate(user);
  }

  private async assertCanAuthenticate(user: Auth): Promise<void> {
    if (!(await this.canAuthenticate(user))) {
      throw new ForbiddenError("This user cannot authenticate.");
    }
  }

  private async issueAccessToken(
    user: Auth,
    payload?: Record<string, unknown>,
    familyId?: string,
  ): Promise<AccessTokenOutput> {
    const data = { ...(payload || this.buildAccessTokenPayload(user)), jti: randomUUID() };
    // Validate before signing so an unusable lifetime cannot mint an immortal token.
    const expiresIn = authConfig.accessToken.expiresInMs();

    const token = await jwt.generate(data, { expiresIn });
    const expiresAt = new Date(Date.now() + expiresIn);

    if (familyId) {
      await this.accessTokenModel.issue(user, token, expiresAt, familyId);
    } else {
      await this.accessTokenModel.issue(user, token, expiresAt);
    }

    return { token, expiresAt: expiresAt.toISOString() };
  }

  /**
   * Sign + persist an access token for the user and return the token with its
   * expiry. The expiry is computed locally from `expiresIn` rather than by
   * re-verifying the token we just signed.
   */
  public async generateAccessToken(
    user: Auth,
    payload?: Record<string, unknown>,
  ): Promise<AccessTokenOutput> {
    await this.assertCanAuthenticate(user);

    return this.issueAccessToken(user, payload);
  }

  private async issueRefreshToken(
    user: Auth,
    deviceInfo?: DeviceInfo,
  ): Promise<RefreshToken | undefined> {
    if (!authConfig.refreshToken.enabled()) return;

    // Validate the lifetime first — before the per-user cap is enforced, before
    // anything is signed — so a bad value can never revoke a user's oldest
    // session on its way to failing.
    const expiresIn = authConfig.refreshToken.expiresInMs();

    const familyId = deviceInfo?.familyId || Random.string(32);

    const family = await AuthTokenFamily.ensure(user, familyId);

    if (family.isRevoked) {
      throw new Error("Cannot issue tokens for a revoked token family");
    }

    const payload = {
      userId: user.id,
      userType: user.userType,
      familyId,
      jti: randomUUID(),
    };

    const expiresAt = new Date(Date.now() + expiresIn).toISOString();

    await this.refreshTokenModel.enforceMax(user, authConfig.refreshToken.maxPerUser());

    const token = await jwt.generateRefreshToken(payload, { expiresIn });

    return this.refreshTokenModel.issue(user, token, { familyId, expiresAt, deviceInfo });
  }

  /**
   * Keep issuance into an explicitly reused family in the same durable
   * transition boundary as rotation and revocation. A new, caller-unspecified
   * family has no concurrent session to protect and retains the lightweight
   * issuance path.
   */
  private async issueInSuppliedFamily<T>(
    user: Auth,
    familyId: string,
    issue: () => Promise<T>,
  ): Promise<T> {
    // Preserve the established error for a family that was already revoked
    // before issuance started. The coordinator covers a revoke that races
    // after this observation.
    const family = await AuthTokenFamily.ensure(user, familyId);

    if (family.isRevoked) {
      throw new Error("Cannot issue tokens for a revoked token family");
    }

    try {
      return await runTokenFamilyOperation(familyId, async () => issue());
    } catch (error) {
      // Do not expose a timing-dependent error shape to callers: a family
      // revoked between ensure() and the transaction is the same unusable
      // family condition as one found above.
      if (error instanceof TokenFamilyUnavailableError) {
        throw new Error("Cannot issue tokens for a revoked token family");
      }

      throw error;
    }
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

    await this.assertCanAuthenticate(user);

    if (deviceInfo?.familyId) {
      return this.issueInSuppliedFamily(user, deviceInfo.familyId, () =>
        this.issueRefreshToken(user, deviceInfo),
      );
    }

    return this.issueRefreshToken(user, deviceInfo);
  }

  private async issueTokenPair(user: Auth, deviceInfo?: DeviceInfo): Promise<TokenPair> {
    const refreshEnabled = authConfig.refreshToken.enabled();
    const familyId = deviceInfo?.familyId || Random.string(32);

    if (refreshEnabled) {
      const family = await AuthTokenFamily.ensure(user, familyId);

      if (family.isRevoked) {
        throw new Error("Cannot issue tokens for a revoked token family");
      }
    }

    const accessToken = await this.issueAccessToken(
      user,
      deviceInfo?.payload,
      refreshEnabled ? familyId : undefined,
    );
    const refreshToken = await this.issueRefreshToken(
      user,
      refreshEnabled ? { ...deviceInfo, familyId } : deviceInfo,
    );

    const tokenPair: TokenPair = {
      accessToken,
      refreshToken: refreshToken
        ? {
            token: refreshToken.get("token"),
            expiresAt: refreshToken.get("expires_at"),
          }
        : undefined,
    };

    afterTokenFamilyOperation(() => authEvents.emit("token.created", user, tokenPair));

    if (refreshToken) {
      afterTokenFamilyOperation(() =>
        authEvents.emit("session.created", user, refreshToken, deviceInfo),
      );
    }

    return tokenPair;
  }

  /**
   * Issue both an access and a refresh token, emitting the creation events.
   */
  public async createTokenPair(user: Auth, deviceInfo?: DeviceInfo): Promise<TokenPair> {
    await this.assertCanAuthenticate(user);

    if (authConfig.refreshToken.enabled() && deviceInfo?.familyId) {
      return this.issueInSuppliedFamily(user, deviceInfo.familyId, () =>
        this.issueTokenPair(user, deviceInfo),
      );
    }

    return this.issueTokenPair(user, deviceInfo);
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
    let decoded: {
      userId: number;
      userType: string;
      familyId: string;
    } | null;

    try {
      decoded = await jwt.verifyRefreshToken<{
        userId: number;
        userType: string;
        familyId: string;
      }>(refreshTokenString);
    } catch (error) {
      if (isInvalidCredentialError(error)) return null;

      throw error;
    }

    if (!decoded) return null;

    const presentedToken = await this.refreshTokenModel.findByToken(refreshTokenString);

    if (!presentedToken || !this.refreshIdentityMatches(presentedToken, decoded)) return null;

    await AuthTokenFamily.ensure(
      { id: decoded.userId, userType: decoded.userType } as Auth,
      presentedToken.familyId,
    );
    return runTokenFamilyOperation(presentedToken.familyId, async () => {
      // Each serializable attempt must read the current row in its own snapshot.
      const refreshToken = await this.refreshTokenModel.findByToken(refreshTokenString);
      if (!refreshToken || !this.refreshIdentityMatches(refreshToken, decoded)) return null;
      if (!refreshToken.isValid) {
        // An already-invalid token may be a replay of a rotated credential.
        if (refreshToken) {
          await this.revokeTokenFamily(refreshToken.familyId);
        }

        return null;
      }

      const UserModel = config.key(`auth.userType.${decoded.userType}`);

      if (!UserModel) {
        throw new Error(`User type ${decoded.userType} is unknown type.`);
      }

      const user = (await UserModel.find(decoded.userId)) as Auth | null;

      if (!user) return null;

      if (!(await this.canAuthenticate(user))) return null;

      const rotationEnabled = authConfig.refreshToken.rotation();

      if (rotationEnabled) {
        const won = await refreshToken.revokeIfActive();

        if (!won) {
          // A concurrent request already rotated this token.
          await this.revokeTokenFamily(refreshToken.familyId);

          return null;
        }
      } else {
        await refreshToken.markAsUsed();
      }

      const newTokenPair = await this.issueTokenPair(user, {
        ...deviceInfo,
        familyId: refreshToken.familyId,
      });

      afterTokenFamilyOperation(() =>
        authEvents.emit("token.refreshed", user, newTokenPair, refreshToken),
      );

      return newTokenPair;
    }).catch((error) => {
      if (error instanceof TokenFamilyUnavailableError) return null;
      throw error;
    });
  }

  /**
   * Opt-in browser-session renewal. Unlike {@link refreshTokens}, this permits
   * a short duplicate presentation to receive the exact committed successor
   * pair. It is deliberately not used by the legacy/public refresh API.
   */
  public async renewAutomaticSession(
    refreshTokenString: string,
    expectedUserType: string,
    options: { overlapMs?: number; deviceInfo?: DeviceInfo; maxAgeMs?: number } = {},
  ): Promise<TokenPair | null> {
    let decoded: { userId: number; userType: string; familyId: string } | null;
    try {
      decoded = await jwt.verifyRefreshToken<{
        userId: number;
        userType: string;
        familyId: string;
      }>(refreshTokenString);
    } catch (error) {
      if (isInvalidCredentialError(error)) return null;
      throw error;
    }

    if (!decoded || decoded.userType !== expectedUserType) return null;
    const presentedToken = await this.refreshTokenModel.findByToken(refreshTokenString);
    if (!presentedToken || !this.refreshIdentityMatches(presentedToken, decoded)) return null;

    await AuthTokenFamily.ensure(
      { id: decoded.userId, userType: decoded.userType } as Auth,
      presentedToken.familyId,
    );
    return runTokenFamilyOperation(presentedToken.familyId, async () => {
      // A retry can follow another process's committed rotation. Never reuse
      // a model captured before the transaction or before a failed attempt.
      const oldToken = await this.refreshTokenModel.findByToken(refreshTokenString);
      if (!oldToken || !this.refreshIdentityMatches(oldToken, decoded)) return null;
      if (!oldToken.isValid) {
        const successor = await this.readAutomaticSuccessor(oldToken, decoded, options.overlapMs);
        if (successor) return successor;
        if (
          this.isAutomaticOverlapOpen(oldToken, options.overlapMs) &&
          this.hasSuccessor(oldToken)
        ) {
          return null;
        }
        await this.revokeTokenFamily(oldToken.familyId);
        return null;
      }

      // Rotation never extends a family past `maxAgeMs` from its first issue.
      if (
        options.maxAgeMs !== undefined &&
        (await this.familyExceedsMaxAge(oldToken.familyId, options.maxAgeMs))
      ) {
        await this.revokeTokenFamily(oldToken.familyId);
        return null;
      }

      const UserModel = config.key(`auth.userType.${decoded.userType}`);
      if (!UserModel) throw new Error(`User type ${decoded.userType} is unknown type.`);
      const user = (await UserModel.find(decoded.userId)) as Auth | null;
      if (!user || !(await this.canAuthenticate(user))) return null;

      if (!(await oldToken.revokeIfActive())) {
        // A newer successor is never substituted here. A stale automatic
        // response must fail quietly rather than revoke a legitimate family.
        const currentToken = await this.refreshTokenModel.findByToken(refreshTokenString);
        if (!currentToken) return null;
        const successor = await this.readAutomaticSuccessor(
          currentToken,
          decoded,
          options.overlapMs,
        );
        if (successor) return successor;
        if (
          this.isAutomaticOverlapOpen(currentToken, options.overlapMs) &&
          this.hasSuccessor(currentToken)
        )
          return null;
        await this.revokeTokenFamily(oldToken.familyId);
        return null;
      }

      const pair = await this.issueTokenPair(user, {
        ...options.deviceInfo,
        familyId: oldToken.familyId,
      });
      const successorAccess = await this.accessTokenModel.findByToken(pair.accessToken.token);
      const successorRefresh = pair.refreshToken
        ? await this.refreshTokenModel.findByToken(pair.refreshToken.token)
        : null;
      if (!successorAccess || !successorRefresh) {
        throw new Error("Automatic renewal did not persist a complete successor pair");
      }

      // `revokeIfActive()` updates the database, not this hydrated instance.
      // Saving that stale instance would write its old `revoked_at: null` back
      // and reopen the predecessor. Update only the successor columns instead.
      const linked = await this.refreshTokenModel.atomic(
        { id: oldToken.id },
        {
          $set: {
            successor_access_token_id: successorAccess.id,
            successor_refresh_token_id: successorRefresh.id,
          },
        },
      );
      if (linked !== 1) throw new Error("Automatic renewal could not link its successor pair");
      afterTokenFamilyOperation(() => authEvents.emit("token.refreshed", user, pair, oldToken));
      return pair;
    }).catch((error) => {
      if (error instanceof TokenFamilyUnavailableError) return null;
      throw error;
    });
  }

  /**
   * Whether the family's first issue is older than `maxAgeMs`. The start is the
   * family row's `created_at`, falling back to its oldest refresh token when
   * the row carries none (an upserted legacy family).
   */
  private async familyExceedsMaxAge(familyId: string, maxAgeMs: number): Promise<boolean> {
    const family = await AuthTokenFamily.findByFamilyId(familyId);
    let started: unknown = family?.get("created_at");

    if (!started) {
      const oldest = await this.refreshTokenModel
        .query()
        .where({ family_id: familyId })
        .orderBy("created_at", "asc")
        .first();

      started = oldest?.get("created_at");
    }

    const startedAt = started ? new Date(started as string | number | Date).getTime() : NaN;

    // Unknown start: nothing to measure against, so the cap cannot apply.
    if (!Number.isFinite(startedAt)) return false;

    return Date.now() - startedAt > maxAgeMs;
  }

  private automaticOverlapMs(overlapMs: number | undefined): number {
    return typeof overlapMs === "number" && Number.isFinite(overlapMs)
      ? Math.max(0, Math.min(10_000, overlapMs))
      : 5000;
  }

  private refreshIdentityMatches(
    token: RefreshToken,
    decoded: { userId: string | number; userType: string; familyId: string },
  ): boolean {
    return (
      token.familyId === decoded.familyId &&
      token.get("user_id") === decoded.userId &&
      token.get("user_type") === decoded.userType
    );
  }

  private hasSuccessor(oldToken: RefreshToken): boolean {
    return Boolean(
      oldToken.get("successor_access_token_id") && oldToken.get("successor_refresh_token_id"),
    );
  }

  private isAutomaticOverlapOpen(oldToken: RefreshToken, overlapMs: number | undefined): boolean {
    const revokedAt = oldToken.get<Date | undefined>("revoked_at");
    const window = this.automaticOverlapMs(overlapMs);
    const elapsed = revokedAt ? Date.now() - new Date(revokedAt).getTime() : NaN;
    return window > 0 && elapsed >= 0 && elapsed <= window;
  }

  private async readAutomaticSuccessor(
    oldToken: RefreshToken,
    decoded: { userId: number; userType: string; familyId: string },
    overlapMs: number | undefined,
  ): Promise<TokenPair | null> {
    if (!this.isAutomaticOverlapOpen(oldToken, overlapMs)) return null;
    const accessId = oldToken.get<string | undefined>("successor_access_token_id");
    const refreshId = oldToken.get<string | undefined>("successor_refresh_token_id");
    if (!accessId || !refreshId) return null;
    const [access, refresh] = await Promise.all([
      this.accessTokenModel.find(accessId),
      this.refreshTokenModel.find(refreshId),
    ]);
    if (!access || access.isExpired || !refresh?.isValid) return null;
    if (
      access.get("family_id") !== decoded.familyId ||
      refresh.get("family_id") !== decoded.familyId ||
      access.get("user_id") !== decoded.userId ||
      refresh.get("user_id") !== decoded.userId ||
      access.get("user_type") !== decoded.userType ||
      refresh.get("user_type") !== decoded.userType
    )
      return null;
    const accessExpiry = new Date(access.get("expires_at")).getTime();
    if (!Number.isFinite(accessExpiry) || accessExpiry <= Date.now()) return null;
    return {
      accessToken: { token: access.get("token"), expiresAt: access.get("expires_at") },
      refreshToken: { token: refresh.get("token"), expiresAt: refresh.get("expires_at") },
    };
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
  public async attemptLogin<T extends Auth>(
    Model: ChildModel<T>,
    data: AuthCredentials,
  ): Promise<T | null> {
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

    if (!(await this.canAuthenticate(user))) {
      authEvents.emit("login.failed", otherData, "Authentication not allowed");

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
    credentials: AuthCredentials,
    deviceInfo?: DeviceInfo,
  ): Promise<LoginResult<T> | null> {
    const user = await this.attemptLogin(Model, credentials);

    if (!user) {
      return null;
    }

    return this.finalizeLogin(user, deviceInfo);
  }

  /**
   * Log in a user some OTHER method already authenticated — a provider
   * callback, a passkey assertion, a one-time code. Applies the
   * `auth.canAuthenticate` policy (403 on refusal), then produces exactly
   * what {@link login} produces: the same tokens, rows and events. Pair with
   * {@link setAuthCookie} for a cookie session, as with password login.
   *
   * Never call this for a user you have not authenticated.
   */
  public async completeLogin<T extends Auth>(
    user: T,
    deviceInfo?: DeviceInfo,
  ): Promise<LoginResult<T>> {
    await this.assertCanAuthenticate(user);

    return this.finalizeLogin(user, deviceInfo);
  }

  /**
   * Cookie login for a browser: same-origin check, credential login, then both
   * session cookies. Unlike the default CSRF guard, the Origin/Referer check
   * runs even when the request carries no cookies (login CSRF): a missing or
   * cross-site Origin/Referer throws `CsrfOriginMismatchError` before any
   * credential is looked at. Returns `null` on bad credentials.
   */
  public async loginWithSessionCookies<T extends Auth>(
    request: Request,
    response: CookieWriter,
    Model: ChildModel<T>,
    credentials: AuthCredentials,
    deviceInfo?: DeviceInfo,
  ): Promise<LoginResult<T> | null> {
    assertCsrfOriginAllowed(request);

    const result = await this.login(Model, credentials, deviceInfo);

    if (!result) return null;

    if (result.tokens.refreshToken) {
      this.setSessionCookies(response, {
        accessToken: result.tokens.accessToken,
        refreshToken: result.tokens.refreshToken,
      });
    } else {
      this.setAuthCookie(response, result.tokens.accessToken);
    }

    return result;
  }

  /** The one token-issuing tail every login method shares. */
  private async finalizeLogin<T extends Auth>(
    user: T,
    deviceInfo?: DeviceInfo,
  ): Promise<LoginResult<T>> {
    if (!authConfig.refreshToken.enabled()) {
      const accessToken = await this.issueAccessToken(user, deviceInfo?.payload);

      return { user, tokens: { accessToken } };
    }

    const tokens = await this.issueTokenPair(user, deviceInfo);

    authEvents.emit("login.success", user, tokens, deviceInfo);

    return { user, tokens };
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
        await this.revokeTokenFamily(token.familyId);
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
   * tokens — "log out of all devices". Each durable family is first marked through its revision coordinator; an
   * event fires per revoked token.
   */
  public async revokeAllTokens(user: Auth): Promise<void> {
    // Upgrade existing installations lazily before the family scan. Include
    // revoked rows: a rotation may have revoked its predecessor while its
    // durable family still needs logout's marker.
    const existingRows = await this.refreshTokenModel.familiesForUser(user);

    for (const token of existingRows) {
      await AuthTokenFamily.ensure(user, token.familyId);
    }

    const families = await AuthTokenFamily.activeFor(user);

    for (const family of families) {
      await this.revokeTokenFamily(family.get<string>("family_id"));
    }

    // A deployment can still have rows created before the additive migration
    // ran; retain the old bulk cleanup as a final conservative backstop.
    const legacyTokens = await this.refreshTokenModel.revokeAllFor(user);

    for (const token of legacyTokens) {
      authEvents.emit("token.revoked", user, token);
    }
    await this.removeAllAccessTokens(user);

    authEvents.emit("logout.all", user);
  }

  /**
   * Revoke an entire token family — rotation breach containment.
   */
  public async revokeTokenFamily(familyId: string): Promise<void> {
    let family = await AuthTokenFamily.findByFamilyId(familyId);

    if (!family) {
      const legacyToken = await this.refreshTokenModel.findInFamily(familyId);

      if (!legacyToken) return;

      family = await AuthTokenFamily.ensure(
        {
          id: legacyToken.get("user_id"),
          userType: legacyToken.get<string>("user_type"),
        } as Auth,
        familyId,
      );
    }

    const user = {
      id: family.get("user_id"),
      userType: family.get<string>("user_type"),
    } as Auth;

    if (family.isRevoked) {
      // Logout and replay containment are idempotent. Re-run cleanup because a
      // request that lost the original race may have observed stale rows.
      const revokedTokens = await this.refreshTokenModel.revokeFamily(familyId);
      await this.accessTokenModel.deleteFamilyAndLegacyForUser(user, familyId);
      afterTokenFamilyOperation(() =>
        authEvents.emit("token.familyRevoked", familyId, revokedTokens),
      );

      return;
    }

    let revokedTokens: RefreshToken[];
    try {
      revokedTokens = await runTokenFamilyOperation(familyId, async (currentFamily) => {
        const familyUser = {
          id: currentFamily.get("user_id"),
          userType: currentFamily.get<string>("user_type"),
        } as Auth;
        const revision = currentFamily.get<number>("revision");
        const revoked = await AuthTokenFamily.revoke(familyId, revision);

        if (revoked !== 1) {
          throw new Error("Token family revoke lost its revision transition");
        }

        const familyTokens = await this.refreshTokenModel.revokeFamily(familyId);
        await this.accessTokenModel.deleteFamilyAndLegacyForUser(familyUser, familyId);

        return familyTokens;
      });
    } catch (error) {
      if (!(error instanceof TokenFamilyUnavailableError)) throw error;

      // Another request committed the revoke between the read above and its
      // CAS. A second logout is successful after idempotent cleanup.
      revokedTokens = await this.refreshTokenModel.revokeFamily(familyId);
      await this.accessTokenModel.deleteFamilyAndLegacyForUser(user, familyId);
    }

    afterTokenFamilyOperation(() =>
      authEvents.emit("token.familyRevoked", familyId, revokedTokens),
    );
  }

  /**
   * Delete expired tokens (refresh + access) and spent one-time tokens
   * (expired or consumed verification/reset/OTP/passkey rows). Emits `token.expired` per refresh
   * token and `cleanup.completed` with the refresh count. Drives the
   * `auth.cleanup` CLI command.
   */
  public async cleanupExpiredTokens(): Promise<number> {
    const expiredTokens = await this.refreshTokenModel.purgeExpired();

    for (const token of expiredTokens) {
      authEvents.emit("token.expired", token);
    }

    await this.accessTokenModel.purgeExpired();
    await this.oneTimeTokenModel.purgeSpent();

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

  /**
   * `Max-Age` (seconds) `setAuthCookie` should apply, derived from an
   * `AccessTokenOutput`'s `expiresAt` — or `undefined` for a bare token
   * string (a session cookie) or an unparseable `expiresAt`.
   */
  private cookieMaxAgeFromToken(token: string | AccessTokenOutput): number | undefined {
    if (typeof token === "string") return undefined;

    const expiresAt = new Date(token.expiresAt).getTime();

    if (Number.isNaN(expiresAt)) return undefined;

    return Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
  }

  /**
   * Write the auth cookie on `response` — the write side of the `cookie:<name>`
   * token source `authMiddleware([], "cookie:<name>")` already reads. An explicit
   * app-controller call, never a side effect of {@link login}, so an existing
   * bearer-only app never starts emitting `Set-Cookie` just by upgrading.
   *
   * Attribute flags (`HttpOnly`, `SameSite=Lax`, `Secure` outside dev) come
   * from `response.cookie()`'s own `secureCookieDefaults()` floor — this
   * method never overrides them, only `name`/`path`/`maxAge`. `raw: true`
   * writes the token unquoted, so the same string a `cookie:<name>` source
   * reads back is exactly what was issued, not a JSON-wrapped copy.
   *
   * @param token - the token string, or an `AccessTokenOutput` (e.g. from
   *   {@link login}) whose `expiresAt` sets `Max-Age` automatically when
   *   `options.maxAge` is not given. A bare string with no `options.maxAge`
   *   produces a session cookie.
   *
   * @example
   * const { user, tokens } = await authService.login(User, credentials);
   * authService.setAuthCookie(response, tokens.accessToken);
   */
  public setAuthCookie(
    response: CookieWriter,
    token: string | AccessTokenOutput,
    options: SetAuthCookieOptions = {},
  ): void {
    const name = options.name ?? authConfig.cookie.name();
    const path = options.path ?? authConfig.cookie.path();
    const tokenValue = typeof token === "string" ? token : token.token;
    const maxAge = options.maxAge ?? this.cookieMaxAgeFromToken(token);

    response.cookie(name, tokenValue, {
      raw: true,
      path,
      ...(maxAge !== undefined ? { maxAge } : {}),
    });
  }

  /**
   * Clear the auth cookie {@link setAuthCookie} wrote. An explicit
   * app-controller call — pair it with {@link logout} after the token row is
   * revoked. `path` must match what the cookie was set with, or the browser
   * silently ignores the clear (see `response.clearCookie`'s own doc comment).
   *
   * @example
   * await authService.logout(user, accessToken, refreshToken);
   * authService.clearAuthCookie(response);
   */
  public clearAuthCookie(response: CookieWriter, options: ClearAuthCookieOptions = {}): void {
    const name = options.name ?? authConfig.cookie.name();
    const path = options.path ?? authConfig.cookie.path();

    response.clearCookie(name, { path });
  }

  /**
   * Write the access and refresh cookies of a browser session. Both are
   * `HttpOnly`, `SameSite=Lax`, `Path=/` (the refresh cookie must reach every
   * page) and `Secure` outside development, named by `auth.cookie.name` and
   * `auth.cookie.refreshName`. Each `Max-Age` is derived from its token's
   * `expiresAt`, so the cookie lives exactly as long as the token.
   *
   * @example
   * const { tokens } = await authService.login(User, credentials);
   * authService.setSessionCookies(response, tokens);
   */
  public setSessionCookies(
    response: CookieWriter,
    tokens: { accessToken: AccessTokenOutput; refreshToken: AccessTokenOutput },
  ): void {
    const cookies = [
      [authConfig.cookie.name(), tokens.accessToken],
      [authConfig.cookie.refreshName(), tokens.refreshToken],
    ] as const;

    for (const [name, token] of cookies) {
      const maxAge = this.cookieMaxAgeFromToken(token);

      response.cookie(name, token.token, {
        raw: true,
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        ...(maxAge !== undefined ? { maxAge } : {}),
      });
    }
  }

  /**
   * Clear both session cookies {@link setSessionCookies} wrote, on `Path=/`.
   * Pair it with {@link logout} after the token rows are revoked.
   */
  public clearSessionCookies(response: CookieWriter): void {
    response.clearCookie(authConfig.cookie.name(), { path: "/" });
    response.clearCookie(authConfig.cookie.refreshName(), { path: "/" });
  }
}

export const authService = new AuthService();
